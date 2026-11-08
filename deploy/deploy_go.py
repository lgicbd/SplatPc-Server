"""Move a Linux server from the Python NEX server to the Go binary over SSH, with backups and a rollback.

    py -3 deploy/deploy_go.py parallel --host root@SERVER [--key KEY] [--domain DOMAIN]    dry run (read-only)
    py -3 deploy/deploy_go.py parallel ... --apply     Go next to Python: other ports, a COPY of the database
    py -3 deploy/deploy_go.py stop-parallel ... --apply     stops that test server, Python untouched
    py -3 deploy/deploy_go.py cutover ... --apply      stops Python, starts Go on the live database and server.json
    py -3 deploy/deploy_go.py rollback ... --apply     stops Go, restarts Python on the same database

The parallel server has no NAT check: UDP 10025 and 10125 belong to the running Python server, which keeps answering.
While Go is live a guard stops the Python unit from starting, because both must never share the database.
Each step checks /health, the owner of server.json and the database files. A cutover that fails its checks rolls back.
The cutover drops running matches: do it when nobody plays. Nothing here deletes a backup or the Python venv.
"""
import argparse
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

from remote import Target, add_target_args

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "linux" / "splatoon-nex"
UNIT = pathlib.Path(__file__).with_name("splatoon-nex-go.service")
GO_SERVICE = "splatoon-nex-go"
PARALLEL_DB_NAME = "accounts-go-parallel.sqlite3"


class Go:
    """Paths of the Go server on the target."""

    def __init__(self, target: Target, auth_port: int):
        self.target = target
        self.dir = f"{target.root}/go"
        self.binary = f"{self.dir}/splatoon-nex"
        self.config = f"{self.dir}/server.json"
        self.log = f"{pathlib.PurePosixPath(target.log).parent}/nexserver-go.log"
        self.live_flag = f"{self.dir}/live"
        self.guard_dir = f"/etc/systemd/system/{target.service}.service.d"
        self.parallel_db = f"{pathlib.PurePosixPath(target.db).parent}/{PARALLEL_DB_NAME}"
        self.auth_port = auth_port

    def as_service_user(self, command: str) -> str:
        """Files the server opens must stay owned by its user, so nothing runs on them as root."""
        return f"runuser -u {self.target.user} -- {command}"

    def firewall(self, action: str) -> str:
        ports = f"{self.auth_port}:{self.auth_port + 1}/udp"
        return f"if ufw status 2>/dev/null | grep -q 'Status: active'; then ufw {action} {ports}; fi"


def build() -> None:
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", "cmd", "internal", "go.mod", "go.sum"],
                           capture_output=True, text=True, check=True).stdout.strip()
    if dirty:
        sys.exit("Commit the Go changes first, the deployed binary must match a revision:\n" + dirty)
    environment = {**os.environ, "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}
    subprocess.run(["go", "build", "-trimpath", "-o", str(BINARY), "./cmd/splatoon-nex"], cwd=str(ROOT), env=environment, check=True)


def backup(target: Target, stamp: str) -> None:
    """Online SQLite backup and server.json, dated, both readable by root and the service user only."""
    source, copy = target.db, f"{target.db}.bak-{stamp}"
    script = f"import sqlite3; s=sqlite3.connect('{source}'); d=sqlite3.connect('{copy}'); s.backup(d); d.close(); s.close()"
    target.ssh(f"runuser -u {target.user} -- {target.python} -c {shlex.quote(script)} && chmod 600 {copy}")
    target.ssh(f"cp -a {target.config} {target.config}.bak-{stamp}")
    print(f"backups: {copy}, {target.config}.bak-{stamp}")


def install_binary(target: Target, go: Go) -> None:
    target.ssh(f"install -d -o {target.user} -g {target.user} -m 755 {go.dir}")
    target.scp([str(BINARY)], f"{go.binary}.new")
    target.ssh(f"chown {target.user}: {go.binary}.new && chmod 755 {go.binary}.new && mv {go.binary}.new {go.binary}")


def install_unit(target: Target) -> None:
    target.scp([str(UNIT)], f"/etc/systemd/system/{GO_SERVICE}.service")
    target.ssh("sed -i 's/\\r$//' " + f"/etc/systemd/system/{GO_SERVICE}.service && systemctl daemon-reload")


def write_parallel_config(target: Target, go: Go) -> None:
    config = json.loads(target.ssh(f"cat {target.config}"))
    config.update(auth_port=go.auth_port, secure_port=go.auth_port + 1, registration_port=go.auth_port + 2,
                  accounts_db=go.parallel_db, natcheck=False)
    for key in ("natcheck_addresses", "natcheck_same_socket", "natcheck_single_ip"):
        config.pop(key, None)
    target.ssh(f"rm -f {go.config} && cat > {go.config}.new && chown {target.user}: {go.config}.new "
               f"&& chmod 600 {go.config}.new && mv {go.config}.new {go.config}", stdin=json.dumps(config, indent=1))


def copy_database(target: Target, go: Go) -> None:
    script = f"import sqlite3; s=sqlite3.connect('{target.db}'); d=sqlite3.connect('{go.parallel_db}'); s.backup(d); d.close(); s.close()"
    target.ssh(f"rm -f {go.parallel_db} {go.parallel_db}-wal {go.parallel_db}-shm && "
               f"runuser -u {target.user} -- {target.python} -c {shlex.quote(script)} && chmod 600 {go.parallel_db}")


def check_config(target: Target, go: Go, path: str) -> None:
    print("config check:", target.ssh(go.as_service_user(f"{go.binary} --config {path} --check-config") + " 2>&1").strip())


def active(target: Target, service: str) -> str:
    return target.ssh(f"systemctl is-active {service}", check=False).strip()


def problems(target: Target) -> list:
    """server.json and the database files must belong to the service user, or the service falls over."""
    data_dir = pathlib.PurePosixPath(target.db).parent
    found = target.ssh(f"find {target.config} {data_dir} -maxdepth 1 ! -user {target.user} -print; stat -c '%a' {target.config}", check=False).split()
    mode = found.pop() if found else "?"
    return found + ([f"server.json mode {mode}"] if mode != "600" else [])


def report(target: Target, go: Go, local_port: int) -> bool:
    """Prints the state of both services, and says whether the server answering on local_port is healthy."""
    answer = target.ssh(f"curl -s -m 10 http://127.0.0.1:{local_port}/health", check=False).strip()
    print(f"python: {active(target, target.service)} | go: {active(target, GO_SERVICE)}")
    print(f"health on {local_port}:", answer)
    print("public health:", target.health())
    wrong = problems(target)
    print("wrong owner or mode:", ", ".join(wrong) or "none")
    print(target.ssh(f"grep -E ' (ERROR|CRITICAL) ' {go.log} 2>/dev/null | tail -5", check=False).strip() or "no error in the Go log")
    try:
        return json.loads(answer).get("ok") is True and not wrong
    except ValueError:
        return False


def parallel(target: Target, go: Go) -> None:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup(target, stamp)
    install_binary(target, go)
    install_unit(target)
    copy_database(target, go)
    write_parallel_config(target, go)
    check_config(target, go, go.config)
    target.ssh(go.firewall("allow"))
    target.ssh(f"systemctl restart {GO_SERVICE}")
    time.sleep(3)
    healthy = report(target, go, go.auth_port + 2)
    print(f"\nParallel server on UDP {go.auth_port}-{go.auth_port + 1}. HTTP stays on the server's loopback: "
          f"ssh -L {go.auth_port + 2}:127.0.0.1:{go.auth_port + 2} {target.host}")
    if not healthy:
        sys.exit("The parallel server is not healthy: see its log, Python did not change.")


def stop_parallel(target: Target, go: Go) -> None:
    if target.ssh(f"test -e {go.live_flag} && echo live", check=False).strip():
        sys.exit("Go is the live server here: use rollback, not stop-parallel.")
    target.ssh(f"systemctl stop {GO_SERVICE}; " + go.firewall("delete allow"))
    report(target, go, target.local_port)


def cutover(target: Target, go: Go) -> None:
    install_binary(target, go)
    install_unit(target)
    check_config(target, go, target.config)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup(target, stamp)
    target.ssh(f"systemctl stop {GO_SERVICE}; " + go.firewall("delete allow"))
    target.ssh(f"mkdir -p {go.guard_dir} && touch {go.live_flag} && "
               f"printf '[Unit]\\nConditionPathExists=!{go.live_flag}\\n' > {go.guard_dir}/go-is-live.conf && systemctl daemon-reload")
    target.ssh(f"systemctl stop {target.service} && systemctl disable {target.service}")
    if active(target, target.service) == "active":
        rollback(target, go)
        sys.exit("Python did not stop: rolled back, Go was not started.")
    target.ssh(f"rm -f {go.config} && ln -s ../server.json {go.config} && chown -h {target.user}: {go.config} && systemctl enable --now {GO_SERVICE}")
    time.sleep(6)
    if not report(target, go, target.local_port):
        print("Checks failed, rolling back.")
        rollback(target, go)
        sys.exit("Rolled back to Python: see the Go log.")
    print(f"\nGo is live. Backups: {stamp}. To undo: deploy_go.py rollback --apply. "
          f"From now on pass --service {GO_SERVICE} to set_integrity.py.")


def rollback(target: Target, go: Go) -> None:
    target.ssh(f"systemctl disable --now {GO_SERVICE}; rm -f {go.config} {go.live_flag} {go.guard_dir}/go-is-live.conf; "
               f"rmdir {go.guard_dir} 2>/dev/null; systemctl daemon-reload")
    if active(target, GO_SERVICE) == "active":
        sys.exit("Go did not stop: Python was not started, both must never share the database.")
    target.ssh(f"systemctl enable --now {target.service}")
    time.sleep(6)
    report(target, go, target.local_port)
    print("The database was not restored: Python runs on what Go wrote, same schema.")


def dry_run(target: Target, go: Go, step: str) -> None:
    print("server machine:", target.ssh("uname -m").strip(), "| free space:", target.ssh("df -h / | tail -1").split()[3])
    print(f"python: {active(target, target.service)} | go: {active(target, GO_SERVICE)}")
    print("public health:", target.health())
    print("ports in use:", " ".join(sorted(set(target.ssh(f"ss -lunH | grep -E ':(60000|60001|10025|10125|{go.auth_port}|{go.auth_port + 1}) ' | awk '{{print $4}}' | sed 's/.*://'", check=False).split()))))
    print("firewall:", target.ssh("ufw status 2>/dev/null | head -1", check=False).strip() or "no ufw")
    print("wrong owner or mode:", ", ".join(problems(target)) or "none")
    print(f"\nDry run only: nothing changed. --apply runs '{step}'.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("step", choices=["parallel", "stop-parallel", "cutover", "rollback"])
    add_target_args(parser)
    parser.add_argument("--apply", action="store_true", help="do it (default: dry run)")
    parser.add_argument("--parallel-port", type=int, default=60100, help="auth port of the parallel server; secure and HTTP are the next two")
    args = parser.parse_args()
    target = Target(args)
    go = Go(target, args.parallel_port)
    if not args.apply:
        dry_run(target, go, args.step)
    elif args.step == "parallel":
        build()
        parallel(target, go)
    elif args.step == "stop-parallel":
        stop_parallel(target, go)
    elif args.step == "cutover":
        build()
        cutover(target, go)
    else:
        rollback(target, go)


if __name__ == "__main__":
    main()
