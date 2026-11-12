"""A test Go server next to the live one, over SSH: its own unit, ports and COPY of the database.

    py -3 deploy/go_test_env.py install --host root@SERVER [--key KEY]            dry run (read-only)
    py -3 deploy/go_test_env.py install --host root@SERVER [--key KEY] --apply    build, install and start the test unit
    py -3 deploy/go_test_env.py stop --host root@SERVER [--key KEY] --apply       stop it and close its UDP ports
    py -3 deploy/go_test_env.py status --host root@SERVER [--key KEY]

The test unit (splatoon-nex-go-test, never enabled at boot) runs the binary built from this repository on UDP --test-port and
--test-port + 1 (opened in ufw) and HTTP --test-port + 2 (server loopback only: ssh -L). Its server.json is the live
one with integrity_mode log, no NAT check and a copy of the accounts database. The live unit, its server.json and its
database are only read. Files stay in place after stop, a new install replaces them.
"""
import argparse
import json
import pathlib
import shlex
import sys
import time

from go_server import BINARY, build
from remote import Target, add_target_args

TEST_SERVICE = "splatoon-nex-go-test"


class TestEnv:
    """Paths of the test server on the target."""

    def __init__(self, target: Target, port: int):
        self.target = target
        self.port = port
        self.dir = f"{target.root}/go-test"
        self.binary = f"{self.dir}/splatoon-nex"
        self.config = f"{self.dir}/server.json"
        self.db = f"{pathlib.PurePosixPath(target.db).parent}/accounts-go-test.sqlite3"
        self.log = f"{pathlib.PurePosixPath(target.log).parent}/nexserver-go-test.log"

    def firewall(self, action: str) -> str:
        return f"if ufw status 2>/dev/null | grep -q 'Status: active'; then ufw {action} {self.port}:{self.port + 1}/udp; fi"

    def unit(self) -> str:
        user = self.target.user
        return f"""# Test copy of the Go NEX server, not production. Installed by deploy/go_test_env.py.
[Unit]
Description=Splatoon NEX server, Go, TEST (ports {self.port}-{self.port + 2}, copied database)
After=network-online.target
Wants=network-online.target

[Service]
User={user}
Group={user}
WorkingDirectory={self.dir}
ExecStart={self.binary} --config {self.config} --log {self.log}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={pathlib.PurePosixPath(self.target.db).parent} {pathlib.PurePosixPath(self.target.log).parent}
"""


def test_config(live: dict, env: TestEnv) -> dict:
    """The live configuration moved to the test ports and database, integrity in log mode, no NAT check."""
    taken = {live.get("auth_port"), live.get("secure_port"), live.get("registration_port"), 10025, 10125}
    wanted = {env.port, env.port + 1, env.port + 2}
    if taken & wanted:
        sys.exit(f"test ports {sorted(wanted)} overlap the live server's {sorted(p for p in taken if p)}")
    config = {**live, "auth_port": env.port, "secure_port": env.port + 1, "registration_port": env.port + 2,
              "accounts_db": env.db, "natcheck": False, "integrity_mode": "log"}
    for key in ("natcheck_addresses", "natcheck_same_socket", "natcheck_single_ip"):
        config.pop(key, None)
    return config


def active(target: Target, service: str) -> str:
    return target.ssh(f"systemctl is-active {service}", check=False).strip()


def status(target: Target, env: TestEnv) -> None:
    print(f"live: {active(target, target.service)} | test: {active(target, TEST_SERVICE)}")
    print("live health:", target.health())
    print("test health:", target.ssh(f"curl -s -m 5 http://127.0.0.1:{env.port + 2}/health", check=False).strip() or "-")
    print("test UDP sockets:", target.ssh(f"ss -lunH | grep -cE ':({env.port}|{env.port + 1}) '", check=False).strip())
    print("test ports in ufw:", target.ssh(f"ufw status 2>/dev/null | grep -c '{env.port}:{env.port + 1}/udp'", check=False).strip())
    print(target.ssh(f"grep -E ' (ERROR|CRITICAL) ' {env.log} 2>/dev/null | tail -3", check=False).strip() or "no error in the test log")


def install(target: Target, env: TestEnv, apply: bool) -> None:
    config = test_config(json.loads(target.ssh(f"cat {target.config}")), env)
    print(f"test server: UDP {env.port}-{env.port + 1}, HTTP {env.port + 2}, database {env.db}, integrity log, no NAT check")
    status(target, env)
    if not apply:
        print("\nDry run only: nothing changed. --apply builds the binary and starts the test unit.")
        return
    build()
    user = target.user
    target.ssh(f"install -d -o {user} -g {user} -m 755 {env.dir}")
    target.scp([str(BINARY)], f"{env.binary}.new")
    target.ssh(f"chown {user}: {env.binary}.new && chmod 755 {env.binary}.new && mv {env.binary}.new {env.binary}")
    target.ssh(f"systemctl stop {TEST_SERVICE} 2>/dev/null; true")
    copy = (f"import sqlite3; s=sqlite3.connect('file:{target.db}?mode=ro', uri=True); d=sqlite3.connect('{env.db}'); "
            "s.backup(d); d.close(); s.close()")
    target.ssh(f"rm -f {env.db} {env.db}-wal {env.db}-shm && "
               f"runuser -u {user} -- {target.python} -c {shlex.quote(copy)} && chmod 600 {env.db}")
    target.ssh(f"cat > {env.config}.new && chown {user}: {env.config}.new && chmod 600 {env.config}.new "
               f"&& mv {env.config}.new {env.config}", stdin=json.dumps(config, indent=1))
    print("config check:", target.ssh(f"runuser -u {user} -- {env.binary} --config {env.config} --check-config 2>&1").strip())
    target.ssh(f"cat > /etc/systemd/system/{TEST_SERVICE}.service && systemctl daemon-reload", stdin=env.unit())
    target.ssh(env.firewall("allow"))
    target.ssh(f"systemctl restart {TEST_SERVICE}")
    time.sleep(3)
    status(target, env)
    print(f"\nTest server on UDP {env.port}-{env.port + 1}. HTTP: ssh -N -L {env.port + 2}:127.0.0.1:{env.port + 2} {target.host}")


def stop(target: Target, env: TestEnv, apply: bool) -> None:
    if apply:
        target.ssh(f"systemctl stop {TEST_SERVICE}; " + env.firewall("delete allow"), check=False)
    status(target, env)
    if not apply:
        print("\nDry run only: --apply stops the test unit and closes its UDP ports.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("step", choices=["install", "stop", "status"])
    add_target_args(parser)
    parser.add_argument("--apply", action="store_true", help="do it (default: dry run)")
    parser.add_argument("--test-port", type=int, default=60100, help="auth port of the test server; secure and HTTP are the next two")
    args = parser.parse_args()
    target = Target(args)
    env = TestEnv(target, args.test_port)
    if args.step == "install":
        install(target, env, args.apply)
    elif args.step == "stop":
        stop(target, env, args.apply)
    else:
        status(target, env)


if __name__ == "__main__":
    main()
