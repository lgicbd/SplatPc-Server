"""Local rehearsal of the move from Python to Go (no network beyond this PC): run it before deploy_go.py --apply.

    py -3.12 deploy/rehearsal.py --old-rev <git revision of the Python code the server runs now> [--lan <this PC address>] [--panel-py panel.py]

1. A fake server folder with the Python code of --old-rev and a database made by that code (accounts, a pseudo, a ban).
2. Parallel run, as deploy_go.py parallel: Go on a copy of the database and other ports while Python keeps running.
3. Cutover, as deploy_go.py cutover: online SQLite backup, server.json gets the integrity keys, the binary validates it,
   Python stops and Go starts in public mode on the same database (other ports than production, NAT check off).
4. Checks over HTTP: /health, a 0.1.3 relay sign-in (no proof) is still accepted in "log" mode and logged, a proof is
   accepted, ops ban/bans/log/unban, the admin panel helper (optional, status, ban, unban) against this server.
5. Rollback: Python starts again on the database Go wrote and still signs players in.
"""
import argparse
import base64
import json
import pathlib
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--old-rev", required=True, help="git revision of the server code currently deployed")
parser.add_argument("--lan", help="non-loopback address of this PC the test server binds to (default: detected)")
parser.add_argument("--work", type=pathlib.Path, default=pathlib.Path(tempfile.gettempdir()) / "splatoon-rehearsal")
parser.add_argument("--panel-py", type=pathlib.Path, help="optional: panel.py of the admin panel, to test its server helper too")
ARGS = parser.parse_args()
WORK, OLD = ARGS.work, ARGS.old_rev


def lan_address():
    """Public mode refuses loopback, so the rehearsal binds to this PC's LAN address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))  # no packet is sent
        return probe.getsockname()[0]


LAN = ARGS.lan or lan_address()
FILES = sorted(pathlib.PurePosixPath(p).name for p in subprocess.run(
    ["git", "-C", str(ROOT), "ls-tree", "--name-only", OLD, "tools/nexlab/"], capture_output=True, text=True, check=True).stdout.split() if p.endswith(".py"))
PORT, REG = 61000, 61002
PARALLEL_PORT, PARALLEL_REG = 61010, 61012
BINARY = WORK / ("splatoon-nex.exe" if sys.platform == "win32" else "splatoon-nex")
ADMIN = secrets.token_hex(16)
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail and not ok else ""))


def put_code(rev, target):
    target.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        data = subprocess.run(["git", "-C", str(ROOT), "show", f"{rev}:tools/nexlab/{name}"], capture_output=True, check=True).stdout
        (target / name).write_bytes(data)


def call(path, body=None, token=None, port=REG):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as reply:
            return reply.status, json.loads(reply.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def start(command, cwd, log, port=REG):
    proc = subprocess.Popen([*command, "--log", str(log)], cwd=str(cwd), stdout=subprocess.DEVNULL, stderr=open(str(log) + ".stderr", "w"))
    for _ in range(40):
        time.sleep(0.25)
        try:
            if call("/health", port=port)[0] == 200:
                return proc
        except Exception:
            pass
    proc.kill()
    sys.exit("server did not start: " + pathlib.Path(str(log) + ".stderr").read_text()[-1500:])


def start_python(code_dir, config, log):
    return start([sys.executable, str(code_dir / "nexserver.py"), "--config", str(config)], code_dir, log)


def start_go(config, log, port=REG):
    return start([str(BINARY), "--config", str(config)], WORK, log, port)


def online_backup(source_path, target_path):
    source, target = sqlite3.connect(str(source_path)), sqlite3.connect(str(target_path))
    source.backup(target)
    target.close(), source.close()


def stop(proc):
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()


shutil.rmtree(WORK, ignore_errors=True)
opt = WORK / "opt"
code = opt / "tools" / "nexlab"
put_code(OLD, code)
db = WORK / "accounts.sqlite3"
config_path = opt / "server.json"
config = {"mode": "public", "listen": LAN, "advertise": LAN, "auth_port": PORT, "secure_port": PORT + 1, "natcheck": False,
          "accounts_db": str(db), "registration": "open", "fill_timeout": 20, "registration_proxy": True, "registration_port": REG,
          "random_session_key": True, "admin_token": ADMIN}
config_path.write_text(json.dumps(config, indent=1))

# 1. The 0.1.3 server and its database.
players = {0x10000001: "A" * 16, 0x10000002: "B" * 16}
old = start_python(code, config_path, WORK / "old.log")
for pid, password in players.items():
    status, _ = call("/register", {"pid": f"0x{pid:08x}", "password": password})
    check(f"old server registers {pid:08x}", status == 200, status)
check("old server claims a pseudo", call("/social/pseudo", {"pid": "0x10000001", "password": players[0x10000001], "pseudo": "Alice"})[0] == 200)
subprocess.run([sys.executable, str(code / "accounts.py"), "--db", str(db), "ban", "--pid", "0x10000002", "--reason", "old ban"],
               cwd=str(code), check=True, capture_output=True)

# 2. Parallel run: Go on a copy, Python still running on the live database.
subprocess.run(["go", "build", "-o", str(BINARY), "./cmd/splatoon-nex"], cwd=str(ROOT), check=True)
parallel_db = WORK / "accounts-go-parallel.sqlite3"
online_backup(db, parallel_db)
parallel_config = WORK / "server.parallel.json"
parallel_config.write_text(json.dumps({**config, "auth_port": PARALLEL_PORT, "secure_port": PARALLEL_PORT + 1,
                                       "registration_port": PARALLEL_REG, "accounts_db": str(parallel_db)}, indent=1))
parallel = start_go(parallel_config, WORK / "parallel.log", PARALLEL_REG)
check("parallel Go answers next to Python", call("/health", port=PARALLEL_REG)[0] == 200 and call("/health")[0] == 200)
check("parallel Go signs in a player of the copy",
      call("/social/session", {"pid": "0x10000001", "password": players[0x10000001]}, port=PARALLEL_REG)[0] == 200)
check("parallel Go registers on its copy only", call("/register", {"pid": "0x10000003", "password": "C" * 16}, port=PARALLEL_REG)[0] == 200
      and sqlite3.connect(str(db)).execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 2)
check("Python still signs in during the parallel run", call("/social/session", {"pid": "0x10000001", "password": players[0x10000001]})[0] == 200)
stop(parallel)

# 3. Cutover.
backup = WORK / "accounts.sqlite3.bak"
online_backup(db, backup)
check("database backup readable", sqlite3.connect(str(backup)).execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 2)
shutil.copy2(config_path, WORK / "server.json.bak")
edited = json.loads(config_path.read_text())
edited.setdefault("integrity_mode", "log")
edited.setdefault("integrity_releases", {})
config_path.write_text(json.dumps(edited, indent=1))
loaded = subprocess.run([str(BINARY), "--config", str(config_path), "--check-config"], capture_output=True, text=True)
check("the binary validates the edited server.json", loaded.returncode == 0 and "mode=public" in loaded.stderr, loaded.stderr[-300:])
stop(old)
new = start_go(config_path, WORK / "new.log")
columns = [r[1] for r in sqlite3.connect(str(db)).execute("PRAGMA table_info(bans)")]
check("database has bans.expires", "expires" in columns, columns)
check("database has mod_log", sqlite3.connect(str(db)).execute("SELECT name FROM sqlite_master WHERE name='mod_log'").fetchone() is not None)

# 4. Checks.
check("/health", call("/health")[0] == 200)
status, answer = call("/social/session", {"pid": "0x10000001", "password": players[0x10000001]})
check("0.1.3 relay (no proof) still signs in with integrity_mode log", status == 200 and answer.get("token"), (status, answer))
time.sleep(0.5)
check("missing proof is logged", "refused proof" in (WORK / "new.log").read_text(errors="replace"))
status, _ = call("/social/session", {"pid": "0x10000001", "password": players[0x10000001], "client": {"version": "0.1.4", "code": "ab" * 32}})
check("unknown proof still signs in (log mode)", status == 200, status)
check("old ban still applies", call("/social/session", {"pid": "0x10000002", "password": players[0x10000002]})[0] == 403)
check("old ban listed by the new code", any(b["pid"] == "10000002" for b in call("/admin/bans", token=ADMIN)[1].get("bans", [])))
ops = [str(BINARY), "ops", "--url", f"http://127.0.0.1:{REG}", "--token", ADMIN]
check("ops ban 1 h", subprocess.run(ops + ["ban", "--pid", "0x10000001", "--hours", "1", "--reason", "rehearsal"], capture_output=True).returncode == 0)
check("banned player refused", call("/social/session", {"pid": "0x10000001", "password": players[0x10000001]})[0] == 403)
log = call("/admin/log", token=ADMIN)[1].get("log", [])
check("moderation log has the ban", log and log[0]["action"] == "ban" and "rehearsal" in log[0]["detail"], log[:1])
check("ops unban", subprocess.run(ops + ["unban", "--pid", "0x10000001"], capture_output=True).returncode == 0)
check("unbanned player signs in", call("/social/session", {"pid": "0x10000001", "password": players[0x10000001]})[0] == 200)

if ARGS.panel_py:
    # The admin panel's server helper, pointed at this server.
    panel_source = ARGS.panel_py.read_text(encoding="utf-8")
    remote = re.search(r"REMOTE = r'''(.*?)'''", panel_source, re.S).group(1).replace("/opt/splatoon/server.json", str(config_path).replace("\\", "/"))
    remote = remote.replace('sh("systemctl", "show"', 'sh("cmd", "/c", "echo"').replace('sh("tail", "-n", "120", "/var/log/splatoon/nexserver.log")', '""')
    remote = remote.replace('open("/proc/loadavg").read().split()[:3]', '["0", "0", "0"]').replace('props.get("ActiveState") == "active"', "True")
    helper = WORK / "panel_remote.py"
    helper.write_text(remote, encoding="utf-8")


    def panel(*args):
        return json.loads(subprocess.run([sys.executable, str(helper), *args], capture_output=True, text=True).stdout or "{}")


    status = panel("status")
    check("panel status sees bans and moderation log", isinstance(status.get("bans"), dict) and "bans" in status["bans"] and "log" in status.get("modlog", {}), status.keys())
    check("panel ban", panel("ban", base64.b64encode(json.dumps({"pid": "0x10000001", "hours": 2, "reason": "panel"}).encode()).decode()).get("ok") is True)
    check("panel unban", panel("unban", base64.b64encode(json.dumps({"pid": "0x10000001"}).encode()).decode()).get("ok") is True)
stop(new)

# 5. Rollback: Python on the database Go wrote.
shutil.copy2(WORK / "server.json.bak", config_path)
old = start_python(code, config_path, WORK / "rollback.log")
check("Python runs on the database Go wrote", call("/social/session", {"pid": "0x10000001", "password": players[0x10000001]})[0] == 200)
check("Python still sees the old ban", call("/social/session", {"pid": "0x10000002", "password": players[0x10000002]})[0] == 403)
check("Python sees the moderation log Go wrote", any("rehearsal" in entry["detail"] for entry in call("/admin/log", token=ADMIN)[1].get("log", [])))
stop(old)

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} checks passed" + (": FAILED " + ", ".join(failed) if failed else ""))
sys.exit(1 if failed else 0)
