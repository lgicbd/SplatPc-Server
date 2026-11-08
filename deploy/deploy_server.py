"""Deploy the NEX server code of this checkout to a Linux server over SSH, with backups and a rollback.

    py -3 deploy/deploy_server.py --host root@SERVER [--key KEY] [--domain DOMAIN]            dry run (read-only)
    py -3 deploy/deploy_server.py --host root@SERVER ... --apply                              does it, then verifies
    py -3 deploy/deploy_server.py --host root@SERVER ... --rollback <stamp>                   puts a backup back

What --apply changes on the server:
  - backups: <root>/tools.bak-<stamp>-nexlab, <root>/server.json.bak-<stamp>, <db>.bak-<stamp> (online SQLite
    backup, safe while the server runs);
  - the files of tools/nexlab that differ (taken from git HEAD of this checkout), checked with py_compile first;
  - server.json: adds "integrity_mode": "log" and "integrity_releases": {} when absent (every other key kept);
  - restart of the service. New code adds database columns and tables on first start (additive: the previous
    code still runs on the migrated database).
The admin token never leaves the server. The restart drops running matches: do it when nobody plays.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import time

from remote import Target, add_target_args

ROOT = pathlib.Path(__file__).resolve().parents[1]


def server_files() -> list:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "tools/nexlab/*.py"], capture_output=True, text=True, check=True).stdout
    return sorted(pathlib.PurePosixPath(line).name for line in out.split())


def local_files(names: list) -> dict:
    """The server files as git HEAD has them (LF), not the working tree."""
    return {name: subprocess.run(["git", "-C", str(ROOT), "show", f"HEAD:tools/nexlab/{name}"], capture_output=True, check=True).stdout
            for name in names}


def preflight(target: Target):
    print("service:", target.ssh(f"systemctl is-active {target.service}", check=False).strip())
    files = local_files(server_files())
    listing = target.ssh(f"cd {target.code_dir} && sha256sum {' '.join(files)}", check=False)
    remote = {line.split()[1]: line.split()[0] for line in listing.splitlines() if len(line.split()) == 2}
    changed = [n for n, data in files.items() if hashlib.sha256(data).hexdigest() != remote.get(n)]
    print("files to update:", ", ".join(changed) or "none")
    config = json.loads(target.ssh(f"cat {target.config}"))
    print("server.json keys:", ", ".join(sorted(config)), "| integrity_mode now:", config.get("integrity_mode", "(absent = off)"))
    print("free space:", target.ssh("df -h / | tail -1").split()[3])
    return files, changed


def apply(target: Target, files: dict, changed: list) -> None:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    root, code, py, db = target.root, target.code_dir, target.python, target.db
    print(f"backup stamp: {stamp}")
    target.ssh(f"cp -a {code} {root}/tools.bak-{stamp}-nexlab && cp -a {target.config} {target.config}.bak-{stamp}")
    target.ssh(f"""{py} -c "import sqlite3; s=sqlite3.connect('{db}'); d=sqlite3.connect('{db}.bak-{stamp}'); s.backup(d); d.close(); s.close()" """
               f"&& chown {target.user}: {db}.bak-{stamp} && chmod 600 {db}.bak-{stamp}")
    staging = f"{root}/nexlab-new-{stamp}"
    target.ssh(f"mkdir -p {staging}")
    with tempfile.TemporaryDirectory() as tmp:
        for name in changed:
            pathlib.Path(tmp, name).write_bytes(files[name])
        if changed:
            target.scp([str(pathlib.Path(tmp, n)) for n in changed], staging + "/")
    target.ssh(f"mkdir -p {staging}/check && cp -a {code}/*.py {staging}/check/ && (cp -a {staging}/*.py {staging}/check/ 2>/dev/null || true); "
               f"cd {staging}/check && {py} -m py_compile *.py")
    # The new configuration is written aside, checked with the NEW code, and only then put in place.
    edit = (f"import json; p='{target.config}'; c=json.load(open(p)); c.setdefault('integrity_mode','log'); "
            f"c.setdefault('integrity_releases',{{}}); json.dump(c, open('{staging}/server.json','w'), indent=1)")
    target.ssh(f'{py} -c "{edit}"')
    target.ssh(f"cd {staging}/check && {py} -c \"import server_config; c=server_config.ServerConfig.load('{staging}/server.json'); print(c.integrity_mode)\"")
    target.ssh(f"cp -a {staging}/check/*.py {code}/ && cp {staging}/server.json {target.config} && chown -R {target.user}: {code} {target.config} "
               f"&& chmod 600 {target.config} && rm -rf {staging} && systemctl restart {target.service}")
    time.sleep(6)
    verify(target)
    print(f"\nDone. To undo: py -3 deploy/deploy_server.py --host {target.host} --rollback {stamp}")


def verify(target: Target) -> None:
    print("service:", target.ssh(f"systemctl is-active {target.service}", check=False).strip())
    print("health:", target.health())
    print("log (errors since restart):")
    print(target.ssh(f"journalctl -u {target.service} --since '-2 min' --no-pager | tail -5; "
                     f"grep -E 'ERROR|Traceback|CRITICAL' {target.log} | tail -5", check=False))


def rollback(target: Target, stamp: str) -> None:
    root = target.root
    target.ssh(f"test -d {root}/tools.bak-{stamp}-nexlab && cp -a {root}/tools.bak-{stamp}-nexlab/. {target.code_dir}/ "
               f"&& cp -a {target.config}.bak-{stamp} {target.config} && chown -R {target.user}: {target.code_dir} {target.config} "
               f"&& systemctl restart {target.service}")
    time.sleep(6)
    verify(target)
    print(f"(the database backup {target.db}.bak-{stamp} was not restored: the new columns are harmless to the old code)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_target_args(parser)
    parser.add_argument("--apply", action="store_true", help="do it (default: dry run)")
    parser.add_argument("--rollback", metavar="STAMP", help="restore the backup made by an earlier --apply")
    args = parser.parse_args()
    target = Target(args)
    if args.rollback:
        rollback(target, args.rollback)
        return
    files, changed = preflight(target)
    if args.apply:
        apply(target, files, changed)
    else:
        print("\nDry run only. --apply: backups (code, server.json, database) -> upload to a staging folder -> py_compile -> "
              "new server.json checked by the new code -> files and config put in place -> restart -> checks.")


if __name__ == "__main__":
    main()
