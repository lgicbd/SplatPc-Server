"""Set integrity_mode and the accepted release hashes in the server's server.json, then restart and check.

    py -3 deploy/set_integrity.py --host root@SERVER enforce 0.1.4=<hash1>,<hash2>            dry run: prints the new keys
    py -3 deploy/set_integrity.py --host root@SERVER enforce 0.1.4=<hash1>,<hash2> --apply
    py -3 deploy/set_integrity.py --host root@SERVER log --apply                              back to log, releases kept
    py -3 deploy/set_integrity.py --host root@SERVER enforce 0.1.5=<hash> --min-client-version 0.1.5   a forced update

--min-client-version also sets "min_client_version" (published in /health: older launchers stop before the game).

The release list given here REPLACES the whole "integrity_releases" object: repeat the hashes of the versions you still
accept. The hashes come from `py -3 scripts/integrity.py --make` in the game repository (see docs/SERVEUR.md).
The new file is checked by the server itself before use: the Go binary (--check-config) when Go is the live server,
the Python code otherwise. The dry run does that check too, on a temporary copy that it removes. With --apply,
server.json is backed up first (server.json.bak-<stamp>). When Go is live its unit is the one restarted.
"""
import argparse
import json
import re
import sys
import time

from deploy_go import GO_SERVICE, Go, go_is_live
from remote import Target, add_target_args


def edited(config: dict, mode: str, release: str = None, min_client_version: str = None) -> dict:
    """The server.json with the new integrity keys; every other key is kept."""
    config = dict(config)
    config["integrity_mode"] = mode
    if release:
        version, _, hashes = release.partition("=")
        names = hashes.split(",")
        if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not all(re.fullmatch(r"[0-9a-f]{64}", name) for name in names):
            sys.exit("release must be VERSION=hash[,hash...] with 64 hex digit hashes, for example 0.1.5=ab12...")
        config["integrity_releases"] = {version: names}
    if min_client_version:
        if not re.fullmatch(r"\d+\.\d+\.\d+", min_client_version):
            sys.exit("--min-client-version must look like 0.1.5")
        config["min_client_version"] = min_client_version
    return config


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_target_args(parser)
    parser.add_argument("mode", choices=["off", "log", "enforce"])
    parser.add_argument("release", nargs="?", help="VERSION=hash[,hash...]")
    parser.add_argument("--min-client-version", help="also set min_client_version, for example 0.1.5")
    parser.add_argument("--apply", action="store_true", help="do it (default: dry run)")
    args = parser.parse_args()
    target = Target(args)

    run(target, args.mode, args.release, args.min_client_version, args.apply)


def checked(target: Target, go: Go, live: bool, path: str) -> None:
    """Stops (non-zero exit of the remote command) when the server would refuse this file."""
    if live:
        # stderr is kept apart: Target.ssh shows it when the binary refuses the file
        print("config check:", target.ssh(go.as_service_user(f"{go.binary} --config {path} --check-config")).strip())
    else:
        target.ssh(f"cd {target.code_dir} && {target.python} -c \"import server_config; "
                   f"c=server_config.ServerConfig.load('{path}'); print(c.integrity_mode, sorted(c.integrity_releases))\"")


def run(target: Target, mode: str, release: str, min_client_version: str, apply: bool) -> None:
    go = Go(target, 0)
    live = go_is_live(target, go)
    service = GO_SERVICE if live else target.service
    before = json.loads(target.ssh(f"cat {target.config}"))
    config = edited(before, mode, release, min_client_version)
    for key in ("integrity_mode", "integrity_releases", "min_client_version"):   # never the other keys: some are secret
        print(f"{key}: {json.dumps(before.get(key))} -> {json.dumps(config.get(key))}")
    print("server:", "Go" if live else "Python", "| unit:", service)

    new, stamp = f"{target.config}.new", time.strftime("%Y%m%d-%H%M%S")
    write = f"cat > {new} && chmod --reference={target.config} {new} && chown --reference={target.config} {new}"
    target.ssh(write, stdin=json.dumps(config, indent=1))
    try:
        checked(target, go, live, new)
    except SystemExit:
        target.ssh(f"rm -f {new}", check=False)
        raise
    if not apply:
        target.ssh(f"rm -f {new}")
        print("Dry run only: the new file passed the server's check and was removed. Nothing changed.")
        return

    target.ssh(f"cp -p {target.config} {target.config}.bak-{stamp}")
    target.ssh(f"mv {new} {target.config} && systemctl restart {service}")
    time.sleep(6)
    print("service:", target.ssh(f"systemctl is-active {service}", check=False).strip())
    print("health:", target.health())
    print(f"undo: cp -p {target.config}.bak-{stamp} {target.config} && systemctl restart {service}")


if __name__ == "__main__":
    main()
