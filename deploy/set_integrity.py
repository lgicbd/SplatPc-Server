"""Set integrity_mode and the accepted release hashes in the server's server.json, then restart and check.

    py -3 deploy/set_integrity.py --host root@SERVER enforce 0.1.4=<hash1>,<hash2>            dry run: prints the new keys
    py -3 deploy/set_integrity.py --host root@SERVER enforce 0.1.4=<hash1>,<hash2> --apply
    py -3 deploy/set_integrity.py --host root@SERVER log --apply                              back to log, releases kept
    py -3 deploy/set_integrity.py --host root@SERVER enforce 0.1.5=<hash> --min-client-version 0.1.5   a forced update

--min-client-version also sets "min_client_version" (published in /health: older launchers stop before the game).

The release list given here REPLACES the whole "integrity_releases" object: repeat the hashes of the versions you still
accept. The hashes come from `py -3 scripts/integrity.py --make` in the game repository (see docs/SERVEUR.md).
Backs up server.json first (server.json.bak-<stamp>); the new file is loaded by the server code before use.
"""
import argparse
import json
import re
import sys
import time

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

    before = json.loads(target.ssh(f"cat {target.config}"))
    config = edited(before, args.mode, args.release, args.min_client_version)
    for key in ("integrity_mode", "integrity_releases", "min_client_version"):   # never the other keys: some are secret
        print(f"{key}: {json.dumps(before.get(key))} -> {json.dumps(config.get(key))}")
    if not args.apply:
        print("Dry run only.")
        return

    new, stamp = f"{target.config}.new", time.strftime("%Y%m%d-%H%M%S")
    target.ssh(f"cp -p {target.config} {target.config}.bak-{stamp}")
    target.ssh(f"cat > {new} && chmod --reference={target.config} {new} && chown --reference={target.config} {new}",
               stdin=json.dumps(config, indent=1))
    target.ssh(f"cd {target.code_dir} && {target.python} -c \"import server_config; "
               f"c=server_config.ServerConfig.load('{new}'); print(c.integrity_mode, sorted(c.integrity_releases))\"")
    target.ssh(f"mv {new} {target.config} && systemctl restart {target.service}")
    time.sleep(6)
    print("service:", target.ssh(f"systemctl is-active {target.service}").strip())
    print("health:", target.health())
    print(f"undo: copy {target.config}.bak-{stamp} back to {target.config} and restart {target.service}")


if __name__ == "__main__":
    main()
