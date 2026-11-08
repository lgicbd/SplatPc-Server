"""Set integrity_mode and the accepted release hashes in the server's server.json, then restart and check.

    py -3 deploy/set_integrity.py --host root@SERVER enforce 0.1.4=<hash1>,<hash2>            dry run: prints the new keys
    py -3 deploy/set_integrity.py --host root@SERVER enforce 0.1.4=<hash1>,<hash2> --apply
    py -3 deploy/set_integrity.py --host root@SERVER log --apply                              back to log, releases kept

The release list given here REPLACES the whole "integrity_releases" object: repeat the hashes of the versions you still
accept. The hashes come from `py -3 scripts/integrity.py --make` in the game repository (see docs/SERVEUR.md).
Backs up server.json first (server.json.bak-<stamp>); the new file is loaded by the server code before use.
"""
import argparse
import json
import time

from remote import Target, add_target_args


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_target_args(parser)
    parser.add_argument("mode", choices=["off", "log", "enforce"])
    parser.add_argument("release", nargs="?", help="VERSION=hash[,hash...]")
    parser.add_argument("--apply", action="store_true", help="do it (default: dry run)")
    args = parser.parse_args()
    target = Target(args)

    config = json.loads(target.ssh(f"cat {target.config}"))
    config["integrity_mode"] = args.mode
    if args.release:
        version, _, hashes = args.release.partition("=")
        config["integrity_releases"] = {version: hashes.split(",")}
    print("integrity_mode:", config["integrity_mode"], "| releases:", json.dumps(config.get("integrity_releases")))
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
