"""Shared by the deploy scripts: where the server lives (SSH target) and how to talk to it.

Nothing here is specific to one machine: every address, key and path comes from the command line.
"""
import argparse
import subprocess
import sys


def add_target_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("server to manage")
    group.add_argument("--host", required=True, help="SSH target, for example root@203.0.113.10")
    group.add_argument("--key", help="SSH private key (default: your ssh agent / ~/.ssh)")
    group.add_argument("--remote-root", default="/opt/splatoon", help="folder holding go/ and server.json")
    group.add_argument("--service", default="splatoon-nex-go", help="systemd unit of the live server")
    group.add_argument("--user", default="splatoon", help="system user the service runs as")
    group.add_argument("--db", default="/var/lib/splatoon/accounts.sqlite3", help="accounts database path on the server")
    group.add_argument("--remote-log", default="/var/log/splatoon/nexserver-go.log")
    group.add_argument("--remote-python", default="python3", help="Python on the server, only used to copy the SQLite database")
    group.add_argument("--domain", help="public domain, to check https://<domain>/health after a change")
    group.add_argument("--registration-port", type=int, default=60002, help="local HTTP port (never exposed)")


class Target:
    def __init__(self, args: argparse.Namespace):
        self.host = args.host
        self.key = args.key
        self.root = args.remote_root.rstrip("/")
        self.service = args.service
        self.user = args.user
        self.db = args.db
        self.log = args.remote_log
        self.domain = args.domain
        self.local_port = args.registration_port
        self.python = args.remote_python

    @property
    def config(self) -> str:
        return f"{self.root}/server.json"

    def _ssh_options(self) -> list:
        options = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
        return ["-i", self.key, *options] if self.key else options

    def ssh(self, command: str, check: bool = True, stdin: str = None) -> str:
        result = subprocess.run(["ssh", *self._ssh_options(), self.host, command], capture_output=True, text=True, input=stdin)
        if check and result.returncode != 0:
            sys.exit(f"Server command failed ({result.returncode}): {command}\n{result.stderr.strip()}")
        return result.stdout

    def scp(self, files: list, destination: str) -> None:
        subprocess.run(["scp", *self._ssh_options(), *files, f"{self.host}:{destination}"], check=True)

    def health(self) -> str:
        """Public /health when a domain is given, otherwise the local HTTP port seen from the server."""
        if self.domain:
            result = subprocess.run(["curl", "-s", "-m", "10", f"https://{self.domain}/health"], capture_output=True, text=True)
            return result.stdout.strip()
        return self.ssh(f"curl -s -m 10 http://127.0.0.1:{self.local_port}/health", check=False).strip()
