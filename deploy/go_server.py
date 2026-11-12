"""Shared by the deploy scripts: where the Go server lives on the target and how to build it."""
import os
import pathlib
import subprocess
import sys

from remote import Target

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "linux" / "splatoon-nex"


class Go:
    """Paths of the live Go server on the target (see splatoon-nex-go.service)."""

    def __init__(self, target: Target):
        self.target = target
        self.dir = f"{target.root}/go"
        self.binary = f"{self.dir}/splatoon-nex"
        self.config = f"{self.dir}/server.json"
        self.log = target.log

    def as_service_user(self, command: str) -> str:
        """Files the server opens must stay owned by its user, so nothing runs on them as root."""
        return f"runuser -u {self.target.user} -- {command}"


def build() -> None:
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", "cmd", "internal", "go.mod", "go.sum"],
                           capture_output=True, text=True, check=True).stdout.strip()
    if dirty:
        sys.exit("Commit the Go changes first, the deployed binary must match a revision:\n" + dirty)
    environment = {**os.environ, "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}
    subprocess.run(["go", "build", "-trimpath", "-o", str(BINARY), "./cmd/splatoon-nex"], cwd=str(ROOT), env=environment, check=True)
