"""Generate PKI once, then distribute only each service's required files."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

SOURCE = Path("/tmp/generated-certs")
CA_STATE = Path("/ca-private")
ROLES = {
    "backend": ("server.crt", "server.key", "probe.crt", "probe.key", 10001),
    "agent": ("agent.crt", "agent.key", None, None, 10002),
    "proxy": ("proxy.crt", "proxy.key", None, None, 0),
}


def main() -> int:
    SOURCE.mkdir(parents=True, exist_ok=True)
    if (CA_STATE / "ca.crt").is_file() and (CA_STATE / "ca.key").is_file():
        shutil.copy2(CA_STATE / "ca.crt", SOURCE / "ca.crt")
        shutil.copy2(CA_STATE / "ca.key", SOURCE / "ca.key")
    subprocess.run(
        [sys.executable, "/opt/generate-dev-certs.py", "--out", str(SOURCE)],
        check=True,
    )
    CA_STATE.mkdir(parents=True, exist_ok=True)
    _copy("ca.crt", CA_STATE, 0o644, 0)
    _copy("ca.key", CA_STATE, 0o600, 0)
    for role, (cert, key, extra_cert, extra_key, uid) in ROLES.items():
        target = Path("/runtime") / role
        target.mkdir(parents=True, exist_ok=True)
        _copy("ca.crt", target, 0o444, uid)
        for name in (cert, key, extra_cert, extra_key):
            if name:
                _copy(name, target, 0o444 if name.endswith(".crt") else 0o400, uid)
    return 0


def _copy(name: str, target: Path, mode: int, uid: int) -> None:
    destination = target / name
    shutil.copyfile(SOURCE / name, destination)
    destination.chmod(mode)
    if hasattr(__import__("os"), "chown"):
        import os

        os.chown(destination, uid, -1)


if __name__ == "__main__":
    raise SystemExit(main())
