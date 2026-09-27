"""Durable read position inside ``cowrie.json`` (RF-01).

The checkpoint is the agent's registry: it records the byte offset just past
the last line whose batch was acknowledged by the backend, so a restart
resumes exactly where delivery stopped instead of re-reading the whole file or
skipping events.

Writes are atomic (temporary file, ``fsync``, ``os.replace``) because the file
is updated on every acknowledged batch, including on a power loss.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TEMP_SUFFIX = ".tmp"


@dataclass(slots=True)
class Checkpoint:
    """The last position of ``cowrie.json`` acknowledged by the backend."""

    path: str
    offset: int = 0
    inode: int | None = None
    updated_at: str | None = None
    sequence: int | None = None

    @property
    def timestamp(self) -> datetime | None:
        if not self.updated_at:
            return None
        try:
            return datetime.fromisoformat(self.updated_at)
        except ValueError:
            return None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Checkpoint:
        offset = data.get("offset", 0)
        inode = data.get("inode")
        sequence = data.get("sequence")
        return cls(
            path=str(data.get("path", "")),
            offset=int(offset) if isinstance(offset, (int, float)) else 0,
            inode=int(inode) if isinstance(inode, (int, float)) else None,
            updated_at=data.get("updated_at") if isinstance(data.get("updated_at"), str) else None,
            sequence=int(sequence) if isinstance(sequence, (int, float)) else None,
        )


def load_checkpoint(path: Path) -> Checkpoint | None:
    """Read a checkpoint, returning ``None`` when absent or unreadable."""

    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.error("cannot read checkpoint %s: %s", path, exc)
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("checkpoint %s is corrupted, starting from the beginning: %s", path, exc)
        return None
    if not isinstance(data, dict):
        logger.error("checkpoint %s has an unexpected shape, ignoring it", path)
        return None
    return Checkpoint.from_dict(data)


def save_checkpoint(path: Path, checkpoint: Checkpoint) -> None:
    """Atomically persist ``checkpoint``."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    checkpoint.updated_at = datetime.now(UTC).isoformat()
    payload = json.dumps(checkpoint.to_dict(), indent=2, sort_keys=True).encode("utf-8")

    temp = target.with_name(target.name + TEMP_SUFFIX)
    with open(temp, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, target)
    _fsync_directory(target.parent)


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
