"""Append only, crash safe spool for received events (RF-01).

The spool is the durability boundary of the ingestion service: a batch is only
acknowledged to the agent after its raw payload has been written and flushed
to disk. Normalized events are written to a second stream so that RF-03 can
load PostgreSQL from a stable, already uniform input without touching the
network again.

Two directories are used:

- ``raw/`` — the Cowrie payload exactly as received, wrapped in an envelope
  that records when and from which agent it was received.
- ``normalized/`` — one :class:`NormalizedEvent` per line.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

RAW_STREAM = "raw"
NORMALIZED_STREAM = "normalized"
RAW_PREFIX = "cowrie"
NORMALIZED_PREFIX = "event"
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class _AppendStream:
    """A single append only JSON Lines file with size based rotation."""

    def __init__(
        self,
        directory: Path,
        prefix: str,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        fsync: bool = True,
        clock: Clock | None = None,
    ) -> None:
        self._directory = Path(directory)
        self._prefix = prefix
        self._max_bytes = max_bytes
        self._fsync = fsync
        self._clock = clock or SystemClock()
        self._handle: Any = None
        self._path: Path | None = None
        self._size = 0
        self._index = 0
        self.records_written = 0
        self.bytes_written = 0
        self.files_created = 0

    @property
    def path(self) -> Path | None:
        return self._path

    def append(self, records: Iterable[Mapping[str, Any]]) -> Path | None:
        """Append ``records`` as JSON Lines, returning the file written to."""

        payload = "".join(
            json.dumps(record, ensure_ascii=False, default=str, separators=(",", ":")) + "\n"
            for record in records
        )
        if not payload:
            return None

        encoded = payload.encode("utf-8")
        handle = self._ensure_open(len(encoded))
        handle.write(encoded)
        handle.flush()
        if self._fsync:
            os.fsync(handle.fileno())
        self._size += len(encoded)
        self.records_written += 1
        self.bytes_written += len(encoded)
        return self._path

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def _ensure_open(self, incoming: int) -> Any:
        if self._handle is not None:
            if self._size and self._size + incoming > self._max_bytes:
                self._rotate()
            else:
                return self._handle
        return self._open_new()

    def _rotate(self) -> None:
        self.close()
        self._index += 1
        self._open_new()

    def _open_new(self) -> Any:
        self._directory.mkdir(parents=True, exist_ok=True)
        day = self._clock.now().strftime("%Y%m%d")
        while True:
            suffix = "" if self._index == 0 else f"-{self._index:04d}"
            candidate = self._directory / f"{self._prefix}-{day}{suffix}.jsonl"
            if not candidate.exists() or candidate.stat().st_size < self._max_bytes:
                break
            self._index += 1

        handle = open(candidate, "ab")
        self._handle = handle
        self._path = candidate
        self._size = candidate.stat().st_size
        self.files_created += 1
        return handle

    def stats(self) -> dict[str, Any]:
        return {
            "path": str(self._path) if self._path else None,
            "records_written": self.records_written,
            "bytes_written": self.bytes_written,
            "files_created": self.files_created,
        }


class EventSpool:
    """Durable landing zone for raw and normalized events."""

    def __init__(
        self,
        spool_dir: Path,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        fsync: bool = True,
        clock: Clock | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._raw = _AppendStream(
            Path(spool_dir) / RAW_STREAM,
            RAW_PREFIX,
            max_bytes=max_bytes,
            fsync=fsync,
            clock=clock,
        )
        self._normalized = _AppendStream(
            Path(spool_dir) / NORMALIZED_STREAM,
            NORMALIZED_PREFIX,
            max_bytes=max_bytes,
            fsync=fsync,
            clock=clock,
        )

    def write_raw(self, records: Iterable[Mapping[str, Any]]) -> Path | None:
        with self._lock:
            return self._raw.append(records)

    def write_normalized(self, records: Iterable[Mapping[str, Any]]) -> Path | None:
        with self._lock:
            return self._normalized.append(records)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "raw": self._raw.stats(),
                "normalized": self._normalized.stats(),
            }

    def close(self) -> None:
        with self._lock:
            self._raw.close()
            self._normalized.close()
