"""Load the normalized spool into PostgreSQL (RF-03).

The normalized spool produced by the ingestion pipeline is the hand off
between RF-02 and RF-03. This replayer is the only writer of the ``events``
table, which keeps a single code path and makes loading restartable:

- The read position of every spool file is stored in ``spool_cursors``.
- A batch is only committed together with the cursor that follows it, so a
  crash replays at most one batch, and replays are harmless because inserts
  ignore duplicate ``event_id`` values.
- If PostgreSQL is unreachable the cursor stays where it is and ingestion
  keeps working: events pile up in the spool until the database returns.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from honeypot_backend.config import Settings
from honeypot_backend.db.repository import EventRepository
from honeypot_backend.db.session import apply_migrations, get_engine

logger = logging.getLogger(__name__)

SPOOL_GLOB = "*.jsonl"


class NormalizedSpoolReplayer:
    """Move normalized events from the spool into the ``events`` table."""

    def __init__(
        self,
        settings: Settings,
        normalized_dir: Path,
        *,
        sessionmaker: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._settings = settings
        self._directory = Path(normalized_dir)
        self._sessionmaker = sessionmaker
        self._cursors: dict[str, int] = {}
        self._schema_ready = False
        self._stopping = asyncio.Event()
        self.events_loaded = 0
        self.batches_loaded = 0
        self.malformed_lines = 0
        self.failures = 0

    @property
    def directory(self) -> Path:
        return self._directory

    def request_stop(self) -> None:
        """Ask the loop to finish and exit."""

        self._stopping.set()

    async def run(self) -> None:
        """Load the spool until asked to stop, retrying on database errors."""

        logger.info("spool replayer started: %s", self._directory)
        while not self._stopping.is_set():
            try:
                loaded = await self.run_once()
            except Exception as exc:  # noqa: BLE001 - the replayer must never die
                self.failures += 1
                self._schema_ready = False
                logger.error("spool replayer pass failed: %s", exc)
                loaded = 0
                await self._backoff()
            if not loaded:
                try:
                    await asyncio.wait_for(
                        self._stopping.wait(), timeout=self._settings.spool_replay_interval
                    )
                except TimeoutError:
                    continue
        logger.info(
            "spool replayer stopped: events=%d batches=%d malformed=%d failures=%d",
            self.events_loaded,
            self.batches_loaded,
            self.malformed_lines,
            self.failures,
        )

    async def run_once(self) -> int:
        """Drain every spool file once, returning the number of stored events."""

        if not self._schema_ready:
            await apply_migrations(get_engine(self._settings))
            self._schema_ready = True

        stored = 0
        for path in self._files():
            stored += await self._drain(path)
        return stored

    def stats(self) -> dict[str, Any]:
        return {
            "directory": str(self._directory),
            "events_loaded": self.events_loaded,
            "batches_loaded": self.batches_loaded,
            "malformed_lines": self.malformed_lines,
            "failures": self.failures,
            "cursors": dict(self._cursors),
        }

    def _files(self) -> list[Path]:
        if not self._directory.is_dir():
            return []
        return sorted(self._directory.glob(SPOOL_GLOB), key=lambda item: item.name)

    async def _drain(self, path: Path) -> int:
        key = str(path)
        offset = self._cursors.get(key)
        if offset is None:
            offset = await self._load_cursor(key)
            self._cursors[key] = offset

        size = path.stat().st_size
        if size < offset:
            logger.warning(
                "%s shrank from %d to %d bytes, reloading it from the beginning", path, offset, size
            )
            offset = 0

        records, consumed, malformed = await asyncio.to_thread(
            _read_batch, path, offset, self._settings.spool_replay_batch_size
        )
        if malformed:
            self.malformed_lines += malformed
            logger.warning("skipped %d unparsable line(s) in %s", malformed, path)
        if consumed == 0:
            return 0

        new_offset = offset + consumed
        if records:
            async with self._sessions()() as session:
                repository = EventRepository(session)
                inserted = await repository.insert_events(records)
                await repository.set_cursor(key, new_offset)
                await session.commit()
            self.batches_loaded += 1
            self.events_loaded += inserted
        else:
            async with self._sessions()() as session:
                await EventRepository(session).set_cursor(key, new_offset)
                await session.commit()

        self._cursors[key] = new_offset
        return len(records)

    async def _load_cursor(self, path: str) -> int:
        async with self._sessions()() as session:
            return await EventRepository(session).get_cursor(path)

    async def _backoff(self) -> None:
        try:
            await asyncio.wait_for(
                self._stopping.wait(), timeout=self._settings.spool_replay_error_backoff
            )
        except TimeoutError:
            return

    def _sessions(self) -> async_sessionmaker[AsyncSession]:
        """Return the session factory, creating it on first use."""

        if self._sessionmaker is None:
            from honeypot_backend.db.session import get_sessionmaker

            self._sessionmaker = get_sessionmaker(self._settings)
        return self._sessionmaker


def _read_batch(path: Path, offset: int, limit: int) -> tuple[list[dict[str, Any]], int, int]:
    """Read up to ``limit`` complete JSON objects starting at ``offset``.

    Returns:
        The decoded records, the number of bytes consumed and the number of
        lines that could not be decoded.
    """

    records: list[dict[str, Any]] = []
    consumed = 0
    malformed = 0
    with open(path, "rb") as handle:
        handle.seek(offset)
        while len(records) < limit:
            line = handle.readline()
            if not line or not line.endswith(b"\n"):
                break
            consumed += len(line)
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(payload, dict):
                records.append(payload)
            else:
                malformed += 1
    return records, consumed, malformed
