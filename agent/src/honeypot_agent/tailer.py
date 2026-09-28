"""Continuous reader for the Cowrie JSON log (RF-01).

``cowrie.json`` is a JSON Lines file: one event per line, appended by Cowrie.
The tailer only ever returns complete lines, so a line that is still being
written is left untouched until its newline arrives.

Rotation and truncation are both detected by comparing the open file with the
path on disk, and they are handled differently because they are not equally
harmful. A rotation replaces the file, so the inode changes and nothing is lost
by reopening. A truncation keeps the inode and shrinks the file, which means
whatever was written between the last read and the truncate is already gone from
disk: the agent cannot recover it, and it re-reads from the beginning of the
new content. That is a property of ``copytruncate``, not a bug to fix here, so
the tailer counts it and says so loudly instead of pretending it is a rotation.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from honeypot_agent.checkpoint import Checkpoint

logger = logging.getLogger(__name__)

NEWLINE = b"\n"


@dataclass(frozen=True, slots=True)
class TailRecord:
    """A complete log line and the offset just past it."""

    text: str
    offset: int


class CowrieLogTailer:
    """Read new lines from ``cowrie.json`` starting at a checkpoint."""

    def __init__(
        self,
        path: Path | str,
        checkpoint: Checkpoint | None = None,
        *,
        start_at_end: bool = True,
    ) -> None:
        self._path = Path(path)
        self._checkpoint = checkpoint
        self._start_at_end = start_at_end
        self._handle: object | None = None
        self._offset = 0
        self._inode: int | None = None
        self._warned_missing = False
        self._rotations = 0
        self._truncations = 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def offset(self) -> int:
        """Current read position."""

        return self._offset

    @property
    def inode(self) -> int | None:
        """Inode of the file currently being read."""

        return self._inode

    @property
    def rotations(self) -> int:
        """How many times the log was replaced under us. No data is lost."""

        return self._rotations

    @property
    def truncations(self) -> int:
        """How many times the log was truncated in place.

        Each one means a window of already written events was discarded before
        the agent could read it. Treat a non zero value as lost evidence.
        """

        return self._truncations

    def poll(self) -> list[TailRecord]:
        """Return every complete line available since the last call."""

        if not self._ensure_open():
            return []

        records: list[TailRecord] = []
        handle = self._handle
        assert handle is not None
        while True:
            line_start = self._offset
            line = handle.readline()
            if not line:
                self._offset = line_start
                break
            if not line.endswith(NEWLINE):
                self._offset = line_start
                handle.seek(line_start)
                break
            self._offset += len(line)
            records.append(TailRecord(text=line.decode("utf-8", errors="replace").strip(), offset=self._offset))
        return records

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def _ensure_open(self) -> bool:
        if self._handle is not None:
            try:
                path_stat = os.stat(self._path)
            except FileNotFoundError:
                return True
            if self._is_rotated(path_stat):
                self._handle_rotation(path_stat)
            elif path_stat.st_size < self._offset:
                self._handle_truncation(path_stat)
            return True

        try:
            path_stat = os.stat(self._path)
        except FileNotFoundError:
            if not self._warned_missing:
                logger.warning("waiting for %s to appear", self._path)
                self._warned_missing = True
            return False
        self._warned_missing = False
        self._open(path_stat)
        return True

    def _is_rotated(self, path_stat: os.stat_result) -> bool:
        handle = self._handle
        if handle is None or self._inode is None or path_stat.st_ino == 0:
            return False
        try:
            open_stat = os.fstat(handle.fileno())
        except OSError:
            return True
        return open_stat.st_ino != path_stat.st_ino

    def _handle_rotation(self, path_stat: os.stat_result) -> None:
        """The file was replaced. Reopen it; nothing was lost by doing so."""

        self._rotations += 1
        logger.warning(
            "%s was rotated: the file was replaced (inode %s became %s), "
            "reopening from its beginning",
            self._path,
            self._inode,
            path_stat.st_ino,
        )
        self._reopen(path_stat)

    def _handle_truncation(self, path_stat: os.stat_result) -> None:
        """The file was emptied in place, so unread events are already gone.

        With ``copytruncate`` the writer truncates the same inode, so the lines
        written since the last read were erased before this process saw them.
        No offset can recover them. What is left is to restart cleanly at the
        beginning of the new content and to make the loss visible to whoever
        reads the logs.
        """

        self._truncations += 1
        lost_from = self._offset
        logger.error(
            "%s was truncated in place at %d bytes, now %d bytes. Any events "
            "written between the last read and the truncate are lost and cannot "
            "be recovered. This is the known cost of copytruncate; switch the log "
            "to rename based rotation to avoid it.",
            self._path,
            lost_from,
            path_stat.st_size,
        )
        self._reopen(path_stat)

    def _reopen(self, path_stat: os.stat_result) -> None:
        self.close()
        self._open(path_stat, force_beginning=True)

    def _open(self, path_stat: os.stat_result, *, force_beginning: bool = False) -> None:
        self._handle = open(self._path, "rb")
        start = self._start_offset(path_stat, force_beginning=force_beginning)
        if start:
            self._handle.seek(start)
        self._offset = start
        self._inode = path_stat.st_ino
        logger.info("tailing %s from offset %d (inode %s)", self._path, start, path_stat.st_ino)

    def _start_offset(self, path_stat: os.stat_result, *, force_beginning: bool) -> int:
        if force_beginning:
            return 0
        checkpoint = self._checkpoint
        if checkpoint is not None and checkpoint.offset > 0:
            same_file = checkpoint.inode is None or checkpoint.inode == path_stat.st_ino
            if same_file and checkpoint.offset <= path_stat.st_size:
                return checkpoint.offset
            logger.warning(
                "checkpoint (inode=%s offset=%d) does not match %s (inode=%s size=%d), "
                "restarting from its beginning",
                checkpoint.inode,
                checkpoint.offset,
                self._path,
                path_stat.st_ino,
                path_stat.st_size,
            )
        if self._start_at_end:
            return path_stat.st_size
        return 0
