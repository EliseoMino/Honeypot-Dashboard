"""The tailer decides what counts as a complete event, so it must never
deliver a half-written line and must survive Cowrie restarting the log.

Platform note: replacing a file that the tailer holds open only works where the
operating system allows it. Linux (the platform the agent runs on) permits the
rename, so rotation is covered by ``test_rotation_*`` below. Windows denies it,
so those two tests are skipped there; truncation and the checkpoint rules cover
the same ``_reopen`` path on every platform.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from honeypot_agent.checkpoint import Checkpoint
from honeypot_agent.tailer import CowrieLogTailer

CAN_REPLACE_OPEN_FILE = sys.platform != "win32"
requires_replace = pytest.mark.skipif(
    not CAN_REPLACE_OPEN_FILE,
    reason="the OS does not allow replacing a file that is already open",
)


def test_a_missing_log_yields_nothing_instead_of_raising(tmp_path: Path) -> None:
    tailer = CowrieLogTailer(tmp_path / "absent.json")

    assert tailer.poll() == []


def test_a_log_that_appears_later_is_picked_up(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    assert tailer.poll() == []

    append('{"eventid": "cowrie.session.connect"}')

    records = tailer.poll()
    assert len(records) == 1
    assert records[0].text == '{"eventid": "cowrie.session.connect"}'


def test_every_complete_line_is_returned_once(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append("one")
    append("two")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)

    records = tailer.poll()

    assert [r.text for r in records] == ["one", "two"]
    assert tailer.poll() == []


def test_the_record_offset_is_just_past_the_line(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    first = append("one")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()

    second = append("two")
    records = tailer.poll()

    assert records[0].offset == second
    assert first < records[0].offset
    assert tailer.offset == cowrie_log.stat().st_size


def test_an_incomplete_line_is_left_for_the_next_poll(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append("complete")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    first = tailer.poll()

    append('{"eventid": "cowrie.log', newline=False)
    assert tailer.poll() == []
    assert tailer.offset == first[0].offset

    end = append('ic.closed"}')

    records = tailer.poll()
    assert len(records) == 1
    assert records[0].text == '{"eventid": "cowrie.logic.closed"}'
    assert records[0].offset == end


def test_starting_at_end_skips_what_was_already_written(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append("old-1")
    append("old-2")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=True)

    assert tailer.poll() == []
    assert tailer.offset == cowrie_log.stat().st_size


def test_starting_at_end_still_reads_new_lines(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append("old")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=True)
    tailer.poll()

    append("new")

    assert [r.text for r in tailer.poll()] == ["new"]


def test_a_checkpoint_resumes_exactly_where_it_stopped(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append("first")
    append("second")
    consumed = append("already-acked")
    append("pending-1")
    append("pending-2")

    tailer = CowrieLogTailer(
        cowrie_log,
        Checkpoint(path=str(cowrie_log), offset=consumed, inode=None),
        start_at_end=True,
    )
    records = tailer.poll()

    assert [r.text for r in records] == ["pending-1", "pending-2"]


def test_a_checkpoint_past_the_end_restarts_from_the_beginning(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    """A shrunken log makes the stored offset meaningless, so re-read it all."""

    append("first")
    append("second")

    tailer = CowrieLogTailer(
        cowrie_log,
        Checkpoint(path=str(cowrie_log), offset=10_000, inode=None),
        start_at_end=False,
    )
    records = tailer.poll()

    assert [r.text for r in records] == ["first", "second"]


def test_a_checkpoint_from_another_log_restarts_from_the_beginning(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    """After a rotation the inode differs, so the offset belongs to the old file."""

    append("first")
    append("second")

    tailer = CowrieLogTailer(
        cowrie_log,
        Checkpoint(path=str(cowrie_log), offset=6, inode=999_999),
        start_at_end=False,
    )
    records = tailer.poll()

    assert [r.text for r in records] == ["first", "second"]


def test_an_unusable_checkpoint_keeps_the_start_at_end_policy(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    """With ``start_at_end`` the agent stays at the end rather than replaying.

    The log line says "restarting from its beginning", but the code honours the
    configured policy. Documented here so the behaviour is pinned either way.
    """

    append("first")
    append("second")

    tailer = CowrieLogTailer(
        cowrie_log,
        Checkpoint(path=str(cowrie_log), offset=10_000, inode=None),
        start_at_end=True,
    )

    assert tailer.poll() == []
    assert tailer.offset == cowrie_log.stat().st_size


def test_a_truncated_log_is_reopened_from_the_beginning(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append("one")
    append("two")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()
    assert tailer.offset == cowrie_log.stat().st_size

    cowrie_log.write_bytes(b"")
    append("fresh")

    records = tailer.poll()

    assert [r.text for r in records] == ["fresh"]
    assert tailer.offset == cowrie_log.stat().st_size


def test_a_truncation_seen_on_a_poll_is_reopened(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    """The supported copytruncate case: the tailer observes the empty file."""

    append("one")
    append("two")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()
    assert tailer.offset == cowrie_log.stat().st_size

    cowrie_log.write_bytes(b"")
    assert tailer.poll() == []  # observes the truncation while the file is empty
    append("after-truncate")

    records = tailer.poll()

    assert [r.text for r in records] == ["after-truncate"]


def test_a_truncation_is_counted(cowrie_log: Path, append: Callable[..., int]) -> None:
    """Truncation is counted, because it means events were lost."""

    append("one")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()
    assert tailer.truncations == 0

    cowrie_log.write_bytes(b"")
    assert tailer.poll() == []  # the empty file is the detectable moment
    append("after")

    assert tailer.truncations == 1
    assert tailer.rotations == 0


def test_a_truncation_is_logged_as_lost_data(
    cowrie_log: Path, append: Callable[..., int], caplog: pytest.LogCaptureFixture
) -> None:
    """The operator has to be told the evidence is gone, not that it rotated."""

    append("one")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()
    lost_from = tailer.offset

    cowrie_log.write_bytes(b"")
    with caplog.at_level(logging.ERROR, logger="honeypot_agent.tailer"):
        tailer.poll()

    assert "truncated" in caplog.text
    assert "lost" in caplog.text
    assert str(lost_from) in caplog.text


def test_repeated_truncations_are_counted_separately(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append("one")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()

    for _ in range(3):
        cowrie_log.write_bytes(b"")
        tailer.poll()
        append("fresh")
        tailer.poll()

    assert tailer.truncations == 3


@requires_replace
def test_a_rotation_is_counted_as_a_rotation_not_a_truncation(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    """Rotation loses nothing, so it must not inflate the truncation count."""

    append("before")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()

    cowrie_log.rename(cowrie_log.with_name("cowrie.json.1"))
    cowrie_log.write_bytes(b"")
    append("after")

    tailer.poll()

    assert tailer.rotations == 1
    assert tailer.truncations == 0


@requires_replace
def test_a_rotation_is_logged_without_claiming_data_was_lost(
    cowrie_log: Path, append: Callable[..., int], caplog: pytest.LogCaptureFixture
) -> None:
    append("before")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()

    cowrie_log.rename(cowrie_log.with_name("cowrie.json.1"))
    cowrie_log.write_bytes(b"")
    append("after")

    with caplog.at_level(logging.WARNING, logger="honeypot_agent.tailer"):
        tailer.poll()

    assert "rotated" in caplog.text
    assert "lost" not in caplog.text


def test_a_truncation_missed_by_a_poll_is_not_detected(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    """Known limitation: truncation is detected by size, not by content.

    If the file is truncated and refilled past the previous offset between two
    polls, the size check does not fire and the tailer resumes mid-line. This    pins the real behaviour so it stays visible: rotate with rename (new inode)
    rather than ``copytruncate``, and note the backend rejects the resulting
    fragment because it carries no ``eventid``.
    """

    append("one")
    append("two")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()

    cowrie_log.write_bytes(b"")
    append("survived-rotation")

    records = tailer.poll()

    assert [r.text for r in records] == ["-rotation"]
    assert json.loads(records[0].text if records[0].text.startswith("{") else "{}") == {}


@requires_replace
def test_a_log_replaced_by_a_new_file_is_reopened(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    """What logrotate does: move the file aside and start a new one."""

    append("before-rotation")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()

    cowrie_log.rename(cowrie_log.with_name("cowrie.json.1"))
    cowrie_log.write_bytes(b"")
    append("after-rotation")

    records = tailer.poll()

    assert [r.text for r in records] == ["after-rotation"]


@requires_replace
def test_rotation_is_detected_by_a_changed_inode(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append("before")
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()
    original = tailer.inode

    replacement = cowrie_log.with_name("cowrie.json.new")
    replacement.write_bytes(b"after\n")
    os.replace(replacement, cowrie_log)

    records = tailer.poll()

    assert original != cowrie_log.stat().st_ino
    assert [r.text for r in records] == ["after"]


def test_the_tailer_reports_the_inode_it_is_reading(cowrie_log: Path) -> None:
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)
    tailer.poll()

    assert tailer.inode == cowrie_log.stat().st_ino
    assert tailer.path == cowrie_log


def test_undecodable_bytes_do_not_break_the_line(
    cowrie_log: Path, append: Callable[..., int]
) -> None:
    append(b'{"eventid": "cowrie.session.connect", "msg": "\xff\xfe"}')
    tailer = CowrieLogTailer(cowrie_log, start_at_end=False)

    records = tailer.poll()

    assert len(records) == 1
    assert "cowrie.session.connect" in records[0].text


def test_a_misconfigured_path_fails_instead_of_looking_empty(tmp_path: Path) -> None:
    """A directory where the log should be must not be mistaken for "no data"."""

    path = tmp_path / "cowrie.json"
    path.mkdir()

    tailer = CowrieLogTailer(path, start_at_end=False)

    with pytest.raises(OSError):
        tailer.poll()
