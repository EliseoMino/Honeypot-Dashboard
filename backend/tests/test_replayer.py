"""Loading the normalized spool into PostgreSQL (RF-03)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from honeypot_backend.db.repository import EventFilters, EventRepository
from honeypot_backend.db.session import dispose_engines
from honeypot_backend.ingest.replayer import NormalizedSpoolReplayer, _read_batch


def _write(path: Path, records: list[dict]) -> None:
    """Append JSON Lines the way the spool does, in binary mode."""

    with open(path, "ab") as handle:
        for item in records:
            handle.write(json.dumps(item).encode("utf-8") + b"\n")


def _line(record: dict) -> bytes:
    return json.dumps(record).encode("utf-8") + b"\n"


def test_read_batch_stops_at_the_first_incomplete_line(tmp_path: Path) -> None:
    path = tmp_path / "event-20260301.jsonl"
    first, second = {"n": 1}, {"n": 2}
    path.write_bytes(_line(first) + _line(second) + b'{"n": 3, "part')

    records, consumed, malformed = _read_batch(path, 0, 10)

    assert records == [first, second]
    assert malformed == 0
    assert consumed == len(_line(first)) + len(_line(second))


def test_read_batch_resumes_from_the_given_offset(tmp_path: Path) -> None:
    path = tmp_path / "event-20260301.jsonl"
    _write(path, [{"n": 1}, {"n": 2}, {"n": 3}])
    offset = len(_line({"n": 1}))

    records, consumed, _ = _read_batch(path, offset, 10)

    assert records == [{"n": 2}, {"n": 3}]
    assert consumed == len(_line({"n": 2})) + len(_line({"n": 3}))


def test_read_batch_honours_the_limit(tmp_path: Path) -> None:
    path = tmp_path / "event-20260301.jsonl"
    _write(path, [{"n": 1}, {"n": 2}, {"n": 3}])

    records, _, _ = _read_batch(path, 0, 2)

    assert records == [{"n": 1}, {"n": 2}]


def test_read_batch_skips_unparsable_lines(tmp_path: Path) -> None:
    path = tmp_path / "event-20260301.jsonl"
    path.write_bytes(_line({"n": 1}) + b"not json\n" + b"\n" + b"[1, 2]\n" + _line({"n": 2}))

    records, consumed, malformed = _read_batch(path, 0, 10)

    assert records == [{"n": 1}, {"n": 2}]
    assert malformed == 2
    assert consumed == path.stat().st_size


def test_an_empty_file_consumes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "event-20260301.jsonl"
    path.touch()

    assert _read_batch(path, 0, 10) == ([], 0, 0)


async def test_a_missing_spool_directory_is_not_an_error(tmp_path, settings, session) -> None:
    replayer = NormalizedSpoolReplayer(settings, tmp_path / "does-not-exist")

    assert await replayer.run_once() == 0


async def test_the_spool_is_loaded_and_the_cursor_is_remembered(tmp_path, settings, session, record) -> None:
    spool = tmp_path / "normalized"
    spool.mkdir()
    _write(
        spool / "event-20260301.jsonl",
        [record(), record(eventid="cowrie.login.failed", username="root")],
    )
    replayer = NormalizedSpoolReplayer(settings, spool)

    assert await replayer.run_once() == 2

    repository = EventRepository(session)
    assert (await repository.list_events(EventFilters())).total == 2
    assert await repository.get_cursor(str(spool / "event-20260301.jsonl")) > 0
    assert replayer.stats()["events_loaded"] == 2
    assert replayer.stats()["batches_loaded"] == 1


async def test_a_second_pass_stores_nothing_new(tmp_path, settings, session, record) -> None:
    spool = tmp_path / "normalized"
    spool.mkdir()
    _write(spool / "event-20260301.jsonl", [record()])
    replayer = NormalizedSpoolReplayer(settings, spool)

    assert await replayer.run_once() == 1
    assert await replayer.run_once() == 0

    assert (await EventRepository(session).list_events(EventFilters())).total == 1


async def test_appended_events_are_loaded_by_the_next_pass(tmp_path, settings, session, record) -> None:
    spool = tmp_path / "normalized"
    spool.mkdir()
    path = spool / "event-20260301.jsonl"
    _write(path, [record()])
    replayer = NormalizedSpoolReplayer(settings, spool)
    assert await replayer.run_once() == 1

    _write(path, [record(eventid="cowrie.command.success", input="uname -a")])
    assert await replayer.run_once() == 1

    assert (await EventRepository(session).list_events(EventFilters())).total == 2


async def test_every_spool_file_is_drained(tmp_path, settings, session, record) -> None:
    spool = tmp_path / "normalized"
    spool.mkdir()
    _write(spool / "event-20260301.jsonl", [record()])
    _write(spool / "event-20260302.jsonl", [record(eventid="cowrie.login.failed")])
    replayer = NormalizedSpoolReplayer(settings, spool)

    assert await replayer.run_once() == 2
    assert (await EventRepository(session).list_events(EventFilters())).total == 2


async def test_malformed_spool_lines_do_not_stop_the_loading(tmp_path, settings, session, record) -> None:
    spool = tmp_path / "normalized"
    spool.mkdir()
    path = spool / "event-20260301.jsonl"
    _write(path, [record()])
    with open(path, "ab") as handle:
        handle.write(b"not json\n")
    _write(path, [record(eventid="cowrie.login.failed")])
    replayer = NormalizedSpoolReplayer(settings, spool)

    assert await replayer.run_once() == 2
    assert replayer.stats()["malformed_lines"] == 1
    assert (await EventRepository(session).list_events(EventFilters())).total == 2


async def test_a_truncated_spool_file_is_read_again(tmp_path, settings, session, record) -> None:
    spool = tmp_path / "normalized"
    spool.mkdir()
    path = spool / "event-20260301.jsonl"
    _write(path, [record(), record(eventid="cowrie.command.success", input="uname -a")])
    replayer = NormalizedSpoolReplayer(settings, spool)
    assert await replayer.run_once() == 2

    # A shorter file under the same name is a rotated file, so it is read from
    # the beginning again. The event it repeats is not stored twice.
    path.write_bytes(_line(record(eventid="cowrie.login.failed")))
    assert await replayer.run_once() == 1

    assert (await EventRepository(session).list_events(EventFilters())).total == 3


async def test_an_unreachable_database_keeps_the_events_in_the_spool(tmp_path, settings, record) -> None:
    spool = tmp_path / "normalized"
    spool.mkdir()
    path = spool / "event-20260301.jsonl"
    _write(path, [record()])
    unreachable = settings.model_copy(
        update={
            "database_url": "postgresql+asyncpg://honeypot:honeypot@127.0.0.1:1/none",
            "spool_replay_error_backoff": 0.01,
        }
    )
    replayer = NormalizedSpoolReplayer(unreachable, spool)

    try:
        with pytest.raises(OSError):
            await replayer.run_once()

        task = asyncio.create_task(replayer.run())
        await asyncio.sleep(0.2)
        replayer.request_stop()
        await asyncio.wait_for(task, timeout=5)

        assert replayer.stats()["events_loaded"] == 0
        assert replayer.stats()["failures"] >= 1
        assert path.read_bytes() == _line(record())
    finally:
        await dispose_engines()
