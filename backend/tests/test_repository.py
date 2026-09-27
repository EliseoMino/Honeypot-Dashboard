"""Storage, filtering, ordering and aggregation of events (RF-03)."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.dialects import postgresql

from honeypot_backend.db.repository import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    EventFilters,
    EventRepository,
    clamp_limit,
)


def _sql(statement: Any, *, literal_binds: bool = True) -> str:
    """Render a statement for PostgreSQL, inlining the bound values."""

    dialect = postgresql.dialect(paramstyle="format")
    return str(
        statement.compile(
            dialect=dialect,
            compile_kwargs={"literal_binds": literal_binds} if literal_binds else {},
        )
    )


def _count(entries: list[dict[str, Any]], key: str) -> int:
    return sum(entry["count"] for entry in entries if entry["key"] == key)


def test_clamp_limit_keeps_the_page_size_within_bounds() -> None:
    assert clamp_limit(0) == 1
    assert clamp_limit(-5) == 1
    assert clamp_limit(DEFAULT_LIMIT) == DEFAULT_LIMIT
    assert clamp_limit(MAX_LIMIT) == MAX_LIMIT
    assert clamp_limit(MAX_LIMIT + 100) == MAX_LIMIT


def test_insert_statement_ignores_conflicting_event_ids(record) -> None:
    sql = _sql(EventRepository.insert_statement([record()]), literal_binds=False).lower()

    assert "insert into events" in sql
    assert "on conflict (event_id) do nothing" in sql
    assert "%s::jsonb" in sql


def test_page_statement_orders_by_time_and_pages() -> None:
    descending = _sql(EventRepository.page_statement(EventFilters(), limit=10, offset=20, order="desc"))
    ascending = _sql(EventRepository.page_statement(EventFilters(), limit=10, offset=20, order="asc"))

    assert "ORDER BY events.occurred_at DESC" in descending
    assert "ORDER BY events.occurred_at ASC" in ascending
    assert "LIMIT 10" in descending
    assert "OFFSET 20" in descending


def test_filters_render_the_expected_conditions() -> None:
    moment = datetime(2026, 3, 1, tzinfo=UTC)
    sql = _sql(
        EventRepository.count_statement(
            EventFilters(
                session_id="sess-1",
                username="root",
                event_types=("auth.login_failed", "command.success"),
                event_category="authentication",
                outcome="failure",
                occurred_from=moment,
                occurred_to=moment,
                search="wget",
            )
        )
    ).lower()

    assert "events.session_id = 'sess-1'" in sql
    assert "events.username = 'root'" in sql
    assert "events.event_type in ('auth.login_failed', 'command.success')" in sql
    assert "events.event_category = 'authentication'" in sql
    assert "events.outcome = 'failure'" in sql
    assert "events.occurred_at >=" in sql
    assert "events.occurred_at <=" in sql
    assert "host(events.source_ip) ilike" in sql
    assert "cast(events.details as varchar) ilike" in sql


def test_the_ip_filter_compares_the_inet_column() -> None:
    statement = EventRepository.count_statement(EventFilters(source_ip="203.0.113.10"))

    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled).lower()

    # A text cast never matches, because PostgreSQL renders an INET with its
    # mask ("203.0.113.10/32").
    assert "events.source_ip = " in sql
    assert "cast(events.source_ip as varchar)" not in sql
    assert list(compiled.params.values()) == [ipaddress.ip_address("203.0.113.10")]


def test_an_unparsable_ip_filter_is_ignored() -> None:
    assert EventFilters(source_ip="not-an-ip").conditions() == []


def test_the_free_text_search_is_bound_as_a_pattern() -> None:
    statement = EventRepository.count_statement(EventFilters(search="wget"))

    compiled = statement.compile(dialect=postgresql.dialect())

    assert any(value == "%wget%" for value in compiled.params.values())


def test_an_empty_filter_matches_everything() -> None:
    assert EventFilters().conditions() == []
    assert " where " not in _sql(EventRepository.count_statement(EventFilters())).lower()


async def test_inserted_events_keep_their_common_attributes(session, record) -> None:
    repository = EventRepository(session)
    original = record(eventid="cowrie.login.failed", username="root", password="admin")

    assert await repository.insert_events([original]) == 1
    await session.commit()

    stored = await repository.get_event(original["event_id"])
    assert stored is not None
    assert stored["source"] == "cowrie"
    assert stored["source_event_id"] == "cowrie.login.failed"
    assert stored["event_type"] == "auth.login_failed"
    assert stored["event_category"] == "authentication"
    assert stored["occurred_at"] == "2026-03-01T11:59:00+00:00"
    assert stored["source_ip"] == "203.0.113.10"
    assert stored["session_id"] == "sess-1"
    assert stored["username"] == "root"
    assert stored["outcome"] == "failure"
    assert stored["details"]["password"] == "admin"
    assert stored["raw"]["eventid"] == "cowrie.login.failed"


async def test_a_stored_event_is_returned_unchanged(session, record) -> None:
    repository = EventRepository(session)
    original = record(
        eventid="cowrie.session.file_download",
        url="http://example.com/x.sh",
        username="root",
    )
    await repository.insert_events([original])
    await session.commit()

    stored = await repository.get_event(original["event_id"])

    assert stored is not None
    assert stored["event_type"] == "transfer.download"
    assert stored["details"]["url"] == "http://example.com/x.sh"


async def test_unknown_events_are_not_found(session) -> None:
    assert await EventRepository(session).get_event("does-not-exist") is None


async def test_the_same_event_is_never_stored_twice(session, record) -> None:
    repository = EventRepository(session)
    original = record()

    assert await repository.insert_events([original]) == 1
    assert await repository.insert_events([original]) == 0
    await session.commit()

    assert (await repository.list_events(EventFilters())).total == 1


async def test_an_empty_batch_is_a_no_op(session) -> None:
    assert await EventRepository(session).insert_events([]) == 0


async def test_events_are_filtered_by_type_session_ip_and_username(session, record) -> None:
    repository = EventRepository(session)
    await repository.insert_events(
        [
            record(eventid="cowrie.session.connect", session="sess-1", src_ip="203.0.113.10"),
            record(
                eventid="cowrie.login.failed",
                session="sess-1",
                src_ip="203.0.113.10",
                username="root",
            ),
            record(
                eventid="cowrie.command.success",
                session="sess-2",
                src_ip="198.51.100.9",
                input="uname -a",
            ),
        ]
    )
    await session.commit()

    assert (await repository.list_events(EventFilters(event_types=("auth.login_failed",)))).total == 1
    assert (await repository.list_events(EventFilters(session_id="sess-1"))).total == 2
    assert (await repository.list_events(EventFilters(source_ip="198.51.100.9"))).total == 1
    assert (await repository.list_events(EventFilters(username="root"))).total == 1
    assert (await repository.list_events(EventFilters(event_category="command"))).total == 1
    assert (await repository.list_events(EventFilters(outcome="failure"))).total == 1
    assert (await repository.list_events(EventFilters(search="uname"))).total == 1
    assert (await repository.list_events(EventFilters(search="nothing-here"))).total == 0


async def test_events_are_filtered_by_time_window(session, record) -> None:
    repository = EventRepository(session)
    await repository.insert_events(
        [
            record(timestamp="2026-03-01T10:00:00.000000Z"),
            record(timestamp="2026-03-02T10:00:00.000000Z"),
        ]
    )
    await session.commit()

    inside = EventFilters(
        occurred_from=datetime(2026, 3, 1, 12, 0, tzinfo=UTC),
        occurred_to=datetime(2026, 3, 2, 12, 0, tzinfo=UTC),
    )
    after = EventFilters(occurred_from=datetime(2026, 3, 3, tzinfo=UTC))

    assert (await repository.list_events(inside)).total == 1
    assert (await repository.list_events(after)).total == 0


async def test_events_are_ordered_by_time(session, record) -> None:
    repository = EventRepository(session)
    await repository.insert_events(
        [
            record(timestamp="2026-03-02T10:00:00.000000Z"),
            record(timestamp="2026-03-01T10:00:00.000000Z"),
            record(timestamp="2026-03-03T10:00:00.000000Z"),
        ]
    )
    await session.commit()

    newest_first = await repository.list_events(EventFilters(), order="desc")
    oldest_first = await repository.list_events(EventFilters(), order="asc")

    assert [item["occurred_at"] for item in newest_first.items] == [
        "2026-03-03T10:00:00+00:00",
        "2026-03-02T10:00:00+00:00",
        "2026-03-01T10:00:00+00:00",
    ]
    assert [item["occurred_at"] for item in oldest_first.items] == [
        "2026-03-01T10:00:00+00:00",
        "2026-03-02T10:00:00+00:00",
        "2026-03-03T10:00:00+00:00",
    ]


async def test_a_page_reports_the_total_of_the_whole_filtered_set(session, record) -> None:
    repository = EventRepository(session)
    await repository.insert_events(
        [record(timestamp=f"2026-03-0{day + 1}T10:00:00.000000Z") for day in range(5)]
    )
    await session.commit()

    page = await repository.list_events(EventFilters(), limit=2, offset=2, order="asc")

    assert page.total == 5
    assert page.limit == 2
    assert page.offset == 2
    assert [item["occurred_at"] for item in page.items] == [
        "2026-03-03T10:00:00+00:00",
        "2026-03-04T10:00:00+00:00",
    ]


async def test_summary_aggregates_the_stored_events(session, record) -> None:
    repository = EventRepository(session)
    await repository.insert_events(
        [
            record(session="sess-1", src_ip="203.0.113.10"),
            record(
                eventid="cowrie.login.failed",
                session="sess-1",
                src_ip="203.0.113.10",
                username="root",
            ),
            record(
                eventid="cowrie.command.success",
                session="sess-2",
                src_ip="198.51.100.9",
                username="admin",
                input="uname -a",
                timestamp="2026-03-05T10:00:00.000000Z",
            ),
        ]
    )
    await session.commit()

    summary = await repository.summary(EventFilters())

    assert summary["total_events"] == 3
    assert summary["unique_source_ips"] == 2
    assert summary["unique_sessions"] == 2
    assert summary["unique_usernames"] == 2
    assert summary["first_event_at"] == "2026-03-01T11:59:00+00:00"
    assert summary["last_event_at"] == "2026-03-05T10:00:00+00:00"
    assert _count(summary["by_category"], "session") == 1
    assert _count(summary["by_category"], "authentication") == 1
    assert _count(summary["by_category"], "command") == 1
    assert _count(summary["by_outcome"], "failure") == 1
    assert _count(summary["by_outcome"], "success") == 1
    assert _count(summary["by_protocol"], "ssh") == 3
    assert _count(summary["top_event_types"], "command.success") == 1


async def test_summary_of_an_empty_database(session) -> None:
    summary = await EventRepository(session).summary(EventFilters())

    assert summary["total_events"] == 0
    assert summary["unique_source_ips"] == 0
    assert summary["unique_sessions"] == 0
    assert summary["first_event_at"] is None
    assert summary["last_event_at"] is None
    assert summary["by_category"] == []


async def test_summary_respects_the_filters(session, record) -> None:
    repository = EventRepository(session)
    await repository.insert_events(
        [
            record(session="sess-1", src_ip="203.0.113.10"),
            record(session="sess-2", src_ip="198.51.100.9"),
        ]
    )
    await session.commit()

    summary = await repository.summary(EventFilters(source_ip="198.51.100.9"))

    assert summary["total_events"] == 1
    assert summary["unique_sessions"] == 1


async def test_the_spool_cursor_is_remembered(session) -> None:
    repository = EventRepository(session)

    assert await repository.get_cursor("/spool/event-20260301.jsonl") == 0

    await repository.set_cursor("/spool/event-20260301.jsonl", 4096)
    await session.commit()
    assert await repository.get_cursor("/spool/event-20260301.jsonl") == 4096

    await repository.set_cursor("/spool/event-20260301.jsonl", 8192)
    await session.commit()
    assert await repository.get_cursor("/spool/event-20260301.jsonl") == 8192
