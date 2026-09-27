"""Schema migrations of the stored events (RF-03)."""

from __future__ import annotations

import re

from sqlalchemy import text

from honeypot_backend.db.models import Base
from honeypot_backend.db.session import MIGRATIONS_DIR, apply_migrations, split_statements

EVENTS_MIGRATION = "0001_events.sql"
EVENTS_VERSION = EVENTS_MIGRATION.removesuffix(".sql")

#: Indexes RF-03 requires on the stored events.
REQUIRED_INDEXES = {
    "ix_events_occurred_at": "(occurred_at)",
    "ix_events_source_ip": "(source_ip)",
    "ix_events_event_type": "(event_type)",
    "ix_events_session_id": "(session_id)",
}


def _flat(name: str) -> str:
    return " ".join((MIGRATIONS_DIR / name).read_text(encoding="utf-8").lower().split())


def test_split_statements_ignores_comments_and_quoted_text() -> None:
    script = """
    -- a comment; with a semicolon
    CREATE TABLE a (id int, name text DEFAULT 'x;y');
    /* a block; comment
       spanning /* nested */ lines */
    INSERT INTO "odd;name" VALUES (1);
    CREATE FUNCTION f() RETURNS int AS $$ BEGIN RETURN 1; END; $$ LANGUAGE plpgsql;
    """

    assert split_statements(script) == [
        "CREATE TABLE a (id int, name text DEFAULT 'x;y')",
        'INSERT INTO "odd;name" VALUES (1)',
        "CREATE FUNCTION f() RETURNS int AS $$ BEGIN RETURN 1; END; $$ LANGUAGE plpgsql",
    ]


def test_split_statements_does_not_return_a_trailing_comment() -> None:
    assert split_statements("SELECT 1;\n-- nothing else here\n") == ["SELECT 1"]
    assert split_statements("") == []
    assert split_statements(";;;") == []


def test_every_migration_splits_into_executable_statements() -> None:
    for script in sorted(MIGRATIONS_DIR.glob("*.sql")):
        statements = split_statements(script.read_text(encoding="utf-8"))
        assert statements, f"{script.name} produced no statement"
        for statement in statements:
            assert split_statements(statement) == [statement]


def test_events_migration_declares_the_indexes_required_by_rf03() -> None:
    flat = _flat(EVENTS_MIGRATION)

    for index, columns in REQUIRED_INDEXES.items():
        assert f"create index if not exists {index} on events {columns}" in flat


def test_events_migration_uses_jsonb_for_the_variable_attributes() -> None:
    flat = _flat(EVENTS_MIGRATION)

    assert "details jsonb not null" in flat
    assert "raw jsonb not null" in flat
    assert "source_ip inet" in flat
    assert "occurred_at timestamptz not null" in flat
    assert "session_id varchar(128)" in flat


def test_events_migration_deduplicates_by_event_id() -> None:
    assert "constraint uq_events_event_id unique (event_id)" in _flat(EVENTS_MIGRATION)


def test_orm_indexes_match_the_migration() -> None:
    created = set(re.findall(r"create index if not exists (\w+)", _flat(EVENTS_MIGRATION)))
    declared = {index.name for table in Base.metadata.tables.values() for index in table.indexes}

    assert declared == created


async def test_migrations_are_recorded_and_never_reapplied(engine) -> None:
    assert await apply_migrations(engine) == []

    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT version FROM schema_migrations"))
        applied = {row[0] for row in result}

    assert EVENTS_VERSION in applied
