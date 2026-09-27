"""Shared fixtures for the backend test suite.

Tests that talk to PostgreSQL are skipped unless ``TEST_DATABASE_URL`` points
at a reachable database, so the suite is still useful without the local Docker
stack running. That database is treated as disposable: the fixtures drop the
RF-03 schema before and after every test that uses it.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from honeypot_backend.config import Settings
from honeypot_backend.db.session import apply_migrations, dispose_engines, get_engine
from honeypot_backend.normalization import normalize

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "").strip()
UNREACHABLE_URL = "postgresql+asyncpg://honeypot:honeypot@127.0.0.1:1/unused"

#: Receipt time shared by the fixtures, so stored timestamps are predictable.
RECEIVED_AT = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)

DROP_SCHEMA = "DROP TABLE IF EXISTS events, spool_cursors, schema_migrations CASCADE"


def pytest_report_header() -> str:
    """Tell the developer up front whether the database tests will run."""

    state = "configured" if TEST_DATABASE_URL else "not set (PostgreSQL tests are skipped)"
    return f"TEST_DATABASE_URL: {state}"


async def _is_reachable(url: str) -> bool:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False
    finally:
        await engine.dispose()
    return True


def build_cowrie_event(**overrides: Any) -> dict[str, Any]:
    """Return a raw Cowrie event, as the agent reads it from cowrie.json."""

    event: dict[str, Any] = {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-03-01T11:59:00.000000Z",
        "sensor": "honeypot-1",
        "session": "sess-1",
        "src_ip": "203.0.113.10",
        "src_port": 51234,
        "dst_ip": "198.51.100.5",
        "dst_port": 2222,
        "protocol": "ssh",
        "version": "SSH-2.0-OpenSSH_8.9p1",
        "message": "New connection",
    }
    event.update(overrides)
    return event


def build_record(**overrides: Any) -> dict[str, Any]:
    """Return a normalized event, as the replayer reads it from the spool."""

    return normalize(build_cowrie_event(**overrides), received_at=RECEIVED_AT).to_record()


@pytest.fixture
def cowrie_event():
    """Factory of raw Cowrie events."""

    return build_cowrie_event


@pytest.fixture
def record():
    """Factory of normalized events, the input of the storage layer."""

    return build_record


@pytest.fixture
async def database_url() -> AsyncIterator[str]:
    """The throwaway database used by the PostgreSQL tests."""

    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is not set, skipping test that needs PostgreSQL")
    if not await _is_reachable(TEST_DATABASE_URL):
        pytest.skip("TEST_DATABASE_URL is set but the database is not reachable")
    yield TEST_DATABASE_URL


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Backend settings isolated from the developer environment."""

    return Settings(
        database_url=TEST_DATABASE_URL or UNREACHABLE_URL,
        spool_dir=tmp_path / "spool",
        spool_fsync=False,
        spool_replay_enabled=False,
    )


@pytest.fixture
async def engine(database_url: str) -> AsyncIterator[AsyncEngine]:
    """An engine whose schema is created from the real migrations."""

    created = get_engine(Settings(database_url=database_url))
    try:
        async with created.begin() as connection:
            await connection.exec_driver_sql(DROP_SCHEMA)
        await apply_migrations(created)
        yield created
    finally:
        async with created.begin() as connection:
            await connection.exec_driver_sql(DROP_SCHEMA)
        await dispose_engines()


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """A session bound to a freshly migrated, empty database."""

    async with async_sessionmaker(engine, expire_on_commit=False)() as open_session:
        yield open_session
