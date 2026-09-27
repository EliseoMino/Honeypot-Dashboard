"""Database engine, session factory and schema migrations (RF-03).

The schema is applied from plain SQL files in ``migrations/`` and recorded in
``schema_migrations``. Applied files are never re-run, and every file runs
inside a single transaction, so a partially applied migration is rolled back.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from honeypot_backend.config import Settings, get_settings
from honeypot_backend.db.models import Base

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
SCHEMA_TABLE = "schema_migrations"

_engines: dict[str, tuple[AsyncEngine, async_sessionmaker[AsyncSession]]] = {}


def get_engine(settings: Settings | None = None) -> AsyncEngine:
    """Return (and cache) the async engine for the configured database."""

    resolved = settings or get_settings()
    cached = _engines.get(resolved.database_url)
    if cached is None:
        engine = create_async_engine(
            resolved.database_url,
            echo=resolved.db_echo,
            pool_size=resolved.db_pool_size,
            max_overflow=resolved.db_max_overflow,
            pool_pre_ping=True,
        )
        cached = (engine, async_sessionmaker(engine, expire_on_commit=False))
        _engines[resolved.database_url] = cached
    return cached[0]


def get_sessionmaker(settings: Settings | None = None) -> async_sessionmaker[AsyncSession]:
    """Return the session factory bound to the configured database."""

    get_engine(settings)
    resolved = settings or get_settings()
    return _engines[resolved.database_url][1]


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a database session."""

    async with get_sessionmaker()() as session:
        yield session


@asynccontextmanager
async def session_scope(settings: Settings | None = None) -> AsyncIterator[AsyncSession]:
    """Async context manager yielding a session that commits on success."""

    async with get_sessionmaker(settings)() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engines() -> None:
    """Close every cached engine."""

    for engine, _ in _engines.values():
        await engine.dispose()
    _engines.clear()


async def apply_migrations(engine: AsyncEngine | None = None) -> list[str]:
    """Apply every pending migration file and return the applied versions."""

    target = engine or get_engine()
    applied: list[str] = []
    async with target.begin() as connection:
        await connection.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS {SCHEMA_TABLE} ("
                "version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
        )
        result = await connection.execute(text(f"SELECT version FROM {SCHEMA_TABLE}"))
        known = {row[0] for row in result}

        for script in sorted(MIGRATIONS_DIR.glob("*.sql")):
            version = script.stem
            if version in known:
                continue
            logger.info("applying migration %s", version)
            await connection.exec_driver_script(script.read_text(encoding="utf-8"))
            await connection.execute(
                text(f"INSERT INTO {SCHEMA_TABLE} (version) VALUES (:version)"),
                {"version": version},
            )
            applied.append(version)

    if applied:
        logger.info("migrations applied: %s", ", ".join(applied))
    return applied


async def create_all(engine: AsyncEngine | None = None) -> None:
    """Create the ORM tables directly. Used by the test suite."""

    target = engine or get_engine()
    async with target.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
