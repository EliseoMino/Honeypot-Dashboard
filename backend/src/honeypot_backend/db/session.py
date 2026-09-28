"""Database engine, session factory and schema migrations (RF-03).

The schema is applied from plain SQL files in ``migrations/`` and recorded in
``schema_migrations``. Applied files are never re-run, and every file runs
inside a single transaction, so a partially applied migration is rolled back.

Migrations are applied one statement at a time because asyncpg prepares every
statement it receives and rejects more than one command per prepared
statement, which rules out sending a whole script at once.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Request
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


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session for the running app's database.

    The settings are read from the application state instead of the process
    environment, so the endpoints always use the database the app was built
    with.
    """

    async with get_sessionmaker(request.app.state.settings)() as session:
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


def split_statements(script: str) -> list[str]:
    """Split a SQL script into the individual statements it contains.

    Line comments, block comments (which nest in PostgreSQL), quoted
    identifiers, string literals and dollar quoted bodies are skipped, so a
    semicolon inside any of them is not mistaken for a statement separator.
    Comments are replaced by whitespace, which keeps a comment that trails the
    last statement from being returned as a statement of its own.
    """

    statements: list[str] = []
    current: list[str] = []
    index = 0
    length = len(script)

    def keep(char: str) -> None:
        if char.strip():
            current.append(char)
        elif current:
            current.append(char)

    while index < length:
        char = script[index]
        pair = script[index : index + 2]

        if pair == "--":
            end = script.find("\n", index)
            index = length if end == -1 else end + 1
            keep("\n")
            continue

        if pair == "/*":
            depth = 1
            index += 2
            while index < length and depth:
                if script[index : index + 2] == "/*":
                    depth += 1
                    index += 2
                elif script[index : index + 2] == "*/":
                    depth -= 1
                    index += 2
                else:
                    index += 1
            keep(" ")
            continue

        if char in {"'", '"'}:
            end = _end_of_quoted(script, index, char)
            current.append(script[index:end])
            index = end
            continue

        if char == "$":
            tag = _dollar_quote_tag(script, index)
            if tag is not None:
                end = script.find(tag, index + len(tag))
                end = length if end == -1 else end + len(tag)
                current.append(script[index:end])
                index = end
                continue

        if char == ";":
            statements.append("".join(current))
            current = []
            index += 1
            continue

        keep(char)
        index += 1

    statements.append("".join(current))
    return [statement.strip() for statement in statements if statement.strip()]


def _end_of_quoted(script: str, start: int, quote: str) -> int:
    """Return the index just past the quoted run that starts at ``start``."""

    index = start + 1
    length = len(script)
    while index < length:
        if script[index] != quote:
            index += 1
            continue
        if index + 1 < length and script[index + 1] == quote:
            index += 2
            continue
        return index + 1
    return length


def _dollar_quote_tag(script: str, start: int) -> str | None:
    """Return the ``$tag$`` delimiter at ``start``, if there is one."""

    index = start + 1
    while index < len(script):
        char = script[index]
        if char == "$":
            return script[start : index + 1]
        if char == "_" or char.isalpha() or (char.isdigit() and index > start + 1):
            index += 1
            continue
        return None
    return None


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
            for statement in split_statements(script.read_text(encoding="utf-8")):
                await connection.exec_driver_sql(statement)
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
