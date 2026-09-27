"""Queries over the stored events (RF-03).

The repository is the only place that talks to the ``events`` table. Inserts
are idempotent thanks to the unique ``event_id``, so replaying a batch after a
crash never duplicates an event.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Select, String, cast, distinct, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.db.models import Event, SpoolCursor
from honeypot_backend.normalization.events import NormalizedEvent

MAX_LIMIT = 500
DEFAULT_LIMIT = 50

_EVENT_COLUMNS = (
    "event_id",
    "source",
    "source_event_id",
    "event_type",
    "event_category",
    "occurred_at",
    "received_at",
    "sensor",
    "session_id",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "username",
    "outcome",
    "details",
    "raw",
)


@dataclass(frozen=True, slots=True)
class EventFilters:
    """Filters accepted by the event query endpoints."""

    source_ip: str | None = None
    session_id: str | None = None
    username: str | None = None
    event_types: tuple[str, ...] = field(default_factory=tuple)
    event_category: str | None = None
    outcome: str | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None
    search: str | None = None

    def conditions(self) -> list[Any]:
        clauses: list[Any] = []
        if self.source_ip:
            clauses.append(cast(Event.source_ip, String) == self.source_ip)
        if self.session_id:
            clauses.append(Event.session_id == self.session_id)
        if self.username:
            clauses.append(Event.username == self.username)
        if self.event_types:
            clauses.append(Event.event_type.in_(self.event_types))
        if self.event_category:
            clauses.append(Event.event_category == self.event_category)
        if self.outcome:
            clauses.append(Event.outcome == self.outcome)
        if self.occurred_from:
            clauses.append(Event.occurred_at >= self.occurred_from)
        if self.occurred_to:
            clauses.append(Event.occurred_at <= self.occurred_to)
        if self.search:
            pattern = f"%{self.search.strip()}%"
            clauses.append(
                or_(
                    Event.username.ilike(pattern),
                    Event.session_id.ilike(pattern),
                    Event.event_type.ilike(pattern),
                    cast(Event.source_ip, String).ilike(pattern),
                    cast(Event.details, String).ilike(pattern),
                )
            )
        return clauses


@dataclass(frozen=True, slots=True)
class EventPage:
    """A page of stored events."""

    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


def _to_row(record: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a normalized event mapping into a database row."""

    return {
        "event_id": record["event_id"],
        "source": record["source"],
        "source_event_id": record["source_event_id"],
        "event_type": record["event_type"],
        "event_category": record["event_category"],
        "occurred_at": _as_datetime(record["occurred_at"]),
        "received_at": _as_datetime(record["received_at"]),
        "sensor": record.get("sensor"),
        "session_id": record.get("session_id"),
        "source_ip": _as_ip(record.get("source_ip")),
        "source_port": record.get("source_port"),
        "destination_ip": _as_ip(record.get("destination_ip")),
        "destination_port": record.get("destination_port"),
        "protocol": record.get("protocol"),
        "username": record.get("username"),
        "outcome": record.get("outcome"),
        "details": record.get("details") or {},
        "raw": record.get("raw") or {},
    }


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def _as_ip(value: Any) -> Any:
    if value is None:
        return None
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


class EventRepository:
    """Read and write access to the stored events."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def insert_events(self, records: Sequence[Mapping[str, Any]]) -> int:
        """Insert normalized events, ignoring the ones already stored."""

        rows = [_to_row(record) for record in records]
        if not rows:
            return 0
        statement = pg_insert(Event.__table__).values(rows)
        statement = statement.on_conflict_do_nothing(index_elements=["event_id"])
        result = await self._session.execute(statement)
        await self._session.flush()
        return result.rowcount or 0

    async def insert_normalized(self, events: Sequence[NormalizedEvent]) -> int:
        return await self.insert_events([event.to_record() for event in events])

    async def list_events(
        self,
        filters: EventFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        order: str = "desc",
    ) -> EventPage:
        """Return a filtered, ordered page of events plus the total count."""

        limit = max(1, min(limit, MAX_LIMIT))
        offset = max(0, offset)
        ordering = Event.occurred_at.asc() if order == "asc" else Event.occurred_at.desc()
        conditions = filters.conditions()

        total = await self._session.scalar(
            select(func.count()).select_from(Event).where(*conditions)
        )
        statement: Select[Any] = (
            select(Event).where(*conditions).order_by(ordering, Event.id.desc()).limit(limit).offset(offset)
        )
        rows = (await self._session.execute(statement)).scalars().all()
        return EventPage(
            items=[row.to_dict() for row in rows],
            total=int(total or 0),
            limit=limit,
            offset=offset,
        )

    async def get_event(self, event_id: str) -> dict[str, Any] | None:
        row = await self._session.get(Event, event_id, primary_key=Event.event_id)
        return row.to_dict() if row is not None else None

    async def summary(self, filters: EventFilters) -> dict[str, Any]:
        """Aggregate counters for the filtered set of events."""

        conditions = filters.conditions()
        totals = await self._session.execute(
            select(
                func.count(),
                func.count(distinct(Event.source_ip)),
                func.count(distinct(Event.session_id)),
                func.count(distinct(Event.username)),
                func.min(Event.occurred_at),
                func.max(Event.occurred_at),
            ).where(*conditions)
        )
        row = totals.one()
        by_category = await self._group_count(Event.event_category, conditions)
        by_outcome = await self._group_count(Event.outcome, conditions)
        top_types = await self._group_count(Event.event_type, conditions, limit=10)
        by_protocol = await self._group_count(Event.protocol, conditions)

        return {
            "total_events": int(row[0] or 0),
            "unique_source_ips": int(row[1] or 0),
            "unique_sessions": int(row[2] or 0),
            "unique_usernames": int(row[3] or 0),
            "first_event_at": row[4].isoformat() if row[4] else None,
            "last_event_at": row[5].isoformat() if row[5] else None,
            "by_category": by_category,
            "by_outcome": by_outcome,
            "by_protocol": by_protocol,
            "top_event_types": top_types,
        }

    async def _group_count(
        self,
        column: Any,
        conditions: Sequence[Any],
        *,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        statement = select(column.label("key"), func.count().label("count")).where(*conditions)
        statement = statement.group_by(column).order_by(func.count().desc())
        if limit is not None:
            statement = statement.limit(limit)
        rows = (await self._session.execute(statement)).all()
        return [{"key": row[0], "count": int(row[1])} for row in rows]

    async def get_cursor(self, path: str) -> int:
        offset = await self._session.scalar(select(SpoolCursor.offset).where(SpoolCursor.path == path))
        return int(offset or 0)

    async def set_cursor(self, path: str, offset: int) -> None:
        statement = (
            pg_insert(SpoolCursor.__table__)
            .values(path=path, offset=offset)
            .on_conflict_do_update(index_elements=["path"], set_={"offset": offset})
        )
        await self._session.execute(statement)
        await self._session.flush()
