"""Queries over the stored events and detections (RF-03, RF-11).

This module is the only place that talks to the ``events`` and ``detections``
tables. Inserts are idempotent: events ignore a duplicate ``event_id`` and
detections ignore a duplicate ``fingerprint``, so replaying a batch or
re-evaluating a rule never records the same thing twice.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Select, String, case, cast, distinct, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.db.models import Alert, Detection, Event, SpoolCursor
from honeypot_backend.normalization.events import NormalizedEvent

MAX_LIMIT = 500
DEFAULT_LIMIT = 50

#: Time bucket widths RF-05 accepts. Passed to date_trunc as a bind parameter,
#: so nothing from the request reaches the SQL text.
BUCKETS = ("minute", "hour", "day")

#: Ranks the severity levels of RF-12 so alerts can be ordered by seriousness.
_SEVERITY_RANK = case(
    {"low": 0, "medium": 1, "high": 2, "critical": 3},
    value=Alert.severity,
    else_=0,
)
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
        address = _as_ip(self.source_ip)
        if address is not None:
            # Compared as INET, not as text: PostgreSQL renders an INET with its
            # mask ("198.51.100.9/32"), so a text comparison never matches.
            clauses.append(Event.source_ip == address)
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
                    func.host(Event.source_ip).ilike(pattern),
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


def _as_str_list(value: Any) -> list[str]:
    """Normalize a PostgreSQL text array into a plain sorted list.

    ``array_agg`` returns a list, but it is ``None`` when the filter removed
    every element, so the aggregate always yields a list for the API.
    """

    if value is None:
        return []
    return sorted({str(item) for item in value})


def clamp_limit(limit: int) -> int:
    """Keep a requested page size inside the allowed range."""

    return max(1, min(limit, MAX_LIMIT))


def clamp_offset(offset: int) -> int:
    """Keep a requested offset non negative."""

    return max(0, offset)


class EventRepository:
    """Read and write access to the stored events."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def insert_statement(records: Sequence[Mapping[str, Any]]) -> Any:
        """Build the idempotent insert for a batch of normalized events."""

        return (
            pg_insert(Event.__table__)
            .values([_to_row(record) for record in records])
            .on_conflict_do_nothing(index_elements=["event_id"])
        )

    @staticmethod
    def count_statement(filters: EventFilters) -> Select[Any]:
        """Build the statement that counts the events matching ``filters``."""

        return select(func.count()).select_from(Event).where(*filters.conditions())

    @staticmethod
    def page_statement(
        filters: EventFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        order: str = "desc",
    ) -> Select[Any]:
        """Build the statement that returns one ordered page of events."""

        ordering = Event.occurred_at.asc() if order == "asc" else Event.occurred_at.desc()
        return (
            select(Event)
            .where(*filters.conditions())
            .order_by(ordering, Event.id.desc())
            .limit(limit)
            .offset(offset)
        )

    async def insert_events(self, records: Sequence[Mapping[str, Any]]) -> int:
        """Insert normalized events, ignoring the ones already stored."""

        if not records:
            return 0
        result = await self._session.execute(self.insert_statement(records))
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

        total = await self._session.scalar(self.count_statement(filters))
        statement = self.page_statement(
            filters,
            limit=clamp_limit(limit),
            offset=clamp_offset(offset),
            order=order,
        )
        rows = (await self._session.execute(statement)).scalars().all()
        return EventPage(
            items=[row.to_dict() for row in rows],
            total=int(total or 0),
            limit=clamp_limit(limit),
            offset=clamp_offset(offset),
        )

    async def get_event(self, event_id: str) -> dict[str, Any] | None:
        row = await self._session.scalar(select(Event).where(Event.event_id == event_id))
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
                func.count().filter(Event.event_category == "authentication"),
                func.count().filter(Event.event_category == "command"),
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
            "auth_attempts": int(row[6] or 0),
            "commands": int(row[7] or 0),
            "by_category": by_category,
            "by_outcome": by_outcome,
            "by_protocol": by_protocol,
            "top_event_types": top_types,
        }

    async def timeseries(
        self,
        filters: EventFilters,
        *,
        bucket: str = "hour",
    ) -> dict[str, Any]:
        """Count the filtered events per time bucket, oldest bucket first.

        RF-05 asks for the evolution of the events over time, so this is the
        same grouped read as the rest of the API, bucketed by the event time.
        Buckets with no events are kept as zero rows: a gap in the series is
        information, because it is what a lull in the attacks looks like.
        """

        if bucket not in BUCKETS:
            raise ValueError(f"unsupported bucket: {bucket}")

        conditions = filters.conditions()
        truncated = func.date_trunc(bucket, Event.occurred_at)
        rows = (
            await self._session.execute(
                select(
                    truncated.label("bucket"),
                    func.count().label("count"),
                    func.count().filter(Event.event_category == "authentication").label("auth"),
                    func.count().filter(Event.event_category == "command").label("commands"),
                )
                .where(*conditions)
                .group_by(truncated)
                .order_by(truncated)
            )
        ).all()

        return {
            "bucket": bucket,
            "points": [
                {
                    "bucket": row.bucket.isoformat(),
                    "count": int(row.count or 0),
                    "auth": int(row.auth or 0),
                    "commands": int(row.commands or 0),
                }
                for row in rows
            ],
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

    async def count_filtered(self, filters: EventFilters) -> int:
        """Count the events matching a filter, ignoring pagination."""

        return int(await self._session.scalar(self.count_statement(filters)) or 0)

    # RF-08: sessions are derived from the events, not stored separately, so the
    # group by needs a non null session id to produce one row per session.

    async def list_sessions(
        self,
        filters: EventFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Summarize each session: who connected, when, and for how long."""

        conditions = [*filters.conditions(), Event.session_id.is_not(None)]
        # Aggregated rather than grouped: host() is a function call, so it is not
        # a valid GROUP BY key, and picking one value keeps exactly one row per
        # session even if the events disagreed about the address.
        source_ip = func.min(func.host(Event.source_ip))
        first_seen = func.min(Event.occurred_at)
        last_seen = func.max(Event.occurred_at)
        span = func.extract("epoch", last_seen - first_seen)

        columns = (
            Event.session_id.label("session_id"),
            source_ip.label("source_ip"),
            first_seen.label("first_seen"),
            last_seen.label("last_seen"),
            (span * 1000).label("duration_ms"),
            func.count().label("event_count"),
            # RF-08 asks for the commands of each session. Counting by category
            # keeps it a single grouped read, with no join on the details JSONB.
            func.count()
            .filter(Event.event_category == "command")
            .label("command_count"),
            func.count(distinct(Event.session_id)).label("session_count"),
            func.array_agg(distinct(Event.username))
            .filter(Event.username.is_not(None))
            .label("usernames"),
            func.array_agg(distinct(Event.protocol))
            .filter(Event.protocol.is_not(None))
            .label("protocols"),
            func.bool_or(Event.event_category == "authentication").label("has_authentication"),
            func.bool_or(Event.outcome == "success").label("has_success"),
        )

        total = int(
            await self._session.scalar(
                select(func.count(distinct(Event.session_id))).where(*conditions)
            )
            or 0
        )
        rows = (
            await self._session.execute(
                select(*columns)
                .where(*conditions)
                .group_by(Event.session_id)
                .order_by(last_seen.desc())
                .limit(clamp_limit(limit))
                .offset(clamp_offset(offset))
            )
        ).all()

        return {
            "total": total,
            "limit": clamp_limit(limit),
            "offset": clamp_offset(offset),
            "items": [self._session_row(row) for row in rows],
        }

    # RF-09: the command text lives in details, so it is read from the JSONB
    # rather than from a column.

    async def list_commands(
        self,
        filters: EventFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List the commands recorded, newest first."""

        conditions = [*filters.conditions(), Event.event_category == "command"]
        columns = (
            Event.event_id.label("event_id"),
            Event.event_type.label("event_type"),
            Event.occurred_at.label("occurred_at"),
            func.host(Event.source_ip).label("source_ip"),
            Event.session_id.label("session_id"),
            Event.username.label("username"),
            Event.outcome.label("outcome"),
            Event.details["command"].astext.label("command"),
            Event.details["command_line"].astext.label("command_line"),
        )
        total = int(await self._session.scalar(select(func.count()).where(*conditions)) or 0)
        rows = (
            await self._session.execute(
                select(*columns)
                .where(*conditions)
                .order_by(Event.occurred_at.desc(), Event.id.desc())
                .limit(clamp_limit(limit))
                .offset(clamp_offset(offset))
            )
        ).all()
        return {
            "total": total,
            "limit": clamp_limit(limit),
            "offset": clamp_offset(offset),
            "items": [self._command_row(row) for row in rows],
        }

    # RF-10: activity per source address, the unit an analyst starts from.

    async def list_source_activity(
        self,
        filters: EventFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Summarize the activity of each source IP."""

        conditions = [*filters.conditions(), Event.source_ip.is_not(None)]
        source_ip = func.host(Event.source_ip)
        first_seen = func.min(Event.occurred_at)
        last_seen = func.max(Event.occurred_at)
        columns = (
            source_ip.label("source_ip"),
            func.count().label("event_count"),
            func.count(distinct(Event.session_id)).label("session_count"),
            func.count().filter(Event.event_category == "authentication").label("auth_attempts"),
            func.count().filter(Event.event_category == "command").label("commands"),
            func.count().filter(Event.event_category == "transfer").label("transfers"),
            func.count()
            .filter(Event.outcome == "failure")
            .label("failures"),
            func.array_agg(distinct(Event.username))
            .filter(Event.username.is_not(None))
            .label("usernames"),
            first_seen.label("first_seen"),
            last_seen.label("last_seen"),
        )
        # The total counts addresses, not events: this is a paginated list of
        # groups, so counting rows here would inflate the page count.
        total = int(
            await self._session.scalar(
                select(func.count(distinct(func.host(Event.source_ip)))).where(*conditions)
            )
            or 0
        )
        rows = (
            await self._session.execute(
                select(*columns)
                .where(*conditions)
                .group_by(source_ip)
                .order_by(func.count().desc(), last_seen.desc())
                .limit(clamp_limit(limit))
                .offset(clamp_offset(offset))
            )
        ).all()
        return {
            "total": total,
            "limit": clamp_limit(limit),
            "offset": clamp_offset(offset),
            "items": [self._source_row(row) for row in rows],
        }

    @staticmethod
    def _session_row(row: Any) -> dict[str, Any]:
        return {
            "session_id": row.session_id,
            "source_ip": row.source_ip,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "duration_ms": int(row.duration_ms) if row.duration_ms is not None else None,
            "event_count": int(row.event_count or 0),
            "command_count": int(row.command_count or 0),
            "usernames": _as_str_list(row.usernames),
            "protocols": _as_str_list(row.protocols),
            "has_authentication": bool(row.has_authentication),
            "has_success": bool(row.has_success),
        }

    @staticmethod
    def _command_row(row: Any) -> dict[str, Any]:
        return {
            "event_id": row.event_id,
            "event_type": row.event_type,
            "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
            "source_ip": row.source_ip,
            "session_id": row.session_id,
            "username": row.username,
            "outcome": row.outcome,
            "command": row.command,
            "command_line": row.command_line or row.command,
        }

    @staticmethod
    def _source_row(row: Any) -> dict[str, Any]:
        return {
            "source_ip": row.source_ip,
            "event_count": int(row.event_count or 0),
            "session_count": int(row.session_count or 0),
            "auth_attempts": int(row.auth_attempts or 0),
            "commands": int(row.commands or 0),
            "transfers": int(row.transfers or 0),
            "failures": int(row.failures or 0),
            "usernames": _as_str_list(row.usernames),
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        }

    async def get_cursor(self, path: str) -> int:
        offset = await self._session.scalar(
            select(SpoolCursor.byte_offset).where(SpoolCursor.path == path)
        )
        return int(offset or 0)

    async def set_cursor(self, path: str, offset: int) -> None:
        statement = (
            pg_insert(SpoolCursor.__table__)
            .values(path=path, byte_offset=offset)
            .on_conflict_do_update(
                index_elements=["path"],
                set_={"byte_offset": offset, "updated_at": func.now()},
            )
        )
        await self._session.execute(statement)
        await self._session.flush()


@dataclass(frozen=True, slots=True)
class DetectionFilters:
    """Filters accepted by the detection query endpoint."""

    rule_id: str | None = None
    source_ip: str | None = None
    session_id: str | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None

    def conditions(self) -> list[Any]:
        clauses: list[Any] = []
        address = _as_ip(self.source_ip)
        if address is not None:
            clauses.append(Detection.source_ip == address)
        if self.rule_id:
            clauses.append(Detection.rule_id == self.rule_id)
        if self.session_id:
            clauses.append(Detection.session_id == self.session_id)
        if self.occurred_from:
            clauses.append(Detection.occurred_from >= self.occurred_from)
        if self.occurred_to:
            clauses.append(Detection.occurred_to <= self.occurred_to)
        return clauses


@dataclass(frozen=True, slots=True)
class DetectionPage:
    """A page of stored detections."""

    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class DetectionRepository:
    """Read and write access to the stored detections (RF-11).

    Inserts ignore a finding whose fingerprint is already stored, so evaluating
    the same rule over the same events twice records it once.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def insert_statement(records: Sequence[Mapping[str, Any]]) -> Any:
        """Build the idempotent insert for a batch of findings."""

        return (
            pg_insert(Detection.__table__)
            .values([dict(record) for record in records])
            .on_conflict_do_nothing(index_elements=["fingerprint"])
            .returning(Detection.id)
        )

    @staticmethod
    def count_statement(filters: DetectionFilters) -> Select[Any]:
        """Build the statement that counts the detections matching ``filters``."""

        return select(func.count()).select_from(Detection).where(*filters.conditions())

    @staticmethod
    def page_statement(
        filters: DetectionFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> Select[Any]:
        """Build the statement that returns one page of detections."""

        return (
            select(Detection)
            .where(*filters.conditions())
            .order_by(Detection.occurred_from.desc(), Detection.id.desc())
            .limit(limit)
            .offset(offset)
        )

    async def insert_detections(self, detections: Sequence[Any]) -> list[dict[str, Any]]:
        """Store findings and return the ones that were not stored before.

        The stored rows are read back, so the caller reports the database state
        (including ``detected_at``) instead of what it tried to write.
        """

        if not detections:
            return []
        records = [detection.to_record() for detection in detections]
        result = await self._session.execute(self.insert_statement(records))
        stored_ids = list(result.scalars().all())
        await self._session.flush()
        if not stored_ids:
            return []

        rows = (
            await self._session.execute(
                select(Detection).where(Detection.id.in_(stored_ids)).order_by(Detection.id)
            )
        ).scalars().all()
        return [row.to_dict() for row in rows]

    async def list_detections(
        self,
        filters: DetectionFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> DetectionPage:
        """Return a page of stored detections, most recent first."""

        total = await self._session.scalar(self.count_statement(filters))
        rows = (
            await self._session.execute(
                self.page_statement(
                    filters, limit=clamp_limit(limit), offset=clamp_offset(offset)
                )
            )
        ).scalars().all()
        return DetectionPage(
            items=[row.to_dict() for row in rows],
            total=int(total or 0),
            limit=clamp_limit(limit),
            offset=clamp_offset(offset),
        )


@dataclass(frozen=True, slots=True)
class AlertFilters:
    """Filters accepted by the alert query endpoints."""

    rule_id: str | None = None
    alert_type: str | None = None
    severity: str | None = None
    source_ip: str | None = None
    session_id: str | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None

    def conditions(self) -> list[Any]:
        clauses: list[Any] = []
        address = _as_ip(self.source_ip)
        if address is not None:
            clauses.append(Alert.source_ip == address)
        if self.rule_id:
            clauses.append(Alert.rule_id == self.rule_id)
        if self.alert_type:
            clauses.append(Alert.alert_type == self.alert_type)
        if self.severity:
            clauses.append(Alert.severity == self.severity)
        if self.session_id:
            clauses.append(Alert.session_id == self.session_id)
        if self.occurred_from:
            clauses.append(Alert.occurred_from >= self.occurred_from)
        if self.occurred_to:
            clauses.append(Alert.occurred_to <= self.occurred_to)
        return clauses


@dataclass(frozen=True, slots=True)
class AlertPage:
    """A page of raised alerts."""

    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class AlertRepository:
    """Read and write access to the raised alerts (RF-12).

    An alert is raised for a detection and never twice for the same one: the
    insert ignores a ``detection_id`` that already has an alert, which is what
    keeps a repeated evaluation of a rule from producing a duplicate alert.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def insert_statement(records: Sequence[Mapping[str, Any]]) -> Any:
        """Build the idempotent insert for a batch of alerts."""

        return (
            pg_insert(Alert.__table__)
            .values([dict(record) for record in records])
            .on_conflict_do_nothing(index_elements=["detection_id"])
            .returning(Alert.id)
        )

    @staticmethod
    def count_statement(filters: AlertFilters) -> Select[Any]:
        """Build the statement that counts the alerts matching ``filters``."""

        return select(func.count()).select_from(Alert).where(*filters.conditions())

    @staticmethod
    def page_statement(
        filters: AlertFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> Select[Any]:
        """Build the statement that returns one page of alerts.

        Alerts are ordered by the severity first, so the ones that need looking
        at come first, and by generation time within a level.
        """

        return (
            select(Alert)
            .where(*filters.conditions())
            .order_by(
                _SEVERITY_RANK.desc(),
                Alert.generated_at.desc(),
                Alert.id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

    async def insert_alerts(self, alerts: Sequence[Any]) -> list[dict[str, Any]]:
        """Store alerts and return the ones that were not raised before."""

        if not alerts:
            return []
        records = [alert.to_record() for alert in alerts]
        result = await self._session.execute(self.insert_statement(records))
        stored_ids = list(result.scalars().all())
        await self._session.flush()
        if not stored_ids:
            return []

        rows = (
            await self._session.execute(
                select(Alert).where(Alert.id.in_(stored_ids)).order_by(Alert.id)
            )
        ).scalars().all()
        return [row.to_dict() for row in rows]

    async def list_alerts(
        self,
        filters: AlertFilters,
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> AlertPage:
        """Return a page of alerts, the most severe and recent first."""

        total = await self._session.scalar(self.count_statement(filters))
        rows = (
            await self._session.execute(
                self.page_statement(filters, limit=clamp_limit(limit), offset=clamp_offset(offset))
            )
        ).scalars().all()
        return AlertPage(
            items=[row.to_dict() for row in rows],
            total=int(total or 0),
            limit=clamp_limit(limit),
            offset=clamp_offset(offset),
        )

    async def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        """Return one alert, or ``None`` when it does not exist."""

        row = await self._session.scalar(select(Alert).where(Alert.id == alert_id))
        return row.to_dict() if row is not None else None

    async def count(self, filters: AlertFilters | None = None) -> int:
        """Count the alerts, for the summary of RF-04."""

        return int(
            await self._session.scalar(self.count_statement(filters or AlertFilters())) or 0
        )
