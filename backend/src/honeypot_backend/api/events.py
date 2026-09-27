"""Query endpoints over the stored events (RF-03).

These endpoints are the read side of the storage requirement: stored events can
be listed, filtered, ordered, searched and aggregated. They also cover the base
of RF-06 (consulta de eventos) and RF-07 (detalle de un evento); the dashboard
still has to be built on top of them.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.db.repository import DEFAULT_LIMIT, MAX_LIMIT, EventFilters, EventRepository
from honeypot_backend.db.session import get_session
from honeypot_backend.normalization.events import EventCategory, EventOutcome, NormalizedEvent

router = APIRouter(prefix="/api/v1/events", tags=["events"])


class CountEntry(BaseModel):
    key: str | None = None
    count: int


class EventPage(BaseModel):
    """A page of stored events."""

    total: int = Field(description="Total number of events matching the filters")
    limit: int
    offset: int
    items: list[NormalizedEvent]


class EventSummary(BaseModel):
    """Aggregated counters for a set of filters.

    The counters named by RF-04 are ``total_events``, ``unique_source_ips``,
    ``unique_sessions``, ``auth_attempts``, ``commands`` and ``alerts``.
    """

    total_events: int
    unique_source_ips: int
    unique_sessions: int
    unique_usernames: int
    first_event_at: str | None
    last_event_at: str | None
    auth_attempts: int = Field(description="Events in the authentication category")
    commands: int = Field(description="Events in the command category")
    alerts: int = Field(
        default=0,
        description=(
            "Always 0: detection rules and alerts (RF-11 and RF-12) are not "
            "implemented yet, so there is nothing to count"
        ),
    )
    by_category: list[CountEntry]
    by_outcome: list[CountEntry]
    by_protocol: list[CountEntry]
    top_event_types: list[CountEntry]


def _source_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{value}' is not a valid IP address",
        ) from None


def _filters(
    source_ip: str | None,
    session_id: str | None,
    username: str | None,
    event_type: list[str] | None,
    event_category: str | None,
    outcome: str | None,
    occurred_from: datetime | None,
    occurred_to: datetime | None,
    q: str | None,
) -> EventFilters:
    types: tuple[str, ...] = tuple(
        part.strip()
        for value in event_type or []
        for part in value.split(",")
        if part.strip()
    )
    return EventFilters(
        source_ip=_source_ip(source_ip),
        session_id=session_id,
        username=username,
        event_types=types,
        event_category=event_category,
        outcome=outcome,
        occurred_from=occurred_from,
        occurred_to=occurred_to,
        search=q,
    )


async def _event_filters(
    source_ip: Annotated[str | None, Query(description="Attacker IP address")] = None,
    session_id: Annotated[str | None, Query(max_length=128)] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
    event_type: Annotated[list[str] | None, Query()] = None,
    event_category: Annotated[EventCategory | None, Query()] = None,
    outcome: Annotated[EventOutcome | None, Query()] = None,
    occurred_from: Annotated[datetime | None, Query()] = None,
    occurred_to: Annotated[datetime | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=256, description="Free text search")] = None,
) -> EventFilters:
    return _filters(
        source_ip,
        session_id,
        username,
        event_type,
        event_category,
        outcome,
        occurred_from,
        occurred_to,
        q,
    )


@router.get("/summary", response_model=EventSummary, summary="Aggregated event counters")
async def events_summary(
    filters: Annotated[EventFilters, Depends(_event_filters)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> EventSummary:
    """Return aggregated counters for the filtered set of events."""

    summary = await EventRepository(session).summary(filters)
    return EventSummary(**summary)


@router.get("", response_model=EventPage, summary="List stored events")
async def list_events(
    filters: Annotated[EventFilters, Depends(_event_filters)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
    order: Annotated[Literal["asc", "desc"], Query()] = "desc",
) -> EventPage:
    """Return a filtered, ordered page of stored events."""

    page = await EventRepository(session).list_events(filters, limit=limit, offset=offset, order=order)
    return EventPage(
        total=page.total,
        limit=page.limit,
        offset=page.offset,
        items=[NormalizedEvent.model_validate(item) for item in page.items],
    )


@router.get("/{event_id}", response_model=NormalizedEvent, summary="Event detail")
async def get_event(
    event_id: str,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> NormalizedEvent:
    """Return the full detail of a single stored event."""

    event = await EventRepository(session).get_event(event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"event '{event_id}' not found",
        )
    return NormalizedEvent.model_validate(event)
