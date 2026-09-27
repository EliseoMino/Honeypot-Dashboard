"""Session query endpoints (RF-08).

A session is not stored in its own table: it is derived from the events that
carry a ``session_id``. RF-08 asks for the identifier, the source IP, the start
and either an end or a duration, and all of that is recoverable from the events
themselves, so this is a grouped read and no migration is involved.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.api.events import _filters, _source_ip
from honeypot_backend.db.repository import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    EventFilters,
    EventRepository,
)
from honeypot_backend.db.session import get_session

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])


class SessionSummary(BaseModel):
    """One session, as far as the stored events describe it."""

    session_id: str
    source_ip: str | None = Field(
        description="First address seen in the session, when the events carry one"
    )
    first_seen: str | None
    last_seen: str | None
    duration_ms: int | None = Field(
        description="Milliseconds between the first and the last event of the session"
    )
    event_count: int
    usernames: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    has_authentication: bool
    has_success: bool


class SessionPage(BaseModel):
    """A page of sessions, the most recently active first."""

    total: int
    limit: int
    offset: int
    items: list[SessionSummary]


async def _session_filters(
    source_ip: Annotated[str | None, Query(description="Attacker IP address")] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
    occurred_from: Annotated[datetime | None, Query()] = None,
    occurred_to: Annotated[datetime | None, Query()] = None,
) -> EventFilters:
    return _filters(source_ip, None, username, None, None, None, occurred_from, occurred_to, None)


@router.get("", response_model=SessionPage, summary="List the recorded sessions")
async def list_sessions(
    filters: Annotated[EventFilters, Depends(_session_filters)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SessionPage:
    """Return a page of the sessions the honeypot recorded."""

    page = await EventRepository(session).list_sessions(filters, limit=limit, offset=offset)
    return SessionPage(
        total=page["total"],
        limit=page["limit"],
        offset=page["offset"],
        items=[SessionSummary(**item) for item in page["items"]],
    )
