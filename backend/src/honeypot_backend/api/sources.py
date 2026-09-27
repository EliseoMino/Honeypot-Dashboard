"""Per source IP activity endpoints (RF-10).

RF-10 asks for the event count, the associated sessions, the authentication
attempts and the commands of a source address. It is a grouped read over the
same events as the rest of the API, so no table is added.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
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

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])


class SourceActivity(BaseModel):
    """Everything one attacker address did."""

    source_ip: str
    event_count: int
    session_count: int = Field(description="Distinct sessions this address opened")
    auth_attempts: int
    commands: int
    transfers: int
    failures: int
    usernames: list[str] = Field(default_factory=list)
    first_seen: str | None
    last_seen: str | None


class SourcePage(BaseModel):
    """A page of source addresses, the busiest first."""

    total: int
    limit: int
    offset: int
    items: list[SourceActivity]


class SourceDetail(SourceActivity):
    """The activity of one address, with where its events fall by category."""

    by_category: list[dict[str, object]] = Field(default_factory=list)


async def _source_filters(
    occurred_from: Annotated[datetime | None, Query()] = None,
    occurred_to: Annotated[datetime | None, Query()] = None,
) -> EventFilters:
    return _filters(None, None, None, None, None, None, occurred_from, occurred_to, None)


@router.get("", response_model=SourcePage, summary="Activity grouped by source IP")
async def list_sources(
    filters: Annotated[EventFilters, Depends(_source_filters)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SourcePage:
    """Return a page of the attacker addresses, busiest first."""

    page = await EventRepository(session).list_source_activity(filters, limit=limit, offset=offset)
    return SourcePage(
        total=page["total"],
        limit=page["limit"],
        offset=page["offset"],
        items=[SourceActivity(**item) for item in page["items"]],
    )


@router.get("/{source_ip}", response_model=SourceDetail, summary="Activity of one source IP")
async def get_source(
    source_ip: str,
    filters: Annotated[EventFilters, Depends(_source_filters)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SourceDetail:
    """Return everything one address did, with the events by category.

    RF-10 is about a single address, so the list and the detail share the same
    aggregation and the detail only adds the category breakdown.
    """

    address = _source_ip(source_ip)
    if address is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"'{source_ip}' is not a valid IP address",
        )
    repository = EventRepository(session)
    scoped = EventFilters(
        source_ip=address,
        occurred_from=filters.occurred_from,
        occurred_to=filters.occurred_to,
    )
    page = await repository.list_source_activity(scoped, limit=1, offset=0)
    if not page["items"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no events were recorded for {source_ip}",
        )
    by_category = (await repository.summary(scoped))["by_category"]
    return SourceDetail(**page["items"][0], by_category=by_category)
