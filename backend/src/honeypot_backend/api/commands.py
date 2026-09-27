"""Command query endpoints (RF-09).

RF-09 asks for the command, when it ran, the source IP and the session it
belongs to. Commands are stored as events in the ``command`` category with the
parsed command in ``details``, so this reads that JSONB rather than adding a
table for it.
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

router = APIRouter(prefix="/api/v1/commands", tags=["commands"])


class CommandRecord(BaseModel):
    """One command recorded during a session."""

    event_id: str
    event_type: str
    occurred_at: str | None
    source_ip: str | None
    session_id: str | None
    username: str | None
    outcome: str | None
    command: str | None = Field(description="The parsed command name, when Cowrie reported one")
    command_line: str | None = Field(description="The full line as it was typed")


class CommandPage(BaseModel):
    """A page of commands, newest first."""

    total: int
    limit: int
    offset: int
    items: list[CommandRecord]


async def _command_filters(
    source_ip: Annotated[str | None, Query(description="Attacker IP address")] = None,
    session_id: Annotated[str | None, Query(max_length=128)] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
    q: Annotated[str | None, Query(max_length=256, description="Free text search")] = None,
    occurred_from: Annotated[datetime | None, Query()] = None,
    occurred_to: Annotated[datetime | None, Query()] = None,
) -> EventFilters:
    return _filters(source_ip, session_id, username, None, None, None, occurred_from, occurred_to, q)


@router.get("", response_model=CommandPage, summary="List the recorded commands")
async def list_commands(
    filters: Annotated[EventFilters, Depends(_command_filters)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CommandPage:
    """Return a page of the commands executed in the honeypot sessions."""

    page = await EventRepository(session).list_commands(filters, limit=limit, offset=offset)
    return CommandPage(
        total=page["total"],
        limit=page["limit"],
        offset=page["offset"],
        items=[CommandRecord(**item) for item in page["items"]],
    )
