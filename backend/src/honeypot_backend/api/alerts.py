"""Alert endpoints (RF-12).

The alerts raised by the RF-11 rules are persisted, so they can be read back
here and shown by the dashboard. The evidence an alert carries identifies the
events that triggered its detection, and ``evidence.event_ids`` is what the
dashboard uses to open those events.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.db.repository import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    AlertFilters,
    AlertRepository,
)
from honeypot_backend.db.session import get_session
from honeypot_backend.detection.rules import SEVERITY_LEVELS

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


class AlertModel(BaseModel):
    """One raised alert, with the activity it reports."""

    id: int
    detection_id: int
    alert_type: str
    severity: str
    rule_id: str
    title: str
    description: str
    source_ip: str | None
    session_id: str | None
    occurred_from: str
    occurred_to: str
    event_count: int
    evidence: dict[str, Any] = Field(
        description="The events that triggered the detection, with their ids"
    )
    generated_at: str


class AlertPage(BaseModel):
    """A page of alerts, the most severe and recent first."""

    total: int
    limit: int
    offset: int
    items: list[AlertModel]


@router.get("", response_model=AlertPage, summary="List raised alerts")
async def list_alerts(
    session: Annotated[AsyncSession, Depends(get_session)],
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    alert_type: Annotated[str | None, Query(max_length=32)] = None,
    severity: Annotated[str | None, Query(description="One of: low, medium, high, critical")] = None,
    source_ip: Annotated[str | None, Query(description="Attacker IP address")] = None,
    session_id: Annotated[str | None, Query(max_length=128)] = None,
    occurred_from: Annotated[datetime | None, Query()] = None,
    occurred_to: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertPage:
    """Return a page of the alerts raised by the detection rules."""

    page = await AlertRepository(session).list_alerts(
        AlertFilters(
            rule_id=rule_id,
            alert_type=alert_type,
            severity=_severity(severity),
            source_ip=_source_ip(source_ip),
            session_id=session_id,
            occurred_from=_as_utc(occurred_from),
            occurred_to=_as_utc(occurred_to),
        ),
        limit=limit,
        offset=offset,
    )
    return AlertPage(
        total=page.total,
        limit=page.limit,
        offset=page.offset,
        items=[AlertModel(**item) for item in page.items],
    )


@router.get("/{alert_id}", response_model=AlertModel, summary="Read one alert")
async def get_alert(
    alert_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AlertModel:
    """Return one alert with the evidence of its detection."""

    alert = await AlertRepository(session).get_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"alert {alert_id} was not found"
        )
    return AlertModel(**alert)


def _severity(value: str | None) -> str | None:
    """Validate the requested severity instead of filtering on nothing."""

    if value is None:
        return None
    if value not in SEVERITY_LEVELS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{value}' is not a severity level, expected one of "
            f"{', '.join(SEVERITY_LEVELS)}",
        )
    return value


def _as_utc(value: datetime | None) -> datetime | None:
    """Return a timezone aware datetime, assuming UTC when none was given."""

    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _source_ip(value: str | None) -> str | None:
    """Validate the requested IP, the way the event endpoints do."""

    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{value}' is not a valid IP address",
        ) from None
