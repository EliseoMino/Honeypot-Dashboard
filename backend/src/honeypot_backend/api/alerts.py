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

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.db.repository import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    AlertFilters,
    AlertRepository,
)
from honeypot_backend.db.session import get_session
from honeypot_backend.db.models import Alert
from honeypot_backend.detection.rules import SEVERITY_LEVELS
from honeypot_backend.api.safe_output import safe_evidence
from honeypot_backend.api.geo import with_country

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])
ALERT_STATUSES = ("new", "in_progress", "resolved", "false_positive")


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
    country_code: str | None = None
    country_name: str | None = None
    session_id: str | None
    occurred_from: str
    occurred_to: str
    event_count: int
    evidence: dict[str, Any] = Field(
        description="The events that triggered the detection, with their ids"
    )
    generated_at: str
    status: str = "new"
    notes: str = ""
    false_positive_reason: str | None = None
    status_updated_at: str | None = None


class AlertTriageUpdate(BaseModel):
    status: str = Field(pattern=r"^(new|in_progress|resolved|false_positive)$")
    notes: str = Field(default="", max_length=4000)
    false_positive_reason: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def _false_positive_reason_required(self) -> AlertTriageUpdate:
        if self.status == "false_positive" and not (self.false_positive_reason or "").strip():
            raise ValueError("false_positive_reason is required for false_positive status")
        return self


class AlertStatusChange(BaseModel):
    previous_status: str | None
    new_status: str
    note: str
    changed_at: str


class AlertListModel(BaseModel):
    """Safe alert collection row; operator notes remain on the detail view."""

    id: int
    detection_id: int
    alert_type: str
    severity: str
    rule_id: str
    title: str
    description: str
    source_ip: str | None
    country_code: str | None = None
    country_name: str | None = None
    session_id: str | None
    occurred_from: str
    occurred_to: str
    event_count: int
    generated_at: str
    status: str
    status_updated_at: str | None = None


class AlertPage(BaseModel):
    """A page of alerts, the most severe and recent first."""

    total: int
    limit: int
    offset: int
    items: list[AlertListModel]


@router.get("", response_model=AlertPage, summary="List raised alerts")
async def list_alerts(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    alert_type: Annotated[str | None, Query(max_length=32)] = None,
    severity: Annotated[str | None, Query(description="One of: low, medium, high, critical")] = None,
    alert_status: Annotated[str | None, Query(alias="status")] = None,
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
            status=_alert_status(alert_status),
        ),
        limit=limit,
        offset=offset,
    )
    return AlertPage(
        total=page.total,
        limit=page.limit,
        offset=page.offset,
        items=[AlertListModel(**with_country(request, item)) for item in page.items],
    )


@router.get("/{alert_id}", response_model=AlertModel, summary="Read one alert")
async def get_alert(
    alert_id: int,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    include_sensitive: Annotated[bool, Query(description="Reveal full alert evidence")]=False,
) -> AlertModel:
    """Return one alert with the evidence of its detection."""

    alert = await AlertRepository(session).get_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"alert {alert_id} was not found"
        )
    if not include_sensitive:
        alert["evidence"] = safe_evidence(alert.get("evidence"))
    return AlertModel(**with_country(request, alert))


@router.patch("/{alert_id}/triage", response_model=AlertModel, summary="Update alert triage")
async def update_alert_triage(
    alert_id: int,
    body: AlertTriageUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AlertModel:
    """Update the single operator's current alert status and notes."""

    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert {alert_id} was not found")
    old_status = alert.status
    now = datetime.now(UTC)
    alert.status = body.status
    alert.notes = body.notes.strip()
    alert.false_positive_reason = (
        body.false_positive_reason.strip() if body.status == "false_positive" else None
    )
    alert.status_updated_at = now
    if old_status != body.status:
        await session.execute(
            text(
                "INSERT INTO alert_status_history "
                "(alert_id, previous_status, new_status, note, changed_at) "
                "VALUES (:alert_id, :previous_status, :new_status, :note, :changed_at)"
            ),
            {
                "alert_id": alert.id,
                "previous_status": old_status,
                "new_status": body.status,
                "note": body.notes.strip(),
                "changed_at": now,
            },
        )
    await session.commit()
    await session.refresh(alert)
    result = alert.to_dict()
    result["evidence"] = safe_evidence(result.get("evidence"))
    return AlertModel(**result)


@router.get("/{alert_id}/history", response_model=list[AlertStatusChange], summary="Alert status history")
async def alert_history(
    alert_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[AlertStatusChange]:
    exists = await session.get(Alert, alert_id)
    if exists is None:
        raise HTTPException(status_code=404, detail=f"alert {alert_id} was not found")
    result = await session.execute(
        text(
            "SELECT previous_status, new_status, note, changed_at "
            "FROM alert_status_history WHERE alert_id = :alert_id ORDER BY changed_at, id"
        ),
        {"alert_id": alert_id},
    )
    return [
        AlertStatusChange(
            previous_status=row.previous_status,
            new_status=row.new_status,
            note=row.note,
            changed_at=row.changed_at.isoformat(),
        )
        for row in result
    ]


def _severity(value: str | None) -> str | None:
    """Validate the requested severity instead of filtering on nothing."""

    if value is None:
        return None
    if value not in SEVERITY_LEVELS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"'{value}' is not a severity level, expected one of "
            f"{', '.join(SEVERITY_LEVELS)}",
        )
    return value


def _alert_status(value: str | None) -> str | None:
    if value is None:
        return None
    if value not in ALERT_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {', '.join(ALERT_STATUSES)}")
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
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"'{value}' is not a valid IP address",
        ) from None
