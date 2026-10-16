"""Bounded, redacted exports for investigations (no raw Cowrie evidence)."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.api.alerts import _alert_status, _as_utc, _severity
from honeypot_backend.api.events import _event_filters, _source_ip
from honeypot_backend.api.geo import with_country
from honeypot_backend.api.safe_output import safe_evidence
from honeypot_backend.db.repository import (
    AlertFilters,
    AlertRepository,
    EventFilters,
    EventRepository,
    MAX_LIMIT,
)
from honeypot_backend.db.models import Alert
from honeypot_backend.db.session import get_session

router = APIRouter(prefix="/api/v1/exports", tags=["exports"])
MAX_EXPORT_ROWS = 10_000
_EVENT_FIELDS = (
    "event_id", "event_type", "event_category", "occurred_at", "received_at",
    "source_ip", "country_code", "country_name", "source_port", "destination_port",
    "protocol", "session_id", "username", "outcome",
)
_ALERT_FIELDS = (
    "id", "generated_at", "severity", "status", "alert_type", "rule_id", "title",
    "source_ip", "country_code", "country_name", "session_id", "occurred_from",
    "occurred_to", "event_count", "evidence",
)


@router.get("/events.{format}", summary="Export filtered events")
async def export_events(
    format: Literal["csv", "json"],
    request: Request,
    filters: Annotated[EventFilters, Depends(_event_filters)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    repository = EventRepository(session)
    total = await repository.count_filtered(filters)
    _check_export_size(total)
    rows: list[dict[str, Any]] = []
    for offset in range(0, total, MAX_LIMIT):
        page = await repository.list_events(filters, limit=MAX_LIMIT, offset=offset, order="asc")
        rows.extend(_safe_event(with_country(request, row)) for row in page.items)
    return _download(format, "events", rows, _EVENT_FIELDS)


@router.get("/alerts.{format}", summary="Export filtered alerts")
async def export_alerts(
    format: Literal["csv", "json"],
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    alert_type: Annotated[str | None, Query(max_length=32)] = None,
    severity: Annotated[str | None, Query()] = None,
    source_ip: Annotated[str | None, Query()] = None,
    session_id: Annotated[str | None, Query(max_length=128)] = None,
    status: Annotated[str | None, Query()] = None,
    occurred_from: Annotated[datetime | None, Query()] = None,
    occurred_to: Annotated[datetime | None, Query()] = None,
) -> Response:
    filters = AlertFilters(
        rule_id=rule_id,
        alert_type=alert_type,
        severity=_severity(severity),
        source_ip=_source_ip(source_ip),
        session_id=session_id,
        occurred_from=_as_utc(occurred_from),
        occurred_to=_as_utc(occurred_to),
        status=_alert_status(status),
    )
    repository = AlertRepository(session)
    total = await repository.count(filters)
    _check_export_size(total)
    rows: list[dict[str, Any]] = []
    for offset in range(0, total, MAX_LIMIT):
        page = await repository.list_alerts(filters, limit=MAX_LIMIT, offset=offset)
        for item in page.items:
            safe = {**item, "evidence": safe_evidence(item.get("evidence"))}
            rows.append(with_country(request, _safe_alert(safe)))
    return _download(format, "alerts", rows, _ALERT_FIELDS)


@router.get("/report.json", summary="Download a redacted activity report")
async def export_report(
    request: Request,
    filters: Annotated[EventFilters, Depends(_event_filters)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    repository = EventRepository(session)
    summary = await repository.summary(filters)
    sources = await repository.list_source_activity(filters, limit=25, offset=0)
    alert_filters = AlertFilters(
        source_ip=filters.source_ip,
        session_id=filters.session_id,
        occurred_from=filters.occurred_from,
        occurred_to=filters.occurred_to,
    )
    alert_repository = AlertRepository(session)
    alert_count = await alert_repository.count(alert_filters)
    alert_groups = await session.execute(
        select(Alert.severity, func.count())
        .where(*alert_filters.conditions())
        .group_by(Alert.severity)
    )
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "filters": {
            "source_ip": filters.source_ip,
            "session_id": filters.session_id,
            "username": filters.username,
            "event_types": list(filters.event_types),
            "event_category": filters.event_category,
            "outcome": filters.outcome,
            "occurred_from": filters.occurred_from.isoformat() if filters.occurred_from else None,
            "occurred_to": filters.occurred_to.isoformat() if filters.occurred_to else None,
            "search_applied": bool(filters.search),
        },
        "summary": summary,
        "alerts": {
            "total": alert_count,
            "by_severity": {severity: count for severity, count in alert_groups.all()},
        },
        "top_sources": [with_country(request, item) for item in sources["items"]],
        "redaction": "No credentials, raw Cowrie payloads, or full command lines are included.",
    }
    return Response(
        content=json.dumps(report, ensure_ascii=False, separators=(",", ":")),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="honeypot-report.json"'},
    )


def _safe_event(item: dict[str, Any]) -> dict[str, Any]:
    return {field: item.get(field) for field in _EVENT_FIELDS}


def _safe_alert(item: dict[str, Any]) -> dict[str, Any]:
    return {field: item.get(field) for field in _ALERT_FIELDS}


def _check_export_size(total: int) -> None:
    if total > MAX_EXPORT_ROWS:
        raise HTTPException(
            status_code=413,
            detail=f"Export has {total} rows; narrow the filters to {MAX_EXPORT_ROWS} rows or fewer.",
        )


def _download(
    format: Literal["csv", "json"],
    name: str,
    rows: list[dict[str, Any]],
    fields: tuple[str, ...],
) -> Response:
    if format == "json":
        payload = json.dumps(rows, ensure_ascii=False, separators=(",", ":"), default=str)
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="honeypot-{name}.json"'},
        )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        safe_row = {key: _csv_safe(row.get(key)) for key in fields}
        if isinstance(safe_row.get("evidence"), (dict, list)):
            safe_row["evidence"] = json.dumps(safe_row["evidence"], ensure_ascii=False)
        writer.writerow(safe_row)
    return Response(
        content="\ufeff" + output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="honeypot-{name}.csv"'},
    )


def _csv_safe(value: Any) -> Any:
    """Prevent spreadsheet formula execution from imported attacker strings."""

    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value
