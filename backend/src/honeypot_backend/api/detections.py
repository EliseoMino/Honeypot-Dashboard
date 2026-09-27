"""Detection endpoints (RF-11).

The rules are evaluated on demand: nothing runs in the background, so what the
API reports is exactly the window the caller asked for and nothing else. A run
stores the findings it had not recorded before, and the recorded findings are
readable through ``GET /api/v1/detections``.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.db.repository import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    DetectionFilters,
    DetectionRepository,
)
from honeypot_backend.db.session import get_session
from honeypot_backend.detection import DetectionService, RulesUnavailable
from honeypot_backend.detection.service import lookback_of

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])


class DetectionModel(BaseModel):
    """A stored detection, with the evidence that produced it."""

    rule_id: str
    rule_kind: str
    title: str
    source_ip: str | None
    session_id: str | None
    occurred_from: str
    occurred_to: str
    event_count: int
    evidence: dict[str, Any] = Field(description="The events that triggered the rule")
    fingerprint: str
    detected_at: str


class DetectionPage(BaseModel):
    """A page of stored detections."""

    total: int
    limit: int
    offset: int
    items: list[DetectionModel]


class DetectionRunRequest(BaseModel):
    """The window of events to evaluate. Defaults to the configured lookback."""

    occurred_from: datetime | None = None
    occurred_to: datetime | None = None

    @model_validator(mode="after")
    def _ordered_window(self) -> DetectionRunRequest:
        if self.occurred_from and self.occurred_to and self.occurred_from > self.occurred_to:
            raise ValueError("occurred_from must not be after occurred_to")
        return self


class DetectionRunResponse(BaseModel):
    """What one evaluation of the rules found."""

    occurred_from: datetime
    occurred_to: datetime
    rules_evaluated: int
    detections_found: int = Field(
        description="Findings in the window, including the ones recorded before"
    )
    detections_created: int = Field(description="Findings stored by this run")
    items: list[DetectionModel] = Field(description="The findings this run stored")


class RuleDescription(BaseModel):
    """One configured rule and the parameters it will be evaluated with."""

    id: str
    kind: str
    title: str
    description: str
    parameters: dict[str, Any]


class RuleSet(BaseModel):
    """The rule configuration of this deployment."""

    available: bool
    path: str | None
    error: str | None
    version: int
    rules: list[RuleDescription]


@router.get("/rules", response_model=RuleSet, summary="Configured detection rules")
async def list_rules(request: Request) -> RuleSet:
    """Report the rules this deployment evaluates and where they come from."""

    service: DetectionService = request.app.state.detection
    described = service.describe()
    common = {"id", "kind", "title", "description"}
    return RuleSet(
        available=described["available"],
        path=described["path"],
        error=described["error"],
        version=described["version"],
        rules=[
            RuleDescription(
                **{key: rule[key] for key in common},
                parameters={key: value for key, value in rule.items() if key not in common},
            )
            for rule in described["rules"]
        ],
    )


@router.post("/run", response_model=DetectionRunResponse, summary="Evaluate the rules")
async def run_detection(
    request: Request,
    body: DetectionRunRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> DetectionRunResponse:
    """Evaluate every rule over a window of events and store the findings."""

    service: DetectionService = request.app.state.detection
    _require_available(service)

    occurred_to = _as_utc(body.occurred_to) or datetime.now(UTC)
    occurred_from = _as_utc(body.occurred_from) or (
        occurred_to - lookback_of(request.app.state.settings)
    )

    engine = service.require_rules()
    found = await engine.run(session, occurred_from=occurred_from, occurred_to=occurred_to)
    created = await DetectionRepository(session).insert_detections(found)
    await session.commit()

    return DetectionRunResponse(
        occurred_from=occurred_from,
        occurred_to=occurred_to,
        rules_evaluated=engine.rule_count,
        detections_found=len(found),
        detections_created=len(created),
        items=[DetectionModel(**record) for record in created],
    )


@router.get("", response_model=DetectionPage, summary="List stored detections")
async def list_detections(
    session: Annotated[AsyncSession, Depends(get_session)],
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    source_ip: Annotated[str | None, Query(description="Attacker IP address")] = None,
    session_id: Annotated[str | None, Query(max_length=128)] = None,
    occurred_from: Annotated[datetime | None, Query()] = None,
    occurred_to: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> DetectionPage:
    """Return a page of the recorded detections, most recent first."""

    page = await DetectionRepository(session).list_detections(
        DetectionFilters(
            rule_id=rule_id,
            source_ip=_source_ip(source_ip),
            session_id=session_id,
            occurred_from=_as_utc(occurred_from),
            occurred_to=_as_utc(occurred_to),
        ),
        limit=limit,
        offset=offset,
    )
    return DetectionPage(
        total=page.total,
        limit=page.limit,
        offset=page.offset,
        items=[DetectionModel(**item) for item in page.items],
    )


def _require_available(service: DetectionService) -> None:
    if not service.available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"detection is not available: {service.error}",
        ) from RulesUnavailable(service.error)


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
