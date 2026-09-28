"""Ingestion endpoints (RF-01) and the normalized output of RF-02.

Flow of a batch:

1. The raw payload is appended to the durable raw spool and flushed. Nothing
   received is ever lost, even if normalization later fails.
2. Each event is normalized to :class:`NormalizedEvent`.
3. Normalized events are appended to the normalized spool.
4. The batch is acknowledged with the read position it covers, which is what
   lets the agent advance its checkpoint.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from honeypot_backend.api.schemas import CheckpointInfo, IngestBatch, IngestResponse, RejectedEvent
from honeypot_backend.config import Settings
from honeypot_backend.ingest.dedupe import RecentEventIds
from honeypot_backend.ingest.metrics import IngestMetrics
from honeypot_backend.ingest.spool import EventSpool
from honeypot_backend.normalization import NormalizationError, normalize

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


def _spool(request: Request) -> EventSpool:
    return request.app.state.spool


def _metrics(request: Request) -> IngestMetrics:
    return request.app.state.metrics


def _dedupe(request: Request) -> RecentEventIds:
    return request.app.state.dedupe


def _settings(request: Request) -> Settings:
    return request.app.state.settings


@router.post(
    "/events",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a batch of Cowrie events",
)
def ingest_events(batch: IngestBatch, request: Request) -> IngestResponse:
    """Accept a batch shipped by the ingestion agent.

    The batch is stored durably before it is acknowledged, so an agent that
    retries after a timeout never causes data loss.
    """

    settings = _settings(request)
    if len(batch.events) > settings.max_batch_events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"batch holds {len(batch.events)} events, limit is {settings.max_batch_events}",
        )

    received_at = datetime.now(UTC)
    spool = _spool(request)

    envelope: list[dict[str, Any]] = [
        {
            "ingested_at": received_at.isoformat(),
            "agent_id": batch.agent_id,
            "batch_id": batch.batch_id,
            "sequence": batch.sequence,
            "sent_at": batch.sent_at.isoformat() if batch.sent_at else None,
            "event": event,
        }
        for event in batch.events
    ]
    raw_path = spool.write_raw(envelope)

    normalized_records: list[dict[str, Any]] = []
    rejected: list[RejectedEvent] = []
    event_types: list[str] = []
    source_event_ids: list[str] = []
    duplicates = 0
    dedupe = _dedupe(request)

    for index, event in enumerate(batch.events):
        try:
            normalized = normalize(event, received_at=received_at)
        except NormalizationError as exc:
            logger.warning("batch=%s event=%s rejected: %s", batch.batch_id, index, exc)
            rejected.append(RejectedEvent(index=index, reason=str(exc)[:512]))
            continue

        source_event_ids.append(normalized.source_event_id)
        event_types.append(normalized.event_type)
        if dedupe.is_duplicate(normalized.event_id):
            duplicates += 1
            continue
        normalized_records.append(normalized.to_record())

    normalized_path = spool.write_normalized(normalized_records)

    _metrics(request).record_batch(
        agent_id=batch.agent_id,
        source_event_ids=source_event_ids,
        event_types=event_types,
        normalized=len(normalized_records),
        rejected=len(rejected),
        duplicated=duplicates,
    )

    logger.info(
        "batch=%s agent=%s received=%d normalized=%d duplicates=%d rejected=%d raw=%s normalized_path=%s",
        batch.batch_id,
        batch.agent_id,
        len(batch.events),
        len(normalized_records),
        duplicates,
        len(rejected),
        raw_path,
        normalized_path,
    )

    return IngestResponse(
        batch_id=batch.batch_id,
        received=len(batch.events),
        accepted=len(batch.events) - len(rejected),
        normalized=len(normalized_records),
        duplicates=duplicates,
        rejected=rejected,
        checkpoint=batch.checkpoint,
    )


@router.get("/stats", summary="Ingestion counters and RF-01 event coverage")
def ingest_stats(request: Request) -> dict[str, Any]:
    """Expose ingestion counters, spool state and required event coverage."""

    settings = _settings(request)
    replayer = getattr(request.app.state, "replayer", None)
    return {
        "spool_dir": str(settings.spool_dir),
        "max_batch_events": settings.max_batch_events,
        "metrics": _metrics(request).snapshot(),
        "spool": _spool(request).stats(),
        "dedupe_window_size": len(_dedupe(request)),
        "replayer": replayer.stats() if replayer is not None else None,
    }
