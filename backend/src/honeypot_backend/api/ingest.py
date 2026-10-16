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
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from honeypot_backend.api.schemas import CheckpointInfo, IngestBatch, IngestResponse, RejectedEvent
from honeypot_backend.config import Settings
from honeypot_backend.ingest.dedupe import RecentEventIds
from honeypot_backend.ingest.metrics import IngestMetrics
from honeypot_backend.ingest.spool import EventSpool
from honeypot_backend.normalization import NormalizationError, normalize

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


class AgentHeartbeat(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    checkpoint_offset: int = Field(ge=0)
    pending_records: int = Field(ge=0)
    malformed_lines: int = Field(ge=0)
    delivery_failures: int = Field(ge=0)
    log_offset: int = Field(ge=0)
    log_size_bytes: int | None = Field(default=None, ge=0)
    log_inode: int | None = Field(default=None, ge=0)
    rotations: int = Field(ge=0)
    truncations: int = Field(ge=0)


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
        received=len(batch.events),
        source_event_ids=source_event_ids,
        event_types=event_types,
        normalized=len(normalized_records),
        rejected=len(rejected),
        duplicated=duplicates,
        sequence=batch.sequence,
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


@router.post("/heartbeat", status_code=status.HTTP_204_NO_CONTENT, summary="Record agent liveness")
def ingest_heartbeat(body: AgentHeartbeat, request: Request) -> None:
    """Accept an authenticated heartbeat over the same mTLS-only API."""

    _metrics(request).record_heartbeat(
        agent_id=body.agent_id,
        state=body.model_dump(exclude={"agent_id"}),
    )


@router.get("/stats", summary="Ingestion counters and RF-01 event coverage")
def ingest_stats(request: Request) -> dict[str, Any]:
    """Expose ingestion counters, spool state and required event coverage."""

    settings = _settings(request)
    replayer = getattr(request.app.state, "replayer", None)
    spool_path = Path(settings.spool_dir)
    cowrie_dir = Path(os.environ.get("COWRIE_DATA_DIR", "/cowrie/var"))
    cowrie_log = cowrie_dir / "log" / "cowrie" / "cowrie.json"
    spool_files = [path for path in spool_path.rglob("*") if path.is_file()] if spool_path.exists() else []
    cowrie_log_dir = cowrie_dir / "log"
    cowrie_files = (
        [path for path in cowrie_log_dir.rglob("*") if path.is_file()]
        if cowrie_log_dir.exists()
        else []
    )
    try:
        cowrie_log_stat = cowrie_log.stat()
        log_state = {
            "status": "ok",
            "size_bytes": cowrie_log_stat.st_size,
            "modified_at": datetime.fromtimestamp(cowrie_log_stat.st_mtime, UTC).isoformat(),
        }
    except OSError:
        log_state = {"status": "unavailable", "size_bytes": None, "modified_at": None}
    try:
        disk = shutil.disk_usage(spool_path if spool_path.exists() else spool_path.parent)
        disk_state = {"free_bytes": disk.free, "total_bytes": disk.total}
    except OSError:
        disk_state = {"free_bytes": None, "total_bytes": None}
    metrics = _metrics(request).snapshot()
    now = datetime.now(UTC)
    agents = []
    for agent_id, heartbeat in metrics.get("last_heartbeat_by_agent", {}).items():
        seen = datetime.fromisoformat(heartbeat)
        age_seconds = max(0, int((now - seen).total_seconds()))
        agents.append({
            "agent_id": agent_id,
            "last_heartbeat_at": heartbeat,
            "age_seconds": age_seconds,
            "status": "active" if age_seconds <= 90 else "stale",
            **metrics.get("agent_state", {}).get(agent_id, {}),
        })
    return {
        "spool_dir": str(settings.spool_dir),
        "max_batch_events": settings.max_batch_events,
        "metrics": metrics,
        "agents": agents,
        "spool": _spool(request).stats(),
        "dedupe_window_size": len(_dedupe(request)),
        "replayer": replayer.stats() if replayer is not None else None,
        "storage": {
            "spool_bytes": sum(path.stat().st_size for path in spool_files),
            "cowrie_data_bytes": sum(path.stat().st_size for path in cowrie_files),
            "cowrie_log": log_state,
            "filesystem": disk_state,
        },
    }
