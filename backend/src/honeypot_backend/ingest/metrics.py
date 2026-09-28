"""Ingestion counters, including RF-01 event type coverage."""

from __future__ import annotations

import threading
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from honeypot_backend.normalization import REQUIRED_EVENT_IDS


class IngestMetrics:
    """Thread safe counters for the ingestion endpoint."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_at = datetime.now(UTC)
        self._batches = 0
        self._events_received = 0
        self._events_normalized = 0
        self._events_rejected = 0
        self._events_duplicated = 0
        self._event_ids: Counter[str] = Counter()
        self._event_types: Counter[str] = Counter()
        self._last_batch_at: datetime | None = None
        self._last_agent_id: str | None = None

    def record_batch(
        self,
        *,
        agent_id: str,
        source_event_ids: list[str],
        event_types: list[str],
        normalized: int,
        rejected: int,
        duplicated: int,
    ) -> None:
        with self._lock:
            self._batches += 1
            self._events_received += len(source_event_ids)
            self._events_normalized += normalized
            self._events_rejected += rejected
            self._events_duplicated += duplicated
            self._event_ids.update(source_event_ids)
            self._event_types.update(event_types)
            self._last_batch_at = datetime.now(UTC)
            self._last_agent_id = agent_id

    def coverage(self) -> dict[str, bool]:
        """Whether each RF-01 required event type has been observed."""

        with self._lock:
            seen = set(self._event_ids)
        return {event_id: event_id in seen for event_id in sorted(REQUIRED_EVENT_IDS)}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            coverage = {
                event_id: event_id in self._event_ids for event_id in sorted(REQUIRED_EVENT_IDS)
            }
            return {
                "started_at": self._started_at.isoformat(),
                "last_batch_at": self._last_batch_at.isoformat() if self._last_batch_at else None,
                "last_agent_id": self._last_agent_id,
                "batches": self._batches,
                "events_received": self._events_received,
                "events_normalized": self._events_normalized,
                "events_rejected": self._events_rejected,
                "events_duplicated": self._events_duplicated,
                "top_event_ids": self._event_ids.most_common(20),
                "event_type_counts": dict(self._event_types),
                "required_event_coverage": coverage,
                "missing_required_event_ids": sorted(
                    event_id for event_id, present in coverage.items() if not present
                ),
            }
