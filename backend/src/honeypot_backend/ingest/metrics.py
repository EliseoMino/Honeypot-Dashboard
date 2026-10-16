"""Ingestion counters, including RF-01 event type coverage."""

from __future__ import annotations

import threading
import json
import os
import logging
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from honeypot_backend.normalization import REQUIRED_EVENT_IDS

logger = logging.getLogger(__name__)


class IngestMetrics:
    """Thread safe counters for the ingestion endpoint."""

    def __init__(self, state_path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._state_path = state_path
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
        self._last_sequence_by_agent: dict[str, int] = {}
        self._sequence_gaps = 0
        self._sequence_replays = 0
        self._last_heartbeat_by_agent: dict[str, str] = {}
        self._agent_state: dict[str, dict[str, Any]] = {}
        self._load()

    def record_batch(
        self,
        *,
        agent_id: str,
        received: int,
        source_event_ids: list[str],
        event_types: list[str],
        normalized: int,
        rejected: int,
        duplicated: int,
        sequence: int | None = None,
    ) -> None:
        with self._lock:
            self._batches += 1
            self._events_received += received
            self._events_normalized += normalized
            self._events_rejected += rejected
            self._events_duplicated += duplicated
            self._event_ids.update(source_event_ids)
            self._event_types.update(event_types)
            self._last_batch_at = datetime.now(UTC)
            self._last_agent_id = agent_id
            if sequence is not None:
                previous = self._last_sequence_by_agent.get(agent_id)
                if previous is not None:
                    if sequence > previous + 1:
                        self._sequence_gaps += sequence - previous - 1
                    elif sequence <= previous:
                        self._sequence_replays += 1
                self._last_sequence_by_agent[agent_id] = max(previous or 0, sequence)
            self._persist_unlocked()

    def record_heartbeat(self, *, agent_id: str, state: dict[str, Any] | None = None) -> None:
        """Persist a recent liveness signal from the tailing agent."""

        with self._lock:
            self._last_heartbeat_by_agent[agent_id] = datetime.now(UTC).isoformat()
            self._agent_state[agent_id] = state or {}
            self._persist_unlocked()

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
                "last_heartbeat_by_agent": dict(self._last_heartbeat_by_agent),
                "agent_state": dict(self._agent_state),
                "last_sequence_by_agent": dict(self._last_sequence_by_agent),
                "sequence_gaps": self._sequence_gaps,
                "sequence_replays": self._sequence_replays,
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

    def _load(self) -> None:
        if self._state_path is None:
            return
        try:
            state = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return
        if not isinstance(state, dict):
            return
        self._batches = int(state.get("batches", 0))
        self._events_received = int(state.get("events_received", 0))
        self._events_normalized = int(state.get("events_normalized", 0))
        self._events_rejected = int(state.get("events_rejected", 0))
        self._events_duplicated = int(state.get("events_duplicated", 0))
        self._event_ids.update(state.get("event_ids", {}))
        self._event_types.update(state.get("event_types", {}))
        self._last_batch_at = _parse_time(state.get("last_batch_at"))
        self._last_agent_id = state.get("last_agent_id")
        self._last_sequence_by_agent.update(state.get("last_sequence_by_agent", {}))
        self._sequence_gaps = int(state.get("sequence_gaps", 0))
        self._sequence_replays = int(state.get("sequence_replays", 0))
        self._last_heartbeat_by_agent.update(state.get("last_heartbeat_by_agent", {}))
        self._agent_state.update(state.get("agent_state", {}))

    def _persist_unlocked(self) -> None:
        if self._state_path is None:
            return
        state = {
            "batches": self._batches,
            "events_received": self._events_received,
            "events_normalized": self._events_normalized,
            "events_rejected": self._events_rejected,
            "events_duplicated": self._events_duplicated,
            "event_ids": dict(self._event_ids),
            "event_types": dict(self._event_types),
            "last_batch_at": self._last_batch_at.isoformat() if self._last_batch_at else None,
            "last_agent_id": self._last_agent_id,
            "last_sequence_by_agent": self._last_sequence_by_agent,
            "sequence_gaps": self._sequence_gaps,
            "sequence_replays": self._sequence_replays,
            "last_heartbeat_by_agent": self._last_heartbeat_by_agent,
            "agent_state": self._agent_state,
        }
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
        try:
            temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
            os.replace(temporary, self._state_path)
        except OSError as exc:
            logger.warning("could not persist ingestion health state: %s", exc)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
