"""The agent main loop: tail, batch, deliver, checkpoint.

Guarantees:

- **No loss.** The checkpoint only advances after the backend acknowledges the
  batch that covers it.
- **At least once.** A crash between the acknowledgement and the checkpoint
  write replays one batch; the backend removes the repeats through the
  deterministic ``event_id``.
- **Back pressure.** When the backend is unreachable the agent stops reading
  new lines instead of growing its memory, so Cowrie keeps appending to
  ``cowrie.json`` and nothing is discarded.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from honeypot_agent.checkpoint import Checkpoint, load_checkpoint, save_checkpoint
from honeypot_agent.config import AgentSettings, get_agent_settings
from honeypot_agent.tailer import CowrieLogTailer, TailRecord
from honeypot_agent.transport import DeliveryError, IngestClient

logger = logging.getLogger(__name__)


class Tailer(Protocol):
    def poll(self) -> list[TailRecord]: ...

    @property
    def offset(self) -> int: ...

    @property
    def inode(self) -> int | None: ...

    @property
    def path(self) -> Any: ...


class Stats:
    """Counters logged periodically and on shutdown."""

    def __init__(self) -> None:
        self.records_read = 0
        self.events_sent = 0
        self.batches_sent = 0
        self.malformed_lines = 0
        self.delivery_failures = 0
        self.rejected_batches = 0

    def snapshot(self) -> dict[str, int]:
        return dict(self.__dict__)


class IngestPipeline:
    """Read new Cowrie events and ship them to the backend."""

    def __init__(
        self,
        settings: AgentSettings,
        *,
        tailer: Tailer | None = None,
        client: IngestClient | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._sleep = sleep
        self._monotonic = monotonic
        self._checkpoint = load_checkpoint(settings.checkpoint_path)
        self._tailer: Tailer = tailer or CowrieLogTailer(
            settings.cowrie_log_path,
            self._checkpoint,
            start_at_end=settings.start_at_end,
        )
        self._client = client or IngestClient(settings)
        self._pending: list[TailRecord] = []
        self._first_pending_at: float | None = None
        self._sequence = (self._checkpoint.sequence or 0) if self._checkpoint else 0
        self._stopping = False
        self.stats = Stats()

    @property
    def checkpoint(self) -> Checkpoint:
        return self._checkpoint or Checkpoint(path=str(self._settings.cowrie_log_path))

    def request_stop(self) -> None:
        """Ask the loop to finish the current batch and exit."""

        self._stopping = True

    def run_forever(self) -> None:
        """Poll, deliver and checkpoint until asked to stop."""

        logger.info(
            "agent %s started: log=%s backend=%s batch_size=%d",
            self._settings.agent_id,
            self._settings.cowrie_log_path,
            self._settings.backend_url,
            self._settings.batch_size,
        )
        try:
            while not self._stopping:
                self.run_once()
                self._sleep(self._settings.poll_interval)
        finally:
            self.shutdown()

    def run_once(self) -> int:
        """Read what is available and deliver a batch if one is due.

        Returns:
            The number of events included in the delivered batch, ``0`` when
            nothing was sent.
        """

        if len(self._pending) >= self._settings.max_pending_records:
            logger.warning(
                "%d events are still pending delivery, pausing reads of %s",
                len(self._pending),
                self._settings.cowrie_log_path,
            )
            self._sleep(self._settings.reject_backoff)
            return 0

        records = self._tailer.poll()
        if records:
            if self._first_pending_at is None:
                self._first_pending_at = self._monotonic()
            self._pending.extend(records)
            self.stats.records_read += len(records)

        if not self._pending or not self._batch_due():
            return 0
        return self._flush()

    def shutdown(self) -> None:
        """Deliver what is still buffered and persist the checkpoint."""

        if self._pending:
            logger.info("flushing %d buffered events before shutdown", len(self._pending))
            self._flush()
        self._client.close()
        logger.info("agent stopped: %s", self.stats.snapshot())

    def _batch_due(self) -> bool:
        if len(self._pending) >= self._settings.batch_size:
            return True
        if self._first_pending_at is None:
            return False
        return self._monotonic() - self._first_pending_at >= self._settings.flush_interval

    def _flush(self) -> int:
        batch = self._pending[: self._settings.batch_size]
        end = batch[-1]
        events, malformed = _decode(batch)
        self.stats.malformed_lines += malformed
        if malformed:
            logger.warning("skipped %d unparsable line(s) in %s", malformed, self._tailer.path)

        next_checkpoint = Checkpoint(
            path=str(self._settings.cowrie_log_path),
            offset=end.offset,
            inode=self._tailer.inode,
            sequence=self._sequence + 1,
        )

        if not events:
            self._advance(batch, next_checkpoint)
            return 0

        payload = {
            "agent_id": self._settings.agent_id,
            "batch_id": uuid.uuid4().hex,
            "sequence": self._sequence,
            "sent_at": datetime.now(UTC).isoformat(),
            "checkpoint": {
                "path": next_checkpoint.path,
                "offset": next_checkpoint.offset,
                "inode": next_checkpoint.inode,
            },
            "events": events,
        }

        try:
            acknowledgement = self._client.send_with_retry(payload, sleep=self._sleep)
        except DeliveryError as exc:
            self._retain(batch, exc)
            return 0

        acknowledged = _acknowledged_offset(acknowledgement)
        if acknowledged is not None and acknowledged < end.offset:
            logger.error(
                "backend acknowledged offset %d but the batch ends at %d, keeping events for replay",
                acknowledged,
                end.offset,
            )
            self._retain(batch, DeliveryError("partial acknowledgement", transient=True))
            return 0

        self._advance(batch, next_checkpoint)
        logger.info(
            "delivered batch=%s events=%d offset=%d duplicates=%s",
            payload["batch_id"],
            len(events),
            end.offset,
            acknowledgement.get("duplicates"),
        )
        return len(events)

    def _advance(self, batch: list[TailRecord], checkpoint: Checkpoint) -> None:
        del self._pending[: len(batch)]
        if not self._pending:
            self._first_pending_at = None
        self._sequence += 1
        self.stats.batches_sent += 1
        self.stats.events_sent += len(batch)
        self._checkpoint = checkpoint
        save_checkpoint(self._settings.checkpoint_path, checkpoint)

    def _retain(self, batch: list[TailRecord], error: DeliveryError) -> None:
        if error.transient:
            self.stats.delivery_failures += 1
            self._sleep(self._settings.reject_backoff)
        else:
            self.stats.rejected_batches += 1
            logger.error("batch rejected by the backend, retrying later: %s", error)
            self._sleep(self._settings.reject_backoff)


def _decode(batch: list[TailRecord]) -> tuple[list[dict[str, Any]], int]:
    events: list[dict[str, Any]] = []
    malformed = 0
    for record in batch:
        if not record.text:
            continue
        try:
            payload = json.loads(record.text)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if isinstance(payload, dict):
            events.append(payload)
        else:
            malformed += 1
    return events, malformed


def _acknowledged_offset(acknowledgement: dict[str, Any]) -> int | None:
    checkpoint = acknowledgement.get("checkpoint")
    if not isinstance(checkpoint, dict):
        return None
    offset = checkpoint.get("offset")
    return offset if isinstance(offset, int) else None


def build_pipeline(settings: AgentSettings | None = None) -> IngestPipeline:
    """Create the pipeline from settings."""

    return IngestPipeline(settings or get_agent_settings())
