"""The pipeline is what turns "read the log" into "the events are stored".

These tests pin the guarantees RF-01 asks for: the checkpoint only moves after
the backend acknowledges, a partial acknowledgement keeps the events for
replay, and a delivery failure never drops anything.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from honeypot_agent.checkpoint import load_checkpoint
from honeypot_agent.config import AgentSettings
from honeypot_agent.pipeline import IngestPipeline
from honeypot_agent.transport import DeliveryError


class FakeClient:
    """Records every batch and answers with a configurable acknowledgement."""

    def __init__(self, *, offset_of: Callable[[dict[str, Any]], int] | None = None) -> None:
        self.sent: list[dict[str, Any]] = []
        self.failures: list[DeliveryError] = []
        self.closed = False
        self._offset_of = offset_of or (lambda payload: payload["checkpoint"]["offset"])

    def send_with_retry(self, payload: dict[str, Any], *, sleep: Callable[[float], None]) -> dict[str, Any]:
        if self.failures:
            raise self.failures.pop(0)
        self.sent.append(payload)
        return {
            "status": "accepted",
            "duplicates": 0,
            "checkpoint": {
                "path": payload["checkpoint"]["path"],
                "offset": self._offset_of(payload),
                "inode": payload["checkpoint"]["inode"],
            },
        }

    def close(self) -> None:
        self.closed = True

    @property
    def events_sent(self) -> list[dict[str, Any]]:
        return [event for batch in self.sent for event in batch["events"]]


@pytest.fixture
def client() -> FakeClient:
    return FakeClient()


def build(settings: AgentSettings, client: FakeClient) -> IngestPipeline:
    return IngestPipeline(settings, client=client, sleep=lambda _: None)


def test_a_batch_is_delivered_and_the_checkpoint_advances(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    end = append(event())
    pipeline = build(settings, client)

    delivered = pipeline.run_once()
    pipeline.shutdown()

    assert delivered == 1
    assert len(client.events_sent) == 1
    assert client.events_sent[0]["eventid"] == "cowrie.session.connect"
    stored = load_checkpoint(settings.checkpoint_path)
    assert stored is not None
    assert stored.offset == end
    assert client.closed is True


def test_no_checkpoint_is_written_while_nothing_has_been_acknowledged(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    """The registry only exists once the backend confirmed the batch."""

    settings.batch_size = 100
    settings.flush_interval = 3600.0  # a batch is not due yet
    append(event())
    pipeline = build(settings, client)

    assert pipeline.run_once() == 0
    assert pipeline.stats.records_read == 1

    assert not settings.checkpoint_path.exists()


def test_a_failed_delivery_keeps_the_events_and_the_checkpoint(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    end = append(event())
    client.failures.append(DeliveryError("backend down", transient=True))
    pipeline = build(settings, client)

    delivered = pipeline.run_once()

    assert delivered == 0
    assert client.sent == []
    assert pipeline.stats.delivery_failures == 1
    stored = load_checkpoint(settings.checkpoint_path)
    assert stored is None or stored.offset == 0
    assert end > 0


def test_the_events_are_retried_on_the_next_round(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    client.failures.append(DeliveryError("backend down", transient=True))
    append(event())
    pipeline = build(settings, client)

    assert pipeline.run_once() == 0
    assert pipeline.run_once() == 1

    assert len(client.events_sent) == 1
    assert pipeline.stats.events_sent == 1


def test_a_permanent_rejection_also_keeps_the_events(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    client.failures.append(DeliveryError("bad batch", transient=False, status_code=422))
    append(event())
    pipeline = build(settings, client)

    assert pipeline.run_once() == 0
    assert pipeline.run_once() == 1

    assert pipeline.stats.rejected_batches == 1
    assert len(client.events_sent) == 1


def test_a_partial_acknowledgement_does_not_advance(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    """If the backend confirms less than the batch, everything is replayed."""

    real_offset = client._offset_of
    shortfall = {"remaining": 1}
    client._offset_of = lambda payload: (
        real_offset(payload) - 1 if shortfall["remaining"] else real_offset(payload)
    )
    append(event())
    append(event())
    pipeline = build(settings, client)

    assert pipeline.run_once() == 0
    assert len(client.events_sent) == 2

    stored = load_checkpoint(settings.checkpoint_path)
    assert stored is None or stored.offset == 0

    shortfall["remaining"] = 0
    assert pipeline.run_once() == 2
    assert pipeline.stats.delivery_failures == 1
    assert pipeline.stats.events_sent == 2


def test_an_acknowledgement_without_a_checkpoint_is_accepted(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    """The offset is a safety net; its absence must not stall the pipeline."""

    class NoCheckpoint(FakeClient):
        def send_with_retry(self, payload: dict[str, Any], *, sleep: Callable[[float], None]) -> dict[str, Any]:
            self.sent.append(payload)
            return {"status": "accepted", "duplicates": 0}

    no_checkpoint = NoCheckpoint()
    append(event())
    pipeline = build(settings, no_checkpoint)

    assert pipeline.run_once() == 1


def test_a_malformed_line_is_skipped_without_stopping_the_batch(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    end = append(event())
    append("{ not json at all")
    end = append(event())
    pipeline = build(settings, client)

    delivered = pipeline.run_once()

    assert delivered == 2
    assert len(client.events_sent) == 2
    assert pipeline.stats.malformed_lines == 1
    stored = load_checkpoint(settings.checkpoint_path)
    assert stored is not None
    assert stored.offset == end


def test_a_json_line_that_is_not_an_object_is_malformed(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    append("[1, 2, 3]")
    pipeline = build(settings, client)

    assert pipeline.run_once() == 0
    assert pipeline.stats.malformed_lines == 1
    assert client.sent == []


def test_a_batch_of_only_garbage_is_never_sent_but_still_advances(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int]
) -> None:
    """The pipeline must not get stuck replaying unparsable lines forever."""

    end = append("{ not json")
    pipeline = build(settings, client)

    assert pipeline.run_once() == 0
    assert client.sent == []

    stored = load_checkpoint(settings.checkpoint_path)
    assert stored is not None
    assert stored.offset == end


def test_blank_lines_are_ignored(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    append("")
    append(event())
    pipeline = build(settings, client)

    assert pipeline.run_once() == 1
    assert pipeline.stats.malformed_lines == 0


def test_the_batch_carries_the_agent_identity_and_a_monotonic_sequence(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    append(event())
    pipeline = build(settings, client)
    pipeline.run_once()

    append(event())
    pipeline.run_once()

    assert [b["sequence"] for b in client.sent] == [0, 1]
    assert all(b["agent_id"] == "test-agent" for b in client.sent)
    assert all(b["batch_id"] for b in client.sent)
    assert len({b["batch_id"] for b in client.sent}) == 2


def test_a_restart_continues_the_sequence_from_the_checkpoint(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    append(event())
    first = build(settings, client)
    first.run_once()
    first.shutdown()

    append(event())
    second = build(settings, client)
    second.run_once()

    assert [b["sequence"] for b in client.sent] == [0, 1]


def test_a_batch_is_split_at_the_configured_size(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    settings.batch_size = 2
    for _ in range(5):
        append(event())
    pipeline = build(settings, client)

    sent = 0
    for _ in range(5):
        sent += pipeline.run_once()

    assert [len(b["events"]) for b in client.sent] == [2, 2, 1]
    assert sent == 5


def test_reads_pause_while_too_many_events_wait_for_delivery(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    """Back pressure: a dead backend must not grow the agent's memory."""

    settings.max_pending_records = 2
    settings.batch_size = 10
    client.failures.append(DeliveryError("backend down", transient=True))
    for _ in range(5):
        append(event())
    pipeline = build(settings, client)

    assert pipeline.run_once() == 0  # the batch is kept
    reads_before = pipeline.stats.records_read

    assert pipeline.run_once() == 0  # back pressure kicks in, nothing is read
    assert pipeline.stats.records_read == reads_before
    assert len(client.sent) == 0


def test_shutdown_flushes_what_is_still_buffered(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    settings.batch_size = 100
    settings.flush_interval = 3600.0  # a batch is not due yet
    append(event())
    pipeline = build(settings, client)

    assert pipeline.run_once() == 0
    assert client.sent == []

    pipeline.shutdown()

    assert len(client.events_sent) == 1
    assert client.closed is True


def test_the_events_sent_match_the_log_content(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    first = json.loads(event())
    second = json.loads(event(eventid="cowrie.login.failed", username="root"))
    append(json.dumps(first))
    append(json.dumps(second))
    pipeline = build(settings, client)

    pipeline.run_once()

    assert client.events_sent == [first, second]


def test_the_reported_statistics_add_up(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    for _ in range(3):
        append(event())
    pipeline = build(settings, client)

    pipeline.run_once()

    stats = pipeline.stats.snapshot()
    assert stats["records_read"] == 3
    assert stats["events_sent"] == 3
    assert stats["batches_sent"] == 1
    assert stats["malformed_lines"] == 0
    assert stats["delivery_failures"] == 0
    assert stats["rotations"] == 0
    assert stats["truncations"] == 0


def test_lost_events_from_a_truncation_reach_the_reported_statistics(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    """A truncation has to be visible in the stats, not only in the log.

    It is the only signal that events existed but were destroyed before the
    agent could ship them, so it cannot stay buried in a log line.
    """

    append(event())
    pipeline = build(settings, client)
    pipeline.run_once()

    settings.cowrie_log_path.write_bytes(b"")
    pipeline.run_once()

    stats = pipeline.stats.snapshot()
    assert stats["truncations"] == 1
    assert stats["rotations"] == 0


def test_requesting_a_stop_finishes_the_current_batch(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    settings.batch_size = 100
    settings.flush_interval = 3600.0  # a batch is not due yet
    append(event())
    pipeline = build(settings, client)
    assert pipeline.run_once() == 0  # read, but held back
    assert client.sent == []

    pipeline.request_stop()
    pipeline.run_forever()

    assert len(client.events_sent) == 1
    assert client.closed is True


def test_stopping_before_reading_keeps_the_events_for_the_next_start(
    settings: AgentSettings, client: FakeClient, append: Callable[..., int], event: Callable[..., str]
) -> None:
    """A stop that arrives first must not skip unread lines."""

    append(event())
    pipeline = build(settings, client)

    pipeline.request_stop()
    pipeline.run_forever()

    assert client.sent == []
    assert not settings.checkpoint_path.exists()

    restarted = build(settings, client)
    assert restarted.run_once() == 1
