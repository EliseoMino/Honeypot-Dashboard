from honeypot_backend.ingest.metrics import IngestMetrics


def _record(metrics: IngestMetrics, sequence: int) -> None:
    metrics.record_batch(
        agent_id="cowrie-agent",
        received=0,
        source_event_ids=[],
        event_types=[],
        normalized=0,
        rejected=0,
        duplicated=0,
        sequence=sequence,
    )


def test_sequence_gaps_and_replays_are_counted() -> None:
    metrics = IngestMetrics()
    _record(metrics, 1)
    _record(metrics, 4)
    _record(metrics, 3)

    snapshot = metrics.snapshot()
    assert snapshot["sequence_gaps"] == 2
    assert snapshot["sequence_replays"] == 1
    assert snapshot["last_sequence_by_agent"] == {"cowrie-agent": 4}
