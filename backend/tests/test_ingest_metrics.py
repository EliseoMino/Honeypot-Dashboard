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


def test_metrics_and_heartbeat_survive_backend_recreation(tmp_path) -> None:
    state_path = tmp_path / "ingest-health.json"
    first = IngestMetrics(state_path)
    _record(first, 2)
    first.record_heartbeat(
        agent_id="cowrie-agent",
        state={"pending_records": 3, "truncations": 1},
    )

    restored = IngestMetrics(state_path)
    snapshot = restored.snapshot()
    assert snapshot["batches"] == 1
    assert snapshot["last_sequence_by_agent"] == {"cowrie-agent": 2}
    assert snapshot["last_heartbeat_by_agent"]["cowrie-agent"]
    assert snapshot["agent_state"]["cowrie-agent"] == {"pending_records": 3, "truncations": 1}
