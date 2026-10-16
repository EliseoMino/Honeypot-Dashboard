from datetime import UTC, datetime
from types import SimpleNamespace

from honeypot_backend.api.events import _event_detail_payload, _mask_sensitive
from honeypot_backend.api.safe_output import safe_evidence
from honeypot_backend.db.repository import EventRepository


def test_sensitive_event_fields_are_masked_recursively() -> None:
    value = {
        "password": "captured-password",
        "command_line": "curl --user admin:captured-password host",
        "nested": [{"token": "captured-token", "event_type": "auth.login_failed"}],
    }

    assert _mask_sensitive(value) == {
        "password": "[REDACTED]",
        "command_line": "[REDACTED]",
        "nested": [{"token": "[REDACTED]", "event_type": "auth.login_failed"}],
    }


def test_general_detection_evidence_excludes_command_and_transfer_payloads() -> None:
    evidence = {
        "event_ids": ["event-1"],
        "matched_commands": ["curl"],
        "command_line": "curl --user admin:secret https://host/file",
        "url": "https://admin:secret@host/file",
        "threshold": 5,
    }

    assert safe_evidence(evidence) == {
        "event_ids": ["event-1"],
        "matched_commands": ["curl"],
        "threshold": 5,
    }


def test_event_detail_redaction_does_not_mutate_the_frozen_model() -> None:
    event = {
        "event_id": "event-1",
        "source": "cowrie",
        "source_event_id": "cowrie.login.failed",
        "event_type": "auth.login_failed",
        "event_category": "authentication",
        "occurred_at": datetime(2026, 10, 16, tzinfo=UTC),
        "received_at": datetime(2026, 10, 16, tzinfo=UTC),
        "details": {"password": "captured-value", "username": "root"},
        "raw": {"password": "captured-value"},
    }

    payload = _event_detail_payload(event, include_sensitive=False)

    assert payload["details"] == {"password": "[REDACTED]", "username": "root"}
    assert payload["raw"] == {}
    assert event["details"]["password"] == "captured-value"


def test_event_detail_can_explicitly_include_sensitive_evidence() -> None:
    event = {
        "event_id": "event-1",
        "source": "cowrie",
        "source_event_id": "cowrie.login.failed",
        "event_type": "auth.login_failed",
        "event_category": "authentication",
        "occurred_at": datetime(2026, 10, 16, tzinfo=UTC),
        "received_at": datetime(2026, 10, 16, tzinfo=UTC),
        "details": {"password": "captured-value"},
        "raw": {"password": "captured-value"},
    }

    payload = _event_detail_payload(event, include_sensitive=True)

    assert payload["details"]["password"] == "captured-value"
    assert payload["raw"]["password"] == "captured-value"


def test_command_list_row_never_returns_the_full_command_line() -> None:
    row = SimpleNamespace(
        event_id="event-1",
        event_type="command.input",
        occurred_at=datetime(2026, 10, 16, tzinfo=UTC),
        source_ip="203.0.113.10",
        session_id="session-1",
        username="root",
        outcome=None,
        command="wget",
        command_line="wget --password captured-value https://example.test/file",
    )

    safe = EventRepository._command_row(row)

    assert safe["command"] == "wget"
    assert safe["command_line"] is None
