from honeypot_backend.api.events import _mask_sensitive
from honeypot_backend.api.safe_output import safe_evidence


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
