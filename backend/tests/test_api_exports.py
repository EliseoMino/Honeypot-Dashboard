import pytest
from fastapi import HTTPException

from honeypot_backend.api.exports import _check_export_size, _csv_safe, _safe_event, MAX_EXPORT_ROWS


def test_export_field_allowlist_omits_raw_evidence_and_command_line() -> None:
    row = _safe_event({
        "event_id": "e-1",
        "event_type": "command.input",
        "source_ip": "203.0.113.9",
        "details": {"command_line": "curl secret"},
        "raw": {"password": "secret"},
    })
    assert "raw" not in row
    assert "details" not in row
    assert "command_line" not in row


def test_csv_export_escapes_spreadsheet_formulas() -> None:
    assert _csv_safe("=1+1") == "'=1+1"
    assert _csv_safe("attacker") == "attacker"


def test_export_is_bounded_to_a_reasonable_number_of_rows() -> None:
    _check_export_size(MAX_EXPORT_ROWS)
    with pytest.raises(HTTPException) as error:
        _check_export_size(MAX_EXPORT_ROWS + 1)
    assert error.value.status_code == 413
