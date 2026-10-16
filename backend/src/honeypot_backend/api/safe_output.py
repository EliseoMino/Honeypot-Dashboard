"""Small allowlists for evidence returned by general API views."""

from __future__ import annotations

from typing import Any

SAFE_EVIDENCE_KEYS = frozenset(
    {
        "event_ids",
        "event_id",
        "event_type",
        "event_ids_truncated",
        "threshold",
        "window_seconds",
        "matched_commands",
        "sessions",
        "usernames",
        "attack_mapping",
    }
)


def safe_evidence(evidence: dict[str, Any] | None) -> dict[str, Any]:
    """Return rule context that cannot include raw command or credential text."""

    return {key: value for key, value in (evidence or {}).items() if key in SAFE_EVIDENCE_KEYS}
