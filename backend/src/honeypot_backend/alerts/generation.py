"""Turning detections into alerts (RF-12).

An alert is raised when a rule of RF-11 matches, and it is raised from the
stored detection, not from the finding in memory: the detection carries the
fingerprint that makes it unique, and the alert points at it. Together they give
the property RF-12 asks for, that evaluating the same activity again does not
produce a second alert, because both the detection and the alert are
deduplicated by the database (``fingerprint`` and ``detection_id``).

The severity is the one the rule declares, so a rule is what decides how
serious a match is. The evidence of the detection is copied into the alert, so
an operator can investigate an alert without reading the detection first, and
the events that triggered it are identified in that evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from honeypot_backend.detection.rules import DEFAULT_SEVERITY, RulesFile


@dataclass(frozen=True, slots=True)
class AlertDraft:
    """The columns of an alert, before it is stored."""

    detection_id: int
    alert_type: str
    severity: str
    rule_id: str
    title: str
    description: str
    source_ip: str | None
    session_id: str | None
    occurred_from: str
    occurred_to: str
    event_count: int
    evidence: dict[str, Any]

    def to_record(self) -> dict[str, Any]:
        """Return the columns of the ``alerts`` table."""

        return {
            "detection_id": self.detection_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "session_id": self.session_id,
            "occurred_from": self.occurred_from,
            "occurred_to": self.occurred_to,
            "event_count": self.event_count,
            "evidence": self.evidence,
        }


def draft_for_detection(detection: dict[str, Any], rules: RulesFile) -> AlertDraft:
    """Return the alert to raise for a stored detection.

    Args:
        detection: A stored detection, as the detection repository returns it.
        rules: The rule configuration, read for the severity and the
            description of the rule that produced the detection.
    """

    rule = rules.by_id(str(detection["rule_id"]))
    return AlertDraft(
        detection_id=int(detection["id"]),
        # The kind of the rule is the type of the alert: it is stable, and it is
        # what a consumer groups by.
        alert_type=str(detection["rule_kind"]),
        severity=rule.severity if rule is not None else DEFAULT_SEVERITY,
        rule_id=str(detection["rule_id"]),
        title=str(detection["title"]),
        description=(rule.description.strip() if rule is not None else ""),
        source_ip=detection["source_ip"],
        session_id=detection["session_id"],
        occurred_from=_as_datetime(detection["occurred_from"]),
        occurred_to=_as_datetime(detection["occurred_to"]),
        event_count=int(detection["event_count"]),
        evidence=dict(detection["evidence"] or {}),
    )


def drafts_for_detections(
    detections: list[dict[str, Any]], rules: RulesFile
) -> list[AlertDraft]:
    """Return the alerts to raise for a list of stored detections."""

    return [draft_for_detection(detection, rules) for detection in detections]


def _as_datetime(value: Any) -> datetime:
    """Accept both a timestamp from PostgreSQL and an ISO 8601 string."""

    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))
