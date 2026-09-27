"""Evaluation of the detection rules over the stored events (RF-11).

The engine is deliberately boring: each rule reads the events of the requested
window and returns a list of findings, with no state between calls. That is
what RF-11 asks for (explicit and deterministic rules) and it is also what
makes a repeated run safe, because every finding carries a deterministic
fingerprint that the storage layer deduplicates.

Three rule kinds are implemented, the minimum the MVP asks for:

``auth_threshold``
    Several authentication attempts from the same source IP inside a period.
``command_of_interest``
    A command line that invoked one of the configured executables.
``file_transfer``
    A file the honeypot was asked to download or to send.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.db.models import Event
from honeypot_backend.detection.matching import invoked_commands
from honeypot_backend.detection.rules import (
    AuthThresholdRule,
    CommandOfInterestRule,
    FileTransferRule,
    RulesFile,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Detection:
    """One rule matching, before it is stored."""

    rule_id: str
    rule_kind: str
    title: str
    occurred_from: datetime
    occurred_to: datetime
    event_count: int
    evidence: dict[str, Any]
    severity: str = "medium"
    source_ip: str | None = None
    session_id: str | None = None
    fingerprint: str = ""

    def to_record(self) -> dict[str, Any]:
        """Return the columns of the ``detections`` table."""

        return {
            "rule_id": self.rule_id,
            "rule_kind": self.rule_kind,
            "title": self.title,
            "source_ip": self.source_ip,
            "session_id": self.session_id,
            "occurred_from": self.occurred_from,
            "occurred_to": self.occurred_to,
            "event_count": self.event_count,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint
            or detection_fingerprint(
                [
                    self.rule_id,
                    self.source_ip,
                    self.session_id,
                    self.occurred_from.isoformat(),
                    self.occurred_to.isoformat(),
                ]
            ),
        }


def detection_fingerprint(parts: Iterable[str | None]) -> str:
    """Return a stable fingerprint for the identity of a finding.

    The parts are the rule and whatever identifies the subject of the finding.
    Two runs over the same data produce the same fingerprint, so the storage
    layer can ignore the finding it already recorded.
    """

    canonical = json.dumps([part for part in parts], separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DetectionRule(Protocol):
    """What every rule implementation provides."""

    spec: Any

    async def detect(
        self,
        session: AsyncSession,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[Detection]: ...


@dataclass(frozen=True, slots=True)
class _EventRow:
    """The columns the rules read from an event."""

    event_id: str
    occurred_at: datetime
    source_ip: str | None
    session_id: str | None
    username: str | None
    event_type: str
    details: dict[str, Any]


async def _read_events(
    session: AsyncSession,
    *,
    occurred_from: datetime,
    occurred_to: datetime,
    event_types: Sequence[str] | None = None,
    categories: Sequence[str] | None = None,
    require_source_ip: bool = False,
) -> list[_EventRow]:
    """Read the events of a window, in the order the rules need them."""

    statement = select(
        Event.event_id,
        Event.occurred_at,
        Event.source_ip,
        Event.session_id,
        Event.username,
        Event.event_type,
        Event.details,
    ).where(Event.occurred_at >= occurred_from, Event.occurred_at <= occurred_to)

    if event_types:
        statement = statement.where(Event.event_type.in_(tuple(event_types)))
    if categories:
        statement = statement.where(Event.event_category.in_(tuple(categories)))
    if require_source_ip:
        statement = statement.where(Event.source_ip.is_not(None))

    statement = statement.order_by(Event.occurred_at, Event.event_id)
    rows = (await session.execute(statement)).all()
    return [
        _EventRow(
            event_id=row[0],
            occurred_at=row[1],
            source_ip=str(row[2]) if row[2] is not None else None,
            session_id=row[3],
            username=row[4],
            event_type=row[5],
            details=row[6] or {},
        )
        for row in rows
    ]


def _single_session(rows: Sequence[_EventRow]) -> str | None:
    """Return the session shared by every row, or ``None`` when they differ."""

    sessions = {row.session_id for row in rows if row.session_id is not None}
    return sessions.pop() if len(sessions) == 1 else None


@dataclass(frozen=True, slots=True)
class AuthThresholdRuleEvaluator:
    """Several authentication attempts from one IP inside the period."""

    spec: AuthThresholdRule

    async def detect(
        self,
        session: AsyncSession,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[Detection]:
        rows = await _read_events(
            session,
            occurred_from=occurred_from,
            occurred_to=occurred_to,
            event_types=self.spec.event_types,
            require_source_ip=True,
        )
        by_ip: dict[str, list[_EventRow]] = {}
        for row in rows:
            if row.source_ip is not None:
                by_ip.setdefault(row.source_ip, []).append(row)

        detections: list[Detection] = []
        for source_ip, attempts in sorted(by_ip.items()):
            detections.extend(self._bursts(source_ip, attempts))
        return detections

    def _bursts(self, source_ip: str, attempts: list[_EventRow]) -> list[Detection]:
        """Group the attempts of one IP into bursts and report the big ones."""

        window = self.spec.window
        found: list[Detection] = []
        index = 0
        while index < len(attempts):
            # The window starts on the first attempt that is not covered yet, so
            # the same burst always produces the same window.
            start = attempts[index].occurred_at
            limit = start + window
            end = index
            while end < len(attempts) and attempts[end].occurred_at < limit:
                end += 1
            burst = attempts[index:end]
            index = end

            if len(burst) < self.spec.threshold:
                continue

            ids = [row.event_id for row in burst]
            truncated = len(ids) > self.spec.max_evidence_events
            found.append(
                Detection(
                    rule_id=self.spec.id,
                    rule_kind=self.spec.kind,
                    title=self.spec.title,
                    severity=self.spec.severity,
                    source_ip=source_ip,
                    session_id=_single_session(burst),
                    occurred_from=start,
                    occurred_to=burst[-1].occurred_at,
                    event_count=len(ids),
                    evidence={
                        "event_ids": ids[: self.spec.max_evidence_events],
                        "event_ids_truncated": truncated,
                        "threshold": self.spec.threshold,
                        "window_seconds": self.spec.window_seconds,
                        "usernames": sorted({row.username for row in burst if row.username}),
                        "sessions": sorted(
                            {row.session_id for row in burst if row.session_id is not None}
                        ),
                    },
                    # A burst is identified by where it started, so a later run
                    # over the same burst does not store it twice.
                    fingerprint=detection_fingerprint(
                        ["burst", self.spec.id, source_ip, start.isoformat()]
                    ),
                )
            )
        return found


@dataclass(frozen=True, slots=True)
class CommandOfInterestRuleEvaluator:
    """A command line that invoked a command of interest."""

    spec: CommandOfInterestRule

    async def detect(
        self,
        session: AsyncSession,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[Detection]:
        rows = await _read_events(
            session,
            occurred_from=occurred_from,
            occurred_to=occurred_to,
            event_types=self.spec.event_types,
            categories=["command"],
        )
        interest = self.spec.interest

        detections: list[Detection] = []
        for row in rows:
            command_line = _command_line(row.details)
            matched = sorted(set(invoked_commands(command_line)) & interest)
            if not matched:
                continue

            detections.append(
                Detection(
                    rule_id=self.spec.id,
                    rule_kind=self.spec.kind,
                    title=self.spec.title,
                    severity=self.spec.severity,
                    source_ip=row.source_ip,
                    session_id=row.session_id,
                    occurred_from=row.occurred_at,
                    occurred_to=row.occurred_at,
                    event_count=1,
                    evidence={
                        "event_ids": [row.event_id],
                        "event_id": row.event_id,
                        "event_type": row.event_type,
                        "command_line": command_line,
                        "matched_commands": matched,
                        "username": row.username,
                    },
                    fingerprint=detection_fingerprint([self.spec.id, row.event_id]),
                )
            )
        return detections


@dataclass(frozen=True, slots=True)
class FileTransferRuleEvaluator:
    """A file the honeypot was asked to download or to send."""

    spec: FileTransferRule

    async def detect(
        self,
        session: AsyncSession,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[Detection]:
        rows = await _read_events(
            session,
            occurred_from=occurred_from,
            occurred_to=occurred_to,
            event_types=self.spec.event_types,
            categories=["transfer"],
        )

        detections: list[Detection] = []
        for row in rows:
            detections.append(
                Detection(
                    rule_id=self.spec.id,
                    rule_kind=self.spec.kind,
                    title=self.spec.title,
                    severity=self.spec.severity,
                    source_ip=row.source_ip,
                    session_id=row.session_id,
                    occurred_from=row.occurred_at,
                    occurred_to=row.occurred_at,
                    event_count=1,
                    evidence={
                        "event_ids": [row.event_id],
                        "event_id": row.event_id,
                        "event_type": row.event_type,
                        # Only the attributes Cowrie reported are recorded.
                        **{key: row.details[key] for key in TRANSFER_FIELDS if key in row.details},
                        "username": row.username,
                    },
                    fingerprint=detection_fingerprint([self.spec.id, row.event_id]),
                )
            )
        return detections


#: Transfer attributes worth keeping as evidence of a download.
TRANSFER_FIELDS = ("url", "outfile", "filename", "destfile", "sha256", "md5", "error", "duplicate")


def _command_line(details: dict[str, Any]) -> str | None:
    """Return the command line of a command event, however it was stored."""

    for key in ("command_line", "input", "command"):
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


_EVALUATORS: dict[str, Any] = {
    "auth_threshold": AuthThresholdRuleEvaluator,
    "command_of_interest": CommandOfInterestRuleEvaluator,
    "file_transfer": FileTransferRuleEvaluator,
}


class DetectionEngine:
    """Evaluates a set of rules over the stored events."""

    def __init__(self, rules: RulesFile | None = None) -> None:
        self._rules: tuple[DetectionRule, ...] = tuple(
            _EVALUATORS[rule.kind](spec=rule) for rule in (rules.rules if rules else ())
        )

    @property
    def rule_count(self) -> int:
        """How many rules the engine will evaluate."""

        return len(self._rules)

    @property
    def rules(self) -> tuple[DetectionRule, ...]:
        """The instantiated rules, in configuration order."""

        return self._rules

    async def run(
        self,
        session: AsyncSession,
        *,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[Detection]:
        """Evaluate every rule over a window of events.

        Findings are returned sorted by time and rule, so two runs over the same
        data produce the same list in the same order.
        """

        found: list[Detection] = []
        for rule in self._rules:
            detections = await rule.detect(session, occurred_from, occurred_to)
            logger.debug(
                "rule %s found %d detection(s) between %s and %s",
                rule.spec.id,
                len(detections),
                occurred_from.isoformat(),
                occurred_to.isoformat(),
            )
            found.extend(detections)

        return sorted(found, key=lambda item: (item.occurred_from, item.rule_id, item.fingerprint))
