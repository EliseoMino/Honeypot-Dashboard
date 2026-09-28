"""The uniform event shape produced by RF-02.

Every Cowrie event, whatever its type, is represented by a single
:class:`NormalizedEvent`, so that later stages (storage, detection, API) can
work with a single schema.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

EventCategory = Literal[
    "session",
    "authentication",
    "command",
    "transfer",
    "client",
    "other",
]

EventOutcome = Literal["success", "failure"]


class NormalizedEvent(BaseModel):
    """A Cowrie event translated to the uniform Honeypot-Dashboard schema.

    Attributes:
        event_id: Deterministic identifier derived from the original payload.
            Used to deduplicate events replayed after an agent restart.
        source: Event source, always ``cowrie`` for now.
        source_event_id: Original Cowrie ``eventid``.
        event_type: Stable dotted type, for example ``auth.login_failed``.
        event_category: Coarse grouping used by the dashboard and detection.
        occurred_at: When the event happened on the honeypot, in UTC.
        received_at: When the backend received the batch, in UTC.
        sensor: Cowrie sensor name (honeypot hostname).
        session_id: Cowrie session identifier, when the event belongs to one.
        source_ip: Attacker IP address.
        source_port: Attacker source port.
        destination_ip: Honeypot IP address.
        destination_port: Honeypot port (SSH or Telnet).
        protocol: ``ssh`` or ``telnet`` when Cowrie reports it.
        username: Username used by the attacker, when the event has one.
        outcome: ``success`` or ``failure`` when the event reports a result.
        details: Event specific fields, with normalized names.
        raw: The original Cowrie payload, kept verbatim for investigation.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str
    source: str
    source_event_id: str
    event_type: str
    event_category: EventCategory
    occurred_at: datetime
    received_at: datetime
    sensor: str | None = None
    session_id: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    outcome: EventOutcome | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        """Return a JSON serializable representation."""

        return self.model_dump(mode="json")
