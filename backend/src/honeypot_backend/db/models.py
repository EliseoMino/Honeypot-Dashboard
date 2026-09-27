"""SQLAlchemy models for the stored events, detections and alerts.

Common attributes are promoted to real columns so that they can be filtered,
ordered and aggregated by the database. Everything event specific lives in the
``details`` JSONB column, and the original Cowrie payload is kept in ``raw``
for investigation (RF-14).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base of the Honeypot-Dashboard schema."""


class Event(Base):
    """A normalized Cowrie event."""

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_events_event_id"),
        Index("ix_events_occurred_at", "occurred_at"),
        Index("ix_events_source_ip", "source_ip"),
        Index("ix_events_event_type", "event_type"),
        Index("ix_events_session_id", "session_id"),
        Index("ix_events_event_category", "event_category"),
        Index("ix_events_session_occurred_at", "session_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    event_category: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sensor: Mapped[str | None] = mapped_column(String(256))
    session_id: Mapped[str | None] = mapped_column(String(128))
    source_ip: Mapped[Any | None] = mapped_column(INET)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[Any | None] = mapped_column(INET)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    username: Mapped[str | None] = mapped_column(String(256))
    outcome: Mapped[str | None] = mapped_column(String(16))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON serializable representation."""

        return {
            "event_id": self.event_id,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "event_type": self.event_type,
            "event_category": self.event_category,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "sensor": self.sensor,
            "session_id": self.session_id,
            "source_ip": str(self.source_ip) if self.source_ip is not None else None,
            "source_port": self.source_port,
            "destination_ip": str(self.destination_ip) if self.destination_ip is not None else None,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": self.username,
            "outcome": self.outcome,
            "details": self.details or {},
            "raw": self.raw or {},
        }


class SpoolCursor(Base):
    """Read position of a normalized spool file, used to resume loading."""

    __tablename__ = "spool_cursors"

    path: Mapped[str] = mapped_column(Text, primary_key=True)
    byte_offset: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class Detection(Base):
    """One detection rule matching stored events (RF-11).

    A detection is idempotent: ``fingerprint`` is derived from the rule and the
    subject it fired on, so evaluating the same rule over the same events again
    does not create a second row.
    """

    __tablename__ = "detections"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_detections_fingerprint"),
        CheckConstraint("occurred_to >= occurred_from", name="ck_detections_window"),
        Index("ix_detections_rule_id", "rule_id"),
        Index("ix_detections_source_ip", "source_ip"),
        Index("ix_detections_occurred_from", "occurred_from"),
        Index("ix_detections_detected_at", "detected_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    rule_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[Any | None] = mapped_column(INET)
    session_id: Mapped[str | None] = mapped_column(String(128))
    occurred_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurred_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON serializable representation."""

        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_kind": self.rule_kind,
            "title": self.title,
            "source_ip": str(self.source_ip) if self.source_ip is not None else None,
            "session_id": self.session_id,
            "occurred_from": self.occurred_from.isoformat() if self.occurred_from else None,
            "occurred_to": self.occurred_to.isoformat() if self.occurred_to else None,
            "event_count": self.event_count,
            "evidence": self.evidence or {},
            "fingerprint": self.fingerprint,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }


class Alert(Base):
    """One alert raised by a detection rule (RF-12).

    An alert is what an operator reads, so it repeats what was detected (type,
    severity, source IP, session, span and evidence) instead of pointing only at
    the detection. ``detection_id`` is unique: the same detection never raises a
    second alert, however many times the rules are evaluated over it.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("detection_id", name="uq_alerts_detection_id"),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')", name="ck_alerts_severity"
        ),
        CheckConstraint("occurred_to >= occurred_from", name="ck_alerts_window"),
        Index("ix_alerts_generated_at", "generated_at"),
        Index("ix_alerts_occurred_from", "occurred_from"),
        Index("ix_alerts_source_ip", "source_ip"),
        Index("ix_alerts_rule_id", "rule_id"),
        Index("ix_alerts_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    detection_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("detections.id", ondelete="CASCADE"), nullable=False
    )
    alert_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_ip: Mapped[Any | None] = mapped_column(INET)
    session_id: Mapped[str | None] = mapped_column(String(128))
    occurred_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurred_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON serializable representation."""

        return {
            "id": self.id,
            "detection_id": self.detection_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "source_ip": str(self.source_ip) if self.source_ip is not None else None,
            "session_id": self.session_id,
            "occurred_from": self.occurred_from.isoformat() if self.occurred_from else None,
            "occurred_to": self.occurred_to.isoformat() if self.occurred_to else None,
            "event_count": self.event_count,
            "evidence": self.evidence or {},
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
        }
