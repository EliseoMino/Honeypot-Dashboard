"""Cowrie to uniform event translation (RF-02).

The mapping below follows the official Cowrie output event reference
(https://docs.cowrie.org/en/latest/OUTPUT.html). Attributes that Cowrie
documents as shared across events (``eventid``, ``timestamp``, ``sensor``,
``session``, ``src_ip``, ``src_port``, ``dst_ip``, ``dst_port``,
``protocol``, ``message``) are lifted into the corresponding
:class:`~honeypot_backend.normalization.events.NormalizedEvent` fields;
everything else lands in ``details`` under a normalized name.

Event types that are not listed here are still accepted: they fall back to a
generic extraction so that new Cowrie events are ingested instead of dropped.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from honeypot_backend.normalization.events import EventCategory, EventOutcome, NormalizedEvent
from honeypot_backend.normalization.fields import (
    MAX_KEY_LENGTH,
    MAX_URL_LENGTH,
    NormalizationError,
    clean_hash,
    clean_text,
    coerce_bool,
    coerce_number,
    normalize_ip,
    normalize_port,
    parse_command_line,
    parse_timestamp,
)

SOURCE = "cowrie"
SOURCE_PREFIX = "cowrie."

SHARED_ATTRIBUTES = frozenset(
    {
        "eventid",
        "timestamp",
        "sensor",
        "session",
        "message",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
    }
)

SUCCESS_SUFFIX = ".success"
FAILURE_SUFFIX = ".failed"

UNKNOWN_EVENT_ID = "cowrie.unknown"

#: Cowrie event ids that RF-01 requires the ingestion to collect. Exposed so
#: the API can report which required event types have actually been observed.
REQUIRED_EVENT_IDS: frozenset[str] = frozenset(
    {
        "cowrie.session.connect",
        "cowrie.session.closed",
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.command.success",
        "cowrie.command.failed",
        "cowrie.session.file_download",
        "cowrie.client.fingerprint",
    }
)


@dataclass(frozen=True, slots=True)
class Extraction:
    """The event specific part of a normalized event."""

    username: str | None = None
    outcome: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


Extractor = Callable[[Mapping[str, Any]], Extraction]


@dataclass(frozen=True, slots=True)
class EventSpec:
    """How a single Cowrie event id is translated."""

    event_type: str
    category: EventCategory
    extractor: Extractor


def _compact(values: Mapping[str, Any]) -> dict[str, Any]:
    """Drop keys whose value could not be interpreted."""

    return {key: value for key, value in values.items() if value is not None}


def _extract_empty(event: Mapping[str, Any]) -> Extraction:
    return Extraction()


def _extract_session_connect(event: Mapping[str, Any]) -> Extraction:
    return Extraction(
        details=_compact(
            {
                "client_version": clean_text(event.get("version"), limit=512),
                "transport": clean_text(event.get("transport"), limit=32),
                "message": clean_text(event.get("message"), limit=1024),
            }
        )
    )


def _extract_session_closed(event: Mapping[str, Any]) -> Extraction:
    duration_ms = coerce_number(event.get("duration_ms"))
    if duration_ms is None:
        legacy_duration = coerce_number(event.get("duration"))
        if legacy_duration is not None:
            duration_ms = legacy_duration * 1000
    return Extraction(details=_compact({"duration_ms": duration_ms}))


def _extract_session_params(event: Mapping[str, Any]) -> Extraction:
    return Extraction(details=_compact({"arch": clean_text(event.get("arch"), limit=64)}))


def _extract_authentication(event: Mapping[str, Any]) -> Extraction:
    password = event.get("password")
    fingerprint = clean_text(event.get("fingerprint"), limit=512)
    key = clean_text(event.get("key"), limit=MAX_KEY_LENGTH)
    key_type = clean_text(event.get("type"), limit=64)
    method = clean_text(event.get("method"), limit=64)

    auth_method = method
    if auth_method is None:
        if password is not None:
            auth_method = "password"
        elif fingerprint or key:
            auth_method = "publickey"

    return Extraction(
        username=clean_text(event.get("username")),
        details=_compact(
            {
                "auth_method": auth_method,
                "password": clean_text(password, limit=512),
                "key_fingerprint": fingerprint,
                "key_type": key_type,
                "key": key,
            }
        ),
    )


def _extract_command(event: Mapping[str, Any]) -> Extraction:
    parsed = parse_command_line(event.get("input"))
    details: dict[str, Any] = {}
    if parsed is not None:
        details["command_line"] = parsed.raw
        details["command"] = parsed.command
        details["arguments"] = list(parsed.arguments)
    realm = clean_text(event.get("realm"), limit=128)
    if realm is not None:
        details["realm"] = realm
    return Extraction(
        username=clean_text(event.get("username")),
        details=_compact(details),
    )


def _extract_chpasswd(event: Mapping[str, Any]) -> Extraction:
    return Extraction(
        username=clean_text(event.get("username")),
        details=_compact({"realm": clean_text(event.get("realm"), limit=128)}),
    )


def _extract_transfer(event: Mapping[str, Any]) -> Extraction:
    duplicate = coerce_bool(event.get("duplicate"))
    return Extraction(
        username=clean_text(event.get("username")),
        details=_compact(
            {
                "url": clean_text(event.get("url"), limit=MAX_URL_LENGTH),
                "outfile": clean_text(event.get("outfile"), limit=1024),
                "filename": clean_text(event.get("filename"), limit=512),
                "destfile": clean_text(event.get("destfile"), limit=1024),
                "sha256": clean_hash(event.get("shasum")) or clean_hash(event.get("sha256")),
                "md5": clean_hash(event.get("md5sum")) or clean_hash(event.get("md5")),
                "duplicate": duplicate,
            }
        ),
    )


def _extract_transfer_failed(event: Mapping[str, Any]) -> Extraction:
    return Extraction(
        details=_compact(
            {
                "url": clean_text(event.get("url"), limit=MAX_URL_LENGTH),
                "error": clean_text(event.get("error"), limit=1024),
            }
        )
    )


def _extract_client_version(event: Mapping[str, Any]) -> Extraction:
    return Extraction(
        details=_compact({"client_version": clean_text(event.get("version"), limit=512)})
    )


def _extract_client_kex(event: Mapping[str, Any]) -> Extraction:
    return Extraction(
        details=_compact(
            {
                "hassh": clean_text(event.get("hassh"), limit=512),
                "hassh_algorithms": clean_text(event.get("hasshAlgorithms"), limit=1024),
                "kex_algorithms": clean_text(event.get("kexAlgs"), limit=1024),
                "host_key_algorithms": clean_text(event.get("keyAlgs"), limit=1024),
                "encryption_algorithms": clean_text(event.get("encCS"), limit=1024),
                "mac_algorithms": clean_text(event.get("macCS"), limit=1024),
                "compression_algorithms": clean_text(event.get("compCS"), limit=1024),
                "languages": clean_text(event.get("langCS"), limit=1024),
            }
        )
    )


def _extract_client_size(event: Mapping[str, Any]) -> Extraction:
    return Extraction(
        details=_compact(
            {
                "width": coerce_number(event.get("width")),
                "height": coerce_number(event.get("height")),
            }
        )
    )


def _extract_client_var(event: Mapping[str, Any]) -> Extraction:
    return Extraction(
        details=_compact(
            {
                "name": clean_text(event.get("name"), limit=256),
                "value": clean_text(event.get("value"), limit=1024),
            }
        )
    )


def _extract_generic(event: Mapping[str, Any]) -> Extraction:
    """Keep every non shared attribute for event types without a dedicated map."""

    details = {key: value for key, value in event.items() if key not in SHARED_ATTRIBUTES}
    return Extraction(username=clean_text(event.get("username")), details=details)


_SPECS: dict[str, EventSpec] = {}


def _register(event_id: str, event_type: str, category: EventCategory, extractor: Extractor) -> None:
    _SPECS[event_id] = EventSpec(event_type=event_type, category=category, extractor=extractor)


_register("cowrie.session.connect", "session.connect", "session", _extract_session_connect)
_register("cowrie.session.closed", "session.closed", "session", _extract_session_closed)
_register("cowrie.session.params", "session.params", "session", _extract_session_params)
_register("cowrie.login.success", "auth.login_success", "authentication", _extract_authentication)
_register("cowrie.login.failed", "auth.login_failed", "authentication", _extract_authentication)
_register("cowrie.client.fingerprint", "auth.key_fingerprint", "authentication", _extract_authentication)
_register("cowrie.command.input", "command.input", "command", _extract_command)
_register("cowrie.command.success", "command.success", "command", _extract_command)
_register("cowrie.command.failed", "command.failed", "command", _extract_command)
_register("cowrie.command.chpasswd", "command.chpasswd", "command", _extract_chpasswd)
_register("cowrie.session.input", "command.stdin", "command", _extract_command)
_register("cowrie.session.file_download", "transfer.download", "transfer", _extract_transfer)
_register("cowrie.session.file_download.failed", "transfer.download_failed", "transfer", _extract_transfer_failed)
_register("cowrie.session.file_upload", "transfer.upload", "transfer", _extract_transfer)
_register("cowrie.client.version", "client.version", "client", _extract_client_version)
_register("cowrie.client.kex", "client.kex", "client", _extract_client_kex)
_register("cowrie.client.size", "client.size", "client", _extract_client_size)
_register("cowrie.client.var", "client.var", "client", _extract_client_var)
_register("cowrie.log.open", "session.ttylog_open", "session", _extract_empty)
_register("cowrie.log.closed", "session.ttylog_closed", "session", _extract_empty)
_register("cowrie.telnet.error", "client.telnet_error", "client", _extract_generic)
_register("cowrie.client.malformed_packet", "client.malformed_packet", "client", _extract_generic)


def supported_event_ids() -> frozenset[str]:
    """Cowrie event ids with a dedicated translation."""

    return frozenset(_SPECS)


def is_supported(source_event_id: str) -> bool:
    """Whether ``source_event_id`` has a dedicated translation."""

    return source_event_id in _SPECS


def compute_event_id(raw: Mapping[str, Any]) -> str:
    """Return a deterministic identifier for a raw event.

    The same payload always produces the same identifier, which lets the
    backend drop the duplicates produced by an agent restart.
    """

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def derive_event_type(source_event_id: str) -> str:
    """Derive a dotted event type from an unmapped Cowrie event id."""

    stripped = source_event_id[len(SOURCE_PREFIX) :] if source_event_id.startswith(SOURCE_PREFIX) else source_event_id
    return f"other.{stripped.replace('.', '_')}" if stripped else "other.unknown"


def derive_outcome(source_event_id: str) -> EventOutcome | None:
    """Derive the outcome from the Cowrie event id naming convention."""

    if source_event_id.endswith(SUCCESS_SUFFIX):
        return "success"
    if source_event_id.endswith(FAILURE_SUFFIX):
        return "failure"
    return None


def normalize(raw: Mapping[str, Any], *, received_at: datetime | None = None) -> NormalizedEvent:
    """Translate a raw Cowrie event into a :class:`NormalizedEvent`.

    Args:
        raw: The decoded ``cowrie.json`` line.
        received_at: Backend receipt time, used as the fallback event time and
            always recorded as ``received_at``.

    Raises:
        NormalizationError: When the payload cannot be identified as a Cowrie
            event at all (no ``eventid`` and no ``timestamp``).
    """

    if not isinstance(raw, Mapping):
        raise NormalizationError("event payload is not a JSON object")

    receipt = received_at or datetime.now(UTC)
    source_event_id = clean_text(raw.get("eventid"), limit=256) or ""
    occurred_at = parse_timestamp(raw.get("timestamp"))
    if not source_event_id and occurred_at is None:
        raise NormalizationError("event has neither 'eventid' nor 'timestamp'")
    if not source_event_id:
        source_event_id = UNKNOWN_EVENT_ID

    spec = _SPECS.get(source_event_id)
    if spec is None:
        spec = EventSpec(
            event_type=derive_event_type(source_event_id),
            category="other",
            extractor=_extract_generic,
        )
    extraction = spec.extractor(raw)

    protocol = clean_text(raw.get("protocol"), limit=16)
    return NormalizedEvent(
        event_id=compute_event_id(raw),
        source=SOURCE,
        source_event_id=source_event_id,
        event_type=spec.event_type,
        event_category=spec.category,
        occurred_at=occurred_at or receipt,
        received_at=receipt,
        sensor=clean_text(raw.get("sensor"), limit=256),
        session_id=clean_text(raw.get("session"), limit=128),
        source_ip=normalize_ip(raw.get("src_ip")),
        source_port=normalize_port(raw.get("src_port")),
        destination_ip=normalize_ip(raw.get("dst_ip")),
        destination_port=normalize_port(raw.get("dst_port")),
        protocol=protocol.lower() if protocol else None,
        username=extraction.username or clean_text(raw.get("username")),
        outcome=cast_outcome(extraction.outcome) or derive_outcome(source_event_id),
        details=extraction.details,
        raw=dict(raw),
    )


def cast_outcome(outcome: str | None) -> EventOutcome | None:
    """Narrow an extractor outcome to the allowed values."""

    if outcome in {"success", "failure"}:
        return outcome  # type: ignore[return-value]
    return None
