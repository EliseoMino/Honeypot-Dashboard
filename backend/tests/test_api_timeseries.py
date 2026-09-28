"""The activity series of RF-05 over HTTP.

The series is the only read here that is time ordered, and the batch spans three
hours on purpose so the bucket width is observable.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
import pytest
from fastapi import FastAPI

from honeypot_backend.app import create_app
from honeypot_backend.config import Settings

#: One event per hour for three hours, so an hour bucket yields three points and
#: a day bucket yields a single one.
BATCH_EVENTS = [
    {
        "eventid": "cowrie.session.connect",
        "timestamp": f"2026-03-01T{hour:02d}:30:00.000000Z",
        "session": f"sess-{hour}",
        "src_ip": "203.0.113.10",
    }
    for hour in (10, 11, 12)
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


async def test_the_series_counts_events_per_period(backend, cowrie_event) -> None:
    assert await backend.ingest(cowrie_event) == 3

    response = await backend.client.get("/api/v1/events/timeseries", params={"bucket": "hour"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["bucket"] == "hour"
    assert [point["count"] for point in payload["points"]] == [1, 1, 1]
    assert [point["bucket"] for point in payload["points"]] == [
        "2026-03-01T10:00:00+00:00",
        "2026-03-01T11:00:00+00:00",
        "2026-03-01T12:00:00+00:00",
    ]


async def test_the_period_width_changes_the_resolution(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    daily = await backend.client.get("/api/v1/events/timeseries", params={"bucket": "day"})

    assert daily.json()["bucket"] == "day"
    assert len(daily.json()["points"]) == 1
    assert daily.json()["points"][0]["count"] == 3
    assert daily.json()["points"][0]["bucket"] == "2026-03-01T00:00:00+00:00"


async def test_the_series_separates_authentication_from_commands(backend, cowrie_event) -> None:
    """RF-05 asks to spot busy periods, so the two loudest kinds stay apart."""

    await backend.ingest(cowrie_event)
    await backend.client.post(
        "/api/v1/ingest/events",
        json={
            "agent_id": "agent-1",
            "batch_id": "batch-2",
            "events": [
                {
                    "eventid": "cowrie.login.failed",
                    "timestamp": "2026-03-01T10:45:00.000000Z",
                    "session": "sess-10",
                    "src_ip": "203.0.113.10",
                    "username": "root",
                }
            ],
        },
    )
    await backend.app.state.replayer.run_once()

    response = await backend.client.get("/api/v1/events/timeseries", params={"bucket": "hour"})

    first = response.json()["points"][0]
    assert first["count"] == 2
    assert first["auth"] == 1
    assert first["commands"] == 0


async def test_the_series_honours_the_event_filters(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get(
        "/api/v1/events/timeseries",
        params={"bucket": "hour", "source_ip": "198.51.100.4"},
    )

    assert response.json()["points"] == []


async def test_the_series_only_contains_periods_that_have_events(backend, cowrie_event) -> None:
    """A lull is not a zero row here: the client decides how to draw the gap."""

    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/events/timeseries", params={"bucket": "hour"})

    assert [point["bucket"] for point in response.json()["points"]] == [
        "2026-03-01T10:00:00+00:00",
        "2026-03-01T11:00:00+00:00",
        "2026-03-01T12:00:00+00:00",
    ]


async def test_an_unknown_period_width_is_rejected(backend, cowrie_event) -> None:
    await backend.ingest(cowrie_event)

    response = await backend.client.get("/api/v1/events/timeseries", params={"bucket": "week"})

    assert response.status_code == 422


async def test_the_series_is_not_swallowed_by_the_event_id_route(backend, cowrie_event) -> None:
    """`/timeseries` is a literal route and has to be matched before `{event_id}`."""

    await backend.ingest(cowrie_event)

    series = await backend.client.get("/api/v1/events/timeseries")
    detail = await backend.client.get("/api/v1/events/timeseries-not-an-event-id")

    assert series.status_code == 200
    assert series.json()["bucket"] == "hour"
    assert detail.status_code == 404
