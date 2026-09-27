"""The application object itself, without touching a database."""

from __future__ import annotations

from honeypot_backend.app import create_app

EXPECTED_ROUTES = {
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("POST", "/api/v1/ingest/events"),
    ("GET", "/api/v1/ingest/stats"),
    ("GET", "/api/v1/events"),
    ("GET", "/api/v1/events/summary"),
    ("GET", "/api/v1/events/{event_id}"),
    ("GET", "/api/v1/sessions"),
    ("GET", "/api/v1/commands"),
    ("GET", "/api/v1/sources"),
    ("GET", "/api/v1/sources/{source_ip}"),
    ("POST", "/api/v1/detections/run"),
    ("GET", "/api/v1/detections"),
    ("GET", "/api/v1/detections/rules"),
    ("GET", "/api/v1/alerts"),
    ("GET", "/api/v1/alerts/{alert_id}"),
}


def test_the_expected_routes_are_registered(settings) -> None:
    app = create_app(settings)
    app.state.spool.close()

    registered = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }

    assert registered == EXPECTED_ROUTES


def test_the_openapi_schema_can_be_generated(settings) -> None:
    app = create_app(settings)
    app.state.spool.close()

    schema = app.openapi()

    assert schema["info"]["title"] == "Honeypot-Dashboard API"
    assert "/api/v1/events" in schema["paths"]
    assert "/api/v1/events/{event_id}" in schema["paths"]


def test_the_event_endpoints_document_every_filter(settings) -> None:
    app = create_app(settings)
    app.state.spool.close()

    parameters = {
        parameter["name"] for parameter in app.openapi()["paths"]["/api/v1/events"]["get"]["parameters"]
    }

    assert {
        "event_type",
        "source_ip",
        "session_id",
        "username",
        "event_category",
        "outcome",
        "occurred_from",
        "occurred_to",
        "q",
        "limit",
        "offset",
        "order",
    } <= parameters


def test_the_spool_of_a_fresh_app_is_empty(settings) -> None:
    app = create_app(settings)

    try:
        stats = app.state.spool.stats()
        assert stats["raw"]["records_written"] == 0
        assert stats["normalized"]["records_written"] == 0
        assert app.state.replayer.events_loaded == 0
    finally:
        app.state.spool.close()
