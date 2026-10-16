"""API response helpers for optional local GeoIP context."""

from __future__ import annotations

from typing import Any

from fastapi import Request


def with_country(request: Request, record: dict[str, Any]) -> dict[str, Any]:
    lookup = getattr(request.app.state, "country_lookup", None)
    metadata = lookup.lookup(record.get("source_ip")) if lookup is not None else {
        "country_code": None,
        "country_name": None,
    }
    return {**record, **metadata}
