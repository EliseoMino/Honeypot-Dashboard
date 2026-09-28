"""Health endpoints."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request, Response, status
from sqlalchemy import text

from honeypot_backend.db.session import get_engine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/healthz", summary="Liveness probe")
def healthz() -> dict[str, Any]:
    """Report that the process is up and serving."""

    return {"status": "ok"}


@router.get("/readyz", summary="Readiness probe")
async def readyz(request: Request) -> Response:
    """Report whether stored events can be read and written.

    The backend is still useful while PostgreSQL is down: ingestion keeps
    spooling normalized events and they are loaded once the database is back.
    The probe therefore answers 503 with a ``degraded`` status instead of
    crashing, which keeps the instance out of rotation without killing it.
    Liveness stays on ``/healthz``.
    """

    settings = request.app.state.settings
    replayer = getattr(request.app.state, "replayer", None)
    payload: dict[str, Any] = {
        "status": "ok",
        "database": {"status": "unknown", "target": settings.database_url.rsplit("@", 1)[-1]},
    }
    if replayer is not None:
        payload["replayer"] = replayer.stats()

    code = status.HTTP_200_OK
    try:
        async with get_engine(settings).connect() as connection:
            await connection.execute(text("SELECT 1"))
        payload["database"]["status"] = "ok"
    except Exception as exc:  # noqa: BLE001 - the probe reports, it never raises
        logger.warning("database not ready: %s", exc)
        payload["status"] = "degraded"
        payload["database"] = {"status": "unreachable", "error": str(exc)[:256]}
        code = status.HTTP_503_SERVICE_UNAVAILABLE

    return Response(
        content=json.dumps(payload),
        status_code=code,
        media_type="application/json",
    )
