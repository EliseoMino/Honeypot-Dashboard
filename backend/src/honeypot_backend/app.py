"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from honeypot_backend import __version__
from honeypot_backend.api import health, ingest
from honeypot_backend.config import Settings, get_settings
from honeypot_backend.ingest.dedupe import RecentEventIds
from honeypot_backend.ingest.metrics import IngestMetrics
from honeypot_backend.ingest.spool import EventSpool

logger = logging.getLogger(__name__)

DESCRIPTION = (
    "Ingestion and normalization of Cowrie honeypot events for Honeypot-Dashboard. "
    "The ingestion endpoint is only reachable over TLS 1.3 with a client "
    "certificate signed by the local CA."
)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application."""

    resolved = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "backend ready: spool=%s tls=%s ca=%s",
            resolved.spool_dir,
            resolved.tls_min_version,
            resolved.tls_ca_certs,
        )
        try:
            yield
        finally:
            application.state.spool.close()
            logger.info("backend stopped, spool closed")

    app = FastAPI(
        title="Honeypot-Dashboard API",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.spool = EventSpool(
        resolved.spool_dir,
        max_bytes=resolved.spool_max_bytes,
        fsync=resolved.spool_fsync,
    )
    app.state.metrics = IngestMetrics()
    app.state.dedupe = RecentEventIds(capacity=resolved.dedupe_window)

    app.include_router(health.router)
    app.include_router(ingest.router)
    return app
