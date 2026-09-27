"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from honeypot_backend import __version__
from honeypot_backend.api import events, health, ingest
from honeypot_backend.config import Settings, get_settings
from honeypot_backend.db.session import apply_migrations, dispose_engines, get_engine
from honeypot_backend.ingest.dedupe import RecentEventIds
from honeypot_backend.ingest.metrics import IngestMetrics
from honeypot_backend.ingest.replayer import NormalizedSpoolReplayer
from honeypot_backend.ingest.spool import EventSpool

logger = logging.getLogger(__name__)

DESCRIPTION = (
    "Ingestion, normalization and storage of Cowrie honeypot events for "
    "Honeypot-Dashboard. The ingestion endpoint is only reachable over TLS 1.3 "
    "with a client certificate signed by the local CA."
)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application."""

    resolved = settings or get_settings()
    spool = EventSpool(
        resolved.spool_dir,
        max_bytes=resolved.spool_max_bytes,
        fsync=resolved.spool_fsync,
    )
    replayer = NormalizedSpoolReplayer(resolved, spool.normalized_dir)
    metrics = IngestMetrics()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "backend ready: spool=%s database=%s tls=%s",
            resolved.spool_dir,
            resolved.database_url.rsplit("@", 1)[-1],
            resolved.tls_min_version,
        )
        try:
            await apply_migrations(get_engine(resolved))
        except Exception as exc:  # noqa: BLE001 - ingestion must survive a database outage
            logger.error("cannot apply migrations yet, the replayer will retry: %s", exc)

        task: asyncio.Task[None] | None = None
        if resolved.spool_replay_enabled:
            task = asyncio.create_task(replayer.run(), name="spool-replayer")
        else:
            logger.warning("spool replayer disabled, events will not reach PostgreSQL")

        try:
            yield
        finally:
            if task is not None:
                replayer.request_stop()
                try:
                    await asyncio.wait_for(task, timeout=10)
                except TimeoutError:
                    task.cancel()
            spool.close()
            await dispose_engines()
            logger.info("backend stopped")

    app = FastAPI(
        title="Honeypot-Dashboard API",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.spool = spool
    app.state.metrics = metrics
    app.state.dedupe = RecentEventIds(capacity=resolved.dedupe_window)
    app.state.replayer = replayer

    app.include_router(health.router)
    app.include_router(ingest.router)
    app.include_router(events.router)
    return app
