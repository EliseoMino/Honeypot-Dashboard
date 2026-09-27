"""Entry point: run the ingestion API behind TLS 1.3 with mutual TLS.

uvicorn builds its own ``SSLContext`` and does not expose a minimum protocol
version, so the context is created here and handed to uvicorn through the
``ssl_context_factory`` hook. That keeps the transport requirement of RF-01
("TLS 1.3, client certificate required") enforced in one place.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Callable
from pathlib import Path

import uvicorn

from honeypot_backend.app import create_app
from honeypot_backend.config import Settings, get_settings

logger = logging.getLogger(__name__)


def build_ssl_context(settings: Settings) -> ssl.SSLContext:
    """Create the server SSL context: TLS 1.3 only, client cert required."""

    _require_file(settings.tls_certfile, "TLS_CERTFILE")
    _require_file(settings.tls_keyfile, "TLS_KEYFILE")
    _require_file(settings.tls_ca_certs, "TLS_CA_CERTS")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = settings.tls_version
    context.maximum_version = settings.tls_version
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    context.load_cert_chain(certfile=str(settings.tls_certfile), keyfile=str(settings.tls_keyfile))
    context.load_verify_locations(cafile=str(settings.tls_ca_certs))
    return context


def _require_file(path: Path, variable: str) -> None:
    if not path.is_file():
        raise SystemExit(
            f"{variable} does not exist: {path}. "
            "Generate the development PKI with 'python scripts/generate-dev-certs.py --out var/certs'."
        )


def create_ssl_context_factory(settings: Settings) -> Callable[[uvicorn.Config, Callable[[], ssl.SSLContext]], ssl.SSLContext]:
    """Return the factory uvicorn calls to build the server TLS context."""

    def factory(config: uvicorn.Config, default_factory: Callable[[], ssl.SSLContext]) -> ssl.SSLContext:
        return build_ssl_context(settings)

    return factory


def main() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app = create_app(settings)
    config = uvicorn.Config(
        app=app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
        ssl_context_factory=create_ssl_context_factory(settings),
    )
    logger.info(
        "starting ingestion API on %s:%s (%s, mutual TLS)",
        settings.host,
        settings.port,
        settings.tls_min_version,
    )
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
