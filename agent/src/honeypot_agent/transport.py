"""TLS 1.3 transport towards the backend (RF-01).

The channel is restricted to TLS 1.3 and the agent authenticates itself with a
client certificate signed by the same local CA the backend trusts, so no shared
secret has to be stored next to the honeypot.

Delivery is at least once: transient failures (connection errors, timeouts,
5xx, 429) are retried with exponential backoff and the batch is kept in the
pipeline until the backend acknowledges it. A permanent rejection (4xx) is
never acknowledged locally, because dropping it would lose events.
"""

from __future__ import annotations

import logging
import random
import ssl
import time
from collections.abc import Callable
from typing import Any

import httpx

from honeypot_agent.config import AgentSettings

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class DeliveryError(RuntimeError):
    """A batch could not be delivered."""

    def __init__(self, message: str, *, transient: bool, status_code: int | None = None) -> None:
        super().__init__(message)
        self.transient = transient
        self.status_code = status_code


class IngestClient:
    """Send batches to the backend ingestion endpoint."""

    def __init__(self, settings: AgentSettings) -> None:
        self._settings = settings
        self._client = httpx.Client(
            verify=self._build_ssl_context(settings),
            timeout=settings.request_timeout,
            limits=httpx.Limits(max_keepalive_connections=1, max_connections=2),
            headers={"user-agent": "honeypot-agent"},
        )

    @property
    def backend_url(self) -> str:
        return self._settings.backend_url

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> IngestClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Deliver one batch and return the backend acknowledgement."""

        try:
            response = self._client.post(self._settings.backend_url, json=payload)
        except httpx.TimeoutException as exc:
            raise DeliveryError(f"timeout after {self._settings.request_timeout}s: {exc}", transient=True) from exc
        except httpx.HTTPError as exc:
            raise DeliveryError(f"transport error: {exc}", transient=True) from exc

        if response.status_code in RETRYABLE_STATUS:
            raise DeliveryError(
                f"backend returned {response.status_code}: {response.text[:200]}",
                transient=True,
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise DeliveryError(
                f"backend rejected the batch with {response.status_code}: {response.text[:200]}",
                transient=False,
                status_code=response.status_code,
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise DeliveryError(f"invalid acknowledgement payload: {exc}", transient=True) from exc
        if not isinstance(body, dict):
            raise DeliveryError("invalid acknowledgement payload: expected a JSON object", transient=True)
        return body

    def send_with_retry(
        self,
        payload: dict[str, Any],
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> dict[str, Any]:
        """Deliver a batch, retrying transient failures with backoff."""

        attempt = 0
        while True:
            try:
                return self.send(payload)
            except DeliveryError as exc:
                if not exc.transient:
                    raise
                attempt += 1
                if attempt > self._settings.max_retries:
                    raise
                delay = min(
                    self._settings.backoff_initial * (2 ** (attempt - 1)),
                    self._settings.backoff_max,
                )
                delay *= 0.5 + random.random()
                logger.warning(
                    "delivery attempt %d/%d failed (%s), retrying in %.1fs",
                    attempt,
                    self._settings.max_retries,
                    exc,
                    delay,
                )
                sleep(delay)


def _build_ssl_context(settings: AgentSettings) -> ssl.SSLContext:
    """Create a client context pinned to TLS 1.3 with the agent certificate."""

    for path, variable in (
        (settings.ca_certs, "AGENT_CA_CERTS"),
        (settings.client_cert, "AGENT_CLIENT_CERT"),
        (settings.client_key, "AGENT_CLIENT_KEY"),
    ):
        if not path.is_file():
            raise SystemExit(
                f"{variable} does not exist: {path}. "
                "Generate the development PKI with 'python scripts/generate-dev-certs.py --out var/certs'."
            )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = settings.tls_version
    context.maximum_version = settings.tls_version
    context.load_verify_locations(cafile=str(settings.ca_certs))
    context.load_cert_chain(certfile=str(settings.client_cert), keyfile=str(settings.client_key))
    return context
