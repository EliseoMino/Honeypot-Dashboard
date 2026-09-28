"""Agent configuration.

Every setting can be overridden with an ``AGENT_`` prefixed environment
variable (for example ``AGENT_COWRIE_LOG_PATH``) or through a ``.env`` file in
the working directory.
"""

from __future__ import annotations

import ssl
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

TLS_VERSIONS: dict[str, ssl.TLSVersion] = {
    "TLSv1_2": ssl.TLSVersion.TLSv1_2,
    "TLSv1_3": ssl.TLSVersion.TLSv1_3,
}


class AgentSettings(BaseSettings):
    """Settings of the ingestion agent."""

    model_config = SettingsConfigDict(
        env_prefix="AGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    agent_id: str = "cowrie-agent"

    cowrie_log_path: Path = Path("/var/log/cowrie/cowrie.json")
    checkpoint_path: Path = Path("/var/lib/honeypot-agent/checkpoint.json")

    backend_url: str = "https://backend:8443/api/v1/ingest/events"
    request_timeout: float = 15.0

    ca_certs: Path = Path("/etc/honeypot-agent/ca.crt")
    client_cert: Path = Path("/etc/honeypot-agent/agent.crt")
    client_key: Path = Path("/etc/honeypot-agent/agent.key")
    tls_min_version: str = "TLSv1_3"

    batch_size: int = 200
    max_pending_records: int = 10_000
    flush_interval: float = 2.0
    poll_interval: float = 0.5

    max_retries: int = 5
    backoff_initial: float = 0.5
    backoff_max: float = 30.0
    reject_backoff: float = 15.0

    start_at_end: bool = True
    log_level: str = "INFO"

    @property
    def tls_version(self) -> ssl.TLSVersion:
        try:
            return TLS_VERSIONS[self.tls_min_version]
        except KeyError:
            raise ValueError(
                f"unsupported AGENT_TLS_MIN_VERSION {self.tls_min_version!r}; "
                f"expected one of {sorted(TLS_VERSIONS)}"
            ) from None


@lru_cache(maxsize=1)
def get_agent_settings() -> AgentSettings:
    """Return the process-wide agent settings instance."""

    return AgentSettings()
