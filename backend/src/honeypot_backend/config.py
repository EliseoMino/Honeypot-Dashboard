"""Runtime configuration for the backend.

Every value can be overridden through an environment variable with the same
name (upper case) or through a ``.env`` file in the working directory.
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


class Settings(BaseSettings):
    """Backend settings."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    tls_certfile: Path = Path("var/certs/server.crt")
    tls_keyfile: Path = Path("var/certs/server.key")
    tls_ca_certs: Path = Path("var/certs/ca.crt")
    tls_min_version: str = "TLSv1_3"

    spool_dir: Path = Path("var/spool")
    spool_max_bytes: int = 64 * 1024 * 1024
    spool_fsync: bool = True

    max_batch_events: int = 500
    dedupe_window: int = 50_000

    database_url: str = "postgresql+asyncpg://honeypot:change-me@127.0.0.1:5432/honeypot"
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 5

    spool_replay_enabled: bool = True
    spool_replay_interval: float = 1.0
    spool_replay_batch_size: int = 500
    spool_replay_error_backoff: float = 5.0

    @property
    def tls_version(self) -> ssl.TLSVersion:
        try:
            return TLS_VERSIONS[self.tls_min_version]
        except KeyError:
            raise ValueError(
                f"unsupported TLS_MIN_VERSION {self.tls_min_version!r}; expected one of {sorted(TLS_VERSIONS)}"
            ) from None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance."""

    return Settings()
