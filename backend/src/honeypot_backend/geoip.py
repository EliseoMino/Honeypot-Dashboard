"""Optional local IP country lookup (never makes network requests)."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CountryLookup:
    """Lazy-open a MaxMind database and return country metadata when present."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._reader: Any | None = None
        self._mtime: int | None = None

    def lookup(self, address: str | None) -> dict[str, str | None]:
        """Return ISO country code/name or ``None`` when lookup is unavailable."""

        empty = {"country_code": None, "country_name": None}
        if not address or self.path is None:
            return empty
        try:
            mtime = self.path.stat().st_mtime_ns
        except OSError:
            return empty
        with self._lock:
            if mtime != self._mtime:
                self._close_unlocked()
                self._mtime = mtime
                try:
                    import maxminddb

                    self._reader = maxminddb.open_database(str(self.path))
                except Exception as exc:  # noqa: BLE001 - malformed/unsupported database stays optional
                    logger.warning("GeoIP database unavailable at %s: %s", self.path, exc)
                    return empty
            if self._reader is None:
                return empty
            try:
                record = self._reader.get(address) or {}
            except ValueError:
                return empty
        country = record.get("country") or record.get("registered_country") or {}
        names = country.get("names") or {}
        return {
            "country_code": country.get("iso_code"),
            "country_name": names.get("en") or names.get("es"),
        }

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()

    def _close_unlocked(self) -> None:
        if self._reader is not None:
            self._reader.close()
        self._reader = None
        self._mtime = None
