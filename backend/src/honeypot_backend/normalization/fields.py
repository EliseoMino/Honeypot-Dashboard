"""Parsing helpers shared by the event normalizers.

Cowrie is tolerant about the values it emits: timestamps may be ISO 8601
strings or epoch numbers, ports may arrive as strings, and attacker supplied
data is never guaranteed to be well formed. These helpers coerce such values
into the uniform types used by :mod:`honeypot_backend.normalization.events`
and silently drop the ones that cannot be interpreted. The untouched payload
is always preserved in ``NormalizedEvent.raw``.
"""

from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

MAX_TEXT_LENGTH = 4096
MAX_URL_LENGTH = 2048
MAX_KEY_LENGTH = 16384
HEX_DIGITS = frozenset("0123456789abcdef")


class NormalizationError(ValueError):
    """Raised when an event cannot be normalized at all."""


@dataclass(frozen=True, slots=True)
class CommandLine:
    """A shell command line split into its executable and arguments."""

    raw: str
    command: str
    arguments: tuple[str, ...]


def parse_timestamp(value: Any) -> datetime | None:
    """Return ``value`` as a timezone aware UTC datetime, or ``None``."""

    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            return _from_epoch(float(text))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _from_epoch(seconds: float) -> datetime | None:
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def normalize_ip(value: Any) -> str | None:
    """Return ``value`` in canonical IP notation, or ``None`` when invalid."""

    if not isinstance(value, str):
        return None
    text = value.strip().strip("[]")
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def normalize_port(value: Any) -> int | None:
    """Return ``value`` as a TCP port number, or ``None`` when out of range."""

    if value is None or isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def clean_text(value: Any, *, limit: int = MAX_TEXT_LENGTH) -> str | None:
    """Return a bounded, stripped string, or ``None`` for empty values."""

    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def clean_hash(value: Any) -> str | None:
    """Return a lower case hexadecimal digest, or ``None`` when not one."""

    text = clean_text(value, limit=128)
    if text is None:
        return None
    lowered = text.lower()
    if not lowered or any(character not in HEX_DIGITS for character in lowered):
        return None
    return lowered


def coerce_bool(value: Any) -> bool | None:
    """Return ``value`` as a boolean, or ``None`` when it is not boolean-ish."""

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def coerce_number(value: Any) -> float | None:
    """Return ``value`` as a float, or ``None`` when it is not numeric."""

    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_command_line(value: Any) -> CommandLine | None:
    """Split a shell command line into command and arguments.

    Quoting is honoured when possible; unbalanced quotes fall back to plain
    whitespace splitting so that the raw input is never lost.
    """

    text = clean_text(value)
    if text is None:
        return None
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()
    if not tokens:
        return None
    return CommandLine(raw=text, command=tokens[0], arguments=tuple(tokens[1:]))
