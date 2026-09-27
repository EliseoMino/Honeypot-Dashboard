"""Wiring between the rule configuration and the API (RF-11).

The rules are read once, when the application is built, and kept on the
application state. A configuration problem is reported by the endpoints instead
of preventing the backend from starting: ingestion and the read API are useful
even when detection is not available.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_backend.config import Settings
from honeypot_backend.detection.engine import Detection, DetectionEngine
from honeypot_backend.detection.rules import RuleConfigError, RulesFile, load_rules

logger = logging.getLogger(__name__)

#: Repository root, used to find the shipped rule file when the backend runs
#: from a directory where the configured relative path does not resolve.
_REPO_ROOT = Path(__file__).resolve().parents[4]


class RulesUnavailable(RuntimeError):
    """Raised when the rule configuration cannot be used."""


@dataclass(frozen=True, slots=True)
class DetectionService:
    """The rules of this deployment and the engine that evaluates them."""

    engine: DetectionEngine
    rules: RulesFile
    path: Path | None
    error: str | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> DetectionService:
        """Load the configured rules, keeping the error instead of raising."""

        path = resolve_rules_path(settings.detection_rules_path)
        try:
            rules = load_rules(path)
        except RuleConfigError as exc:
            logger.error("detection is disabled: %s", exc)
            return cls(engine=DetectionEngine(), rules=RulesFile(), path=path, error=str(exc))

        logger.info("detection rules loaded from %s: %d rule(s)", path, len(rules.rules))
        return cls(engine=DetectionEngine(rules), rules=rules, path=path)

    @property
    def available(self) -> bool:
        """Whether the rules could be loaded."""

        return self.error is None

    def require_rules(self) -> DetectionEngine:
        """Return the engine, or explain why detection is not available."""

        if self.error is not None:
            raise RulesUnavailable(self.error)
        return self.engine

    def describe(self) -> dict[str, Any]:
        """Return the rule set, for the endpoint that reports it.

        The fields every rule has are reported as they are, and the parameters
        that only mean something to one kind of rule are grouped together, so a
        consumer can show a rule without knowing every kind.
        """

        common = ("id", "kind", "title", "description", "severity")
        return {
            "available": self.available,
            "path": str(self.path) if self.path is not None else None,
            "error": self.error,
            "version": self.rules.version,
            "rules": [
                {
                    **{key: rule.model_dump(mode="json")[key] for key in common},
                    "parameters": {
                        key: value
                        for key, value in rule.model_dump(mode="json").items()
                        if key not in common
                    },
                }
                for rule in self.rules.rules
            ],
        }

    async def run(
        self,
        session: AsyncSession,
        *,
        occurred_from: datetime,
        occurred_to: datetime,
    ) -> list[Detection]:
        """Evaluate the rules over a window."""

        return await self.require_rules().run(
            session, occurred_from=occurred_from, occurred_to=occurred_to
        )


def resolve_rules_path(configured: Path | None) -> Path | None:
    """Return the rule file to read.

    A relative path is looked up in the working directory first and then
    relative to the repository, so the backend can be started from either.
    """

    if configured is None:
        return None
    if configured.is_absolute():
        return configured
    for candidate in (Path.cwd() / configured, _REPO_ROOT / configured):
        if candidate.is_file():
            return candidate
    return None


def lookback_of(settings: Settings) -> timedelta:
    """The period evaluated when a run does not specify one."""

    return timedelta(seconds=settings.detection_default_lookback)
