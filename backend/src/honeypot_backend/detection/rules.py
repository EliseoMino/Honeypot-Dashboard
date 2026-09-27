"""Rule configuration for the detection engine (RF-11).

The parameters of every rule live in a TOML file so they can be reviewed and
changed without touching the code. The file is read with :mod:`tomllib` from
the standard library, and validated here, so a typo in the configuration is
reported when it is loaded instead of silently changing what is detected.

The shipped configuration is ``/infrastructure/detection/rules.toml``. Every
rule declares an ``id``, which identifies it in the stored detections, and a
``kind``, which selects the implementation that evaluates it.
"""

from __future__ import annotations

import tomllib
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

#: Bounds shared by the rules, to keep one configuration from asking for
#: something that would scan the whole table.
MIN_WINDOW_SECONDS = 1
MAX_WINDOW_SECONDS = 7 * 24 * 3600
MIN_THRESHOLD = 2
MAX_THRESHOLD = 10_000
MAX_EVIDENCE_EVENTS = 200

DEFAULT_COMMANDS_OF_INTEREST: tuple[str, ...] = (
    # Downloading and transferring tooling.
    "wget",
    "curl",
    "tftp",
    "ftp",
    "scp",
    "sftp",
    "rsync",
    # Reverse shells and raw sockets.
    "nc",
    "ncat",
    "netcat",
    "socat",
    # Encoding, packing and encryption, often used to hide a payload.
    "base64",
    "openssl",
    "gpg",
    "xz",
    "zip",
    # Interpreters that can run a downloaded file.
    "perl",
    "python",
    "python2",
    "python3",
    "ruby",
    "php",
    "node",
    # Busybox and the usual privilege or persistence helpers.
    "busybox",
    "chmod",
    "chown",
    "crontab",
    "ssh-keygen",
    "powershell",
    "Invoke-WebRequest",
    "certutil",
)

DEFAULT_TRANSFER_EVENTS: tuple[str, ...] = (
    "transfer.download",
    "transfer.download_failed",
    "transfer.upload",
)

DEFAULT_AUTH_EVENTS: tuple[str, ...] = (
    "auth.login_failed",
    "auth.login_success",
)


class RuleConfigError(ValueError):
    """Raised when the rule configuration cannot be used."""


class _Base(BaseModel):
    """Common fields of every rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)


class AuthThresholdRule(_Base):
    """Several authentication attempts from the same source IP in a period.

    The window is anchored on the first attempt of a burst instead of on a
    fixed clock grid, so attempts are never split across two windows and the
    same burst is always recognised as the same one.
    """

    kind: Literal["auth_threshold"]
    threshold: int = Field(ge=MIN_THRESHOLD, le=MAX_THRESHOLD)
    window_seconds: int = Field(ge=MIN_WINDOW_SECONDS, le=MAX_WINDOW_SECONDS)
    event_types: tuple[str, ...] = Field(default=DEFAULT_AUTH_EVENTS, min_length=1)
    max_evidence_events: int = Field(default=50, ge=1, le=MAX_EVIDENCE_EVENTS)

    @property
    def window(self) -> timedelta:
        """The period the rule looks at, as a timedelta."""

        return timedelta(seconds=self.window_seconds)


class CommandOfInterestRule(_Base):
    """Execution of a command from the list of commands of interest.

    Matching is on the executables a command line invokes, so ``sudo wget x``
    and ``sh -c "wget x"`` match ``wget`` while ``echo wget`` does not.
    """

    kind: Literal["command_of_interest"]
    commands: tuple[str, ...] = Field(default=DEFAULT_COMMANDS_OF_INTEREST, min_length=1)
    event_types: tuple[str, ...] = (
        "command.success",
        "command.failed",
        "command.input",
        "command.stdin",
    )

    @property
    def interest(self) -> frozenset[str]:
        """The command names to compare against, lower cased."""

        return frozenset(command.lower() for command in self.commands)


class FileTransferRule(_Base):
    """A file the honeypot was asked to download or to send."""

    kind: Literal["file_transfer"]
    event_types: tuple[str, ...] = Field(default=DEFAULT_TRANSFER_EVENTS, min_length=1)


RuleSpec = Annotated[
    AuthThresholdRule | CommandOfInterestRule | FileTransferRule,
    Field(discriminator="kind"),
]


class RulesFile(BaseModel):
    """The parsed content of a rule configuration file.

    Rules are written as ``[[rule]]`` blocks, which is the name a reader expects
    for an array of tables; ``rules`` is accepted as an alias.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    version: int = Field(default=1, ge=1)
    rules: tuple[RuleSpec, ...] = Field(
        default=(), validation_alias=AliasChoices("rule", "rules")
    )

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> RulesFile:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)
        return self

    def by_kind(self, kind: str) -> tuple[RuleSpec, ...]:
        """Return the rules of one kind, in configuration order."""

        return tuple(rule for rule in self.rules if rule.kind == kind)


def load_rules(path: Path | None) -> RulesFile:
    """Read and validate the rule configuration at ``path``.

    Args:
        path: The TOML file to read. ``None`` yields an empty rule set, which
            is what a deployment without detection configured gets.

    Raises:
        RuleConfigError: When the file is missing, is not valid TOML or does
            not satisfy the schema of the rules.
    """

    if path is None:
        return RulesFile()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RuleConfigError(f"cannot read the rule file {path}: {exc}") from exc

    try:
        document: dict[str, Any] = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise RuleConfigError(f"{path} is not valid TOML: {exc}") from exc

    try:
        return RulesFile.model_validate(document)
    except ValueError as exc:
        raise RuleConfigError(f"{path} does not describe a valid rule set: {exc}") from exc
