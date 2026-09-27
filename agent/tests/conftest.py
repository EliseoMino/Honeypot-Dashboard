"""Shared fixtures for the agent test suite.

The agent is the component RF-01 leans on to guarantee that nothing is lost or
duplicated in bulk, so its tests exercise the real files on a temporary
directory instead of mocking the filesystem.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from honeypot_agent.config import AgentSettings


@pytest.fixture
def cowrie_log(tmp_path: Path) -> Path:
    """An empty ``cowrie.json`` the test can append to."""

    path = tmp_path / "cowrie" / "cowrie.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    return path


@pytest.fixture
def append(cowrie_log: Path) -> Callable[..., int]:
    """Append raw bytes to ``cowrie.json`` as Cowrie would.

    Returns the absolute offset just past what was written, which is what the
    tailer reports and what a checkpoint stores.
    """

    def _append(text: str | bytes, *, newline: bool = True) -> int:
        data = text.encode("utf-8") if isinstance(text, str) else text
        if newline:
            data += b"\n"
        with cowrie_log.open("ab") as handle:
            handle.write(data)
            handle.flush()
            return handle.tell()

    return _append


@pytest.fixture
def event() -> Callable[..., str]:
    """Build a raw Cowrie event line, as the agent reads it from the log."""

    counter = {"n": 0}

    def _event(**overrides: Any) -> str:
        counter["n"] += 1
        payload: dict[str, Any] = {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-03-01T11:59:00.000000Z",
            "sensor": "honeypot-1",
            "session": "sess-1",
            "src_ip": "203.0.113.10",
            "src_port": 51234,
            "dst_ip": "198.51.100.5",
            "dst_port": 2222,
            "protocol": "ssh",
            "message": f"event {counter['n']}",
        }
        payload.update(overrides)
        return json.dumps(payload)

    return _event


@pytest.fixture
def settings(tmp_path: Path, cowrie_log: Path) -> AgentSettings:
    """Agent settings that never touch the developer's environment or network."""

    return AgentSettings(
        agent_id="test-agent",
        cowrie_log_path=cowrie_log,
        checkpoint_path=tmp_path / "state" / "checkpoint.json",
        backend_url="https://backend.invalid/api/v1/ingest/events",
        batch_size=50,
        flush_interval=0.0,
        poll_interval=0.0,
        reject_backoff=0.0,
        start_at_end=False,
    )
