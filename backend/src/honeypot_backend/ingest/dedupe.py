"""Bounded in memory duplicate suppression for replayed events.

The agent delivers at least once, so a crash between a successful delivery and
the local checkpoint write replays a batch. Replayed events carry the same
deterministic ``event_id`` (see
:func:`honeypot_backend.normalization.compute_event_id`), which lets the
backend recognise them without storing state. RF-03 will make the check
authoritative with a unique constraint; this window only keeps the normalized
stream free of immediate repeats.
"""

from __future__ import annotations

import threading
from collections import deque

DEFAULT_CAPACITY = 50_000


class RecentEventIds:
    """A fixed size set of recently seen event ids."""

    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        self._capacity = max(1, capacity)
        self._lock = threading.Lock()
        self._ids: set[str] = set()
        self._order: deque[str] = deque()

    def __len__(self) -> int:
        with self._lock:
            return len(self._ids)

    def is_duplicate(self, event_id: str) -> bool:
        """Record ``event_id``, returning whether it was already present."""

        with self._lock:
            if event_id in self._ids:
                return True
            self._ids.add(event_id)
            self._order.append(event_id)
            while len(self._order) > self._capacity:
                self._ids.discard(self._order.popleft())
            return False
