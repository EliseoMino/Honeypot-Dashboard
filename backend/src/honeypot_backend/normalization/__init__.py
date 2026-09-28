"""Public surface of the normalization layer."""

from honeypot_backend.normalization.cowrie import (
    REQUIRED_EVENT_IDS,
    SOURCE,
    compute_event_id,
    is_supported,
    normalize,
    supported_event_ids,
)
from honeypot_backend.normalization.events import EventCategory, EventOutcome, NormalizedEvent
from honeypot_backend.normalization.fields import NormalizationError

__all__ = [
    "REQUIRED_EVENT_IDS",
    "SOURCE",
    "EventCategory",
    "EventOutcome",
    "NormalizedEvent",
    "NormalizationError",
    "compute_event_id",
    "is_supported",
    "normalize",
    "supported_event_ids",
]
