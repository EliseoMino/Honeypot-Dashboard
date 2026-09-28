"""Alert generation for the RF-11 detection rules (RF-12).

:mod:`honeypot_backend.alerts.generation` turns a stored detection into the
alert to raise, and the ``alerts`` table stores it. Only that: the MVP asks for
persistence and consultation, not for external notifications.
"""

from honeypot_backend.alerts.generation import (
    AlertDraft,
    draft_for_detection,
    drafts_for_detections,
)

__all__ = ["AlertDraft", "draft_for_detection", "drafts_for_detections"]
