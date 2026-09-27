"""Wire format of the ingestion API (RF-01)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CheckpointInfo(BaseModel):
    """Byte position of the agent inside ``cowrie.json``.

    ``offset`` is the position just past the last line covered by the batch, so
    the agent can resume reading exactly where this batch ended.
    """

    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=1024)
    offset: int = Field(ge=0)
    inode: int | None = None
    updated_at: datetime | None = None


class IngestBatch(BaseModel):
    """A batch of raw Cowrie events shipped by the agent."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    batch_id: str = Field(min_length=1, max_length=128)
    sequence: int | None = Field(default=None, ge=0)
    sent_at: datetime | None = None
    checkpoint: CheckpointInfo | None = None
    events: list[dict[str, Any]] = Field(min_length=1)


class RejectedEvent(BaseModel):
    """An event that could not be normalized."""

    index: int = Field(ge=0)
    reason: str = Field(max_length=512)


class IngestResponse(BaseModel):
    """Acknowledgement of a batch.

    The echoed ``checkpoint`` confirms the read position the backend durably
    stored; the agent only advances its own checkpoint after receiving it.
    """

    batch_id: str
    received: int
    accepted: int
    normalized: int
    duplicates: int
    rejected: list[RejectedEvent] = Field(default_factory=list)
    checkpoint: CheckpointInfo | None = None
