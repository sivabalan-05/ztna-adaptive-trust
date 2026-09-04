"""Audit log API models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditRecordOut(BaseModel):
    seq: int = Field(description="Position in the chain; row N commits to N-1")
    id: uuid.UUID
    timestamp: datetime
    actor_id: uuid.UUID | None
    actor_label: str
    action: str
    resource_type: str
    resource_id: str
    ip_address: str
    payload: dict[str, Any]
    payload_hash: str
    prev_hash: str
    record_hash: str
    note: str


class AuditPage(BaseModel):
    total: int
    limit: int
    offset: int
    records: list[AuditRecordOut]


class ChainVerification(BaseModel):
    """The result of walking the hash chain."""

    valid: bool
    records_checked: int
    broken_at: int | None = Field(
        default=None, description="Chain position of the first bad record"
    )
    reason: str | None = None
    head_hash: str
    partial: bool = Field(
        default=False,
        description="True when only a suffix of the chain was verified",
    )
    verified_from: int = 1
    duration_ms: float
    genesis_hash: str
    checked_at: datetime


class AuditStats(BaseModel):
    total_records: int
    first_record_at: datetime | None
    last_record_at: datetime | None
    head_hash: str
    actions: dict[str, int]
    top_actors: dict[str, int]
