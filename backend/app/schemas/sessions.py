"""Live session monitoring and revocation."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class LiveSessionOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    username: str
    full_name: str
    role: str
    status: str
    ip_address: str
    city: str
    country: str
    is_vpn: bool
    device_label: str | None
    device_status: str | None
    started_at: datetime
    last_seen_at: datetime
    last_verified_at: datetime | None
    expires_at: datetime
    current_trust_score: float
    current_risk_level: str
    current_action: str
    mfa_passed: bool
    step_up_required: bool
    request_count: int
    denied_count: int
    revoked_reason: str


class RevokeRequest(BaseModel):
    reason: str = Field(
        default="Revoked by an administrator.", min_length=3, max_length=255
    )


class SessionSummary(BaseModel):
    active_sessions: int
    by_risk_level: dict[str, int]
    average_trust_score: float | None
    verification_interval_seconds: int
    live_subscribers: int


class SweepOut(BaseModel):
    checked: int
    revoked: int
    expired: int
    escalated: int
    improved: int
    errors: int
    duration_ms: float
    changes: list[dict]
