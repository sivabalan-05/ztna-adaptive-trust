"""User administration, alerts and dashboard aggregates."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class UserRow(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    full_name: str
    department: str
    role: str
    is_admin: bool
    account_status: str
    is_locked: bool
    mfa_enabled: bool
    mfa_enrolled: bool
    last_login_at: datetime | None
    failed_login_count: int
    home_city: str
    home_country: str
    device_count: int
    active_sessions: int
    latest_trust_score: float | None
    latest_risk_level: str | None


class UserUpdate(BaseModel):
    role: str | None = None
    account_status: str | None = Field(
        default=None, pattern="^(ACTIVE|LOCKED|DISABLED|PENDING)$"
    )
    department: str | None = Field(default=None, max_length=64)
    unlock: bool | None = Field(
        default=None, description="Clear the lockout and reset the failure counter"
    )


class AlertRow(BaseModel):
    id: uuid.UUID
    severity: str
    status: str
    category: str
    title: str
    description: str
    trust_score: float | None
    evidence: dict
    user_id: uuid.UUID | None
    username: str | None
    session_id: uuid.UUID | None
    created_at: datetime
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    resolution_note: str


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    alerts: list[AlertRow]


class AlertResolve(BaseModel):
    note: str = Field(default="", max_length=1000)


class AlertStats(BaseModel):
    open: int
    acknowledged: int
    resolved: int
    today: int
    by_severity: dict[str, int]
    by_category: dict[str, int]


class TrustPoint(BaseModel):
    at: datetime
    score: float
    risk_level: str


class RiskSlice(BaseModel):
    level: str
    count: int


class OverviewOut(BaseModel):
    """Everything the dashboard header and its charts need, in one call."""

    active_sessions: int
    average_trust_score: float | None
    alerts_today: int
    open_alerts: int
    blocked_attempts_today: int
    total_users: int
    locked_users: int
    pending_devices: int
    risk_distribution: list[RiskSlice]
    trust_over_time: list[TrustPoint]
    recent_alerts: list[AlertRow]
    verification_interval_seconds: int
    anomaly_model_version: str | None
    audit_records: int
