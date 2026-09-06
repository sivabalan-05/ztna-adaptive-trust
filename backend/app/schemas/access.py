"""Resource catalogue, access decisions and policy administration."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ResourceOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str
    category: str
    sensitivity: str
    min_trust_score: int
    owner: str
    enabled: bool
    has_file: bool = False
    file_name: str | None = None
    content_type: str | None = None
    file_size: int | None = None


class ResourceReachability(ResourceOut):
    """A resource plus whether *this* session could open it right now."""

    reachable: bool
    action: str
    reason: str
    gate: str = Field(
        description="Which gate refuses it: clearance, policy, trust or resource"
    )
    required_score: int
    matched_policy: str


class ResourceCreate(BaseModel):
    """A new catalogue entry. The file, if any, is attached separately."""

    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=2, max_length=128)
    description: str = ""
    category: str = Field(default="application", max_length=64)
    sensitivity: str = Field(default="INTERNAL",
                             pattern="^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    owner: str = Field(default="", max_length=96)
    #: Left unset, the sensitivity's own floor is applied.
    min_trust_score: int | None = Field(default=None, ge=0, le=100)


class ResourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=128)
    description: str | None = None
    category: str | None = Field(default=None, max_length=64)
    sensitivity: str | None = Field(
        default=None, pattern="^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$"
    )
    owner: str | None = Field(default=None, max_length=96)
    min_trust_score: int | None = Field(default=None, ge=0, le=100)
    enabled: bool | None = None


class PolicyEvaluationOut(BaseModel):
    name: str
    effect: str
    priority: int
    matched: bool
    decisive: bool
    unmet_conditions: list[str]


class AccessDecisionOut(BaseModel):
    resource: str
    sensitivity: str
    granted: bool
    action: str
    reason: str
    gate: str
    matched_policy: str
    required_score: int
    trust_score: float
    risk_level: str
    latency_ms: float
    policies_evaluated: list[PolicyEvaluationOut]


class PolicyOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    role: str | None = None
    resource: str | None = None
    sensitivity: str | None = None
    min_trust_score: int
    require_mfa: bool
    require_known_device: bool
    deny_vpn: bool
    allowed_countries: list[str]
    time_window: dict[str, Any]
    effect: str
    priority: int
    enabled: bool


class PolicyCreate(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    description: str = ""
    role: str | None = Field(default=None, description="Role name, or null for any")
    resource: str | None = Field(default=None, description="Resource slug, or null")
    sensitivity: str | None = None
    min_trust_score: int = Field(default=0, ge=0, le=100)
    require_mfa: bool = False
    require_known_device: bool = False
    deny_vpn: bool = False
    allowed_countries: list[str] = Field(default_factory=list)
    time_window: dict[str, Any] = Field(default_factory=dict)
    effect: str = Field(default="ALLOW", pattern="^(ALLOW|DENY)$")
    priority: int = Field(default=100, ge=0, le=1000)
    enabled: bool = True


class PolicyUpdate(BaseModel):
    description: str | None = None
    min_trust_score: int | None = Field(default=None, ge=0, le=100)
    require_mfa: bool | None = None
    require_known_device: bool | None = None
    deny_vpn: bool | None = None
    allowed_countries: list[str] | None = None
    time_window: dict[str, Any] | None = None
    priority: int | None = Field(default=None, ge=0, le=1000)
    enabled: bool | None = None


class AccessRequestOut(BaseModel):
    id: uuid.UUID
    requested_at: datetime
    resource: str | None
    path: str
    score_at_request: float
    risk_level: str
    decision: str
    granted: bool
    reason: str
    matched_policy: str
    latency_ms: float
