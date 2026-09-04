"""Trust score API models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FactorOut(BaseModel):
    """One row of the explainable breakdown."""

    factor: str
    weight: int = Field(description="Factor weight out of 100")
    penalty: float = Field(description="Normalised 0-100 penalty before weighting")
    points_deducted: float = Field(description="penalty x weight / 100")
    reason: str = Field(description="Plain-English explanation")
    reasons: list[str] = Field(default_factory=list)
    signals: dict[str, Any] = Field(
        default_factory=dict, description="Raw signals this factor looked at"
    )


class TrustScoreOut(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    user_id: uuid.UUID
    score: float
    risk_level: str
    action: str
    trigger: str
    anomaly_score: float | None = Field(
        default=None,
        description="Isolation Forest output 0-1; null until a model is trained",
    )
    reason: str
    factors: list[FactorOut]
    created_at: datetime


class TrustAssessmentOut(BaseModel):
    """A freshly computed assessment, including what the arithmetic did."""

    score: float
    weighted_score: float = Field(description="Score before any override clamp")
    risk_level: str
    action: str
    anomaly_score: float | None = None
    headline: str
    narrative: str
    total_deducted: float
    was_overridden: bool
    applied_overrides: list[str]
    factors: list[FactorOut]
    weights: dict[str, int]


class RiskBandOut(BaseModel):
    level: str
    min: int
    max: int
    description: str


class TrustConfigOut(BaseModel):
    """The scoring configuration, so the dashboard legend is never hardcoded."""

    weights: dict[str, int]
    bands: list[RiskBandOut]
    sensitivity_floors: dict[str, int]
    overrides: list[dict[str, Any]]
    anomaly_model_available: bool
    anomaly_model: dict[str, Any] | None = Field(
        default=None, description="Version, parameters and accuracy of the model in service"
    )
    continuous_verification_interval_seconds: int


class TrustHistoryPoint(BaseModel):
    at: datetime
    score: float
    risk_level: str
    action: str
    trigger: str
    reason: str
