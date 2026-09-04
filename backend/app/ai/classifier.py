"""Risk level classification: a 0-100 score to one of four bands."""

from __future__ import annotations

from app.core.config import settings
from app.models.enums import RiskLevel

#: Human-readable band descriptions, used by the dashboard legend.
BAND_DESCRIPTIONS: dict[RiskLevel, str] = {
    RiskLevel.LOW: "Behaviour matches the established baseline; full access.",
    RiskLevel.MEDIUM: "Something is off; read-only access, sensitive resources hidden.",
    RiskLevel.HIGH: "Materially unusual; re-authentication required to continue.",
    RiskLevel.CRITICAL: "Access denied and the session terminated.",
}


def classify(score: float) -> RiskLevel:
    if score >= settings.risk_low_min:
        return RiskLevel.LOW
    if score >= settings.risk_medium_min:
        return RiskLevel.MEDIUM
    if score >= settings.risk_high_min:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def band_bounds(level: RiskLevel) -> tuple[int, int]:
    """Inclusive ``(lower, upper)`` score bounds for a band."""
    if level is RiskLevel.LOW:
        return settings.risk_low_min, 100
    if level is RiskLevel.MEDIUM:
        return settings.risk_medium_min, settings.risk_low_min - 1
    if level is RiskLevel.HIGH:
        return settings.risk_high_min, settings.risk_medium_min - 1
    return 0, settings.risk_high_min - 1


def bands() -> list[dict[str, object]]:
    """The full band table, for the API and the dashboard legend."""
    return [
        {
            "level": level.value,
            "min": band_bounds(level)[0],
            "max": band_bounds(level)[1],
            "description": BAND_DESCRIPTIONS[level],
        }
        for level in (
            RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL
        )
    ]
