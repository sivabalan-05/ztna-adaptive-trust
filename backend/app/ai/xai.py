"""Explainable AI: turn a score into an account a person can argue with.

Every assessment carries the full per-factor breakdown — raw signal, weight,
points contributed, plain-English reason — plus a headline naming the factor
that cost the most. When a panel asks "why did it drop to 42?", the answer is
in the record, not reconstructed afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.ai.classifier import classify
from app.ai.decision import Decision, decide
from app.ai.overrides import Override, apply as apply_overrides
from app.ai.scoring import FactorResult, TrustSignals, evaluate_factors
from app.core.config import settings
from app.models.enums import AccessAction, RiskLevel, Sensitivity


@dataclass
class TrustAssessment:
    """The complete, self-describing result of one evaluation."""

    score: float
    weighted_score: float              # before any override clamp
    risk_level: RiskLevel
    action: AccessAction
    factors: list[FactorResult]
    overrides: list[Override] = field(default_factory=list)
    headline: str = ""
    anomaly_score: float | None = None
    decision: Decision | None = None

    @property
    def was_overridden(self) -> bool:
        return bool(self.overrides) and self.score < self.weighted_score

    @property
    def total_deducted(self) -> float:
        return round(100.0 - self.score, 2)

    def top_factors(self, limit: int = 3) -> list[FactorResult]:
        """The factors that actually moved the score, worst first."""
        moved = [f for f in self.factors if f.points_deducted >= 0.5]
        return sorted(moved, key=lambda f: f.points_deducted, reverse=True)[:limit]

    def factor_payload(self) -> list[dict[str, Any]]:
        """What gets stored in ``trust_scores.factors``."""
        payload = [f.to_dict() for f in self.factors]
        if self.was_overridden:
            payload.append(
                {
                    "factor": "override",
                    "weight": 0,
                    "penalty": round(self.weighted_score - self.score, 2),
                    "points_deducted": round(self.weighted_score - self.score, 2),
                    "reason": self.overrides[0].reason if self.overrides else "",
                    "reasons": [o.reason for o in self.overrides],
                    "signals": {
                        "applied_overrides": [o.name for o in self.overrides],
                        "weighted_score": round(self.weighted_score, 2),
                        "clamped_to": round(self.score, 2),
                    },
                }
            )
        return payload

    def narrative(self) -> str:
        """A short paragraph a human can read on the dashboard."""
        if self.was_overridden:
            return self.overrides[0].reason

        movers = self.top_factors()
        if not movers:
            return (
                f"Trust {self.score:.0f}/100. All six factors are within this "
                f"account's normal range."
            )

        parts = [
            f"{f.factor.value} cost {f.points_deducted:.0f} points ({f.reasons[0]})"
            for f in movers
        ]
        return (
            f"Trust {self.score:.0f}/100, {self.total_deducted:.0f} points "
            f"deducted. " + "; ".join(parts)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "weighted_score": round(self.weighted_score, 2),
            "risk_level": self.risk_level.value,
            "action": self.action.value,
            "anomaly_score": self.anomaly_score,
            "headline": self.headline,
            "narrative": self.narrative(),
            "total_deducted": self.total_deducted,
            "was_overridden": self.was_overridden,
            "applied_overrides": [o.name for o in self.overrides],
            "factors": self.factor_payload(),
            "weights": settings.trust_weights,
        }


def _headline(
    score: float, factors: list[FactorResult], overrides: list[Override]
) -> str:
    if overrides:
        return overrides[0].reason
    worst = max(factors, key=lambda f: f.points_deducted)
    if worst.points_deducted < 0.5:
        return "All six trust factors are within this account's normal range."
    return (
        f"{worst.factor.value.capitalize()} factor cost "
        f"{worst.points_deducted:.0f} points: {worst.reasons[0]}"
    )


def assess(
    signals: TrustSignals,
    *,
    sensitivity: Sensitivity | None = None,
    resource_min_trust: int | None = None,
    resource_name: str = "",
    weights: dict[str, int] | None = None,
) -> TrustAssessment:
    """Score, classify, decide and explain — the single entry point.

    Everything that needs a trust score calls this: the login path, the
    continuous-verification worker, the policy enforcement point, the demo
    scripts and the seeder. There is exactly one implementation.
    """
    weighted_score, factors = evaluate_factors(signals, weights)
    score, overrides = apply_overrides(weighted_score, signals)

    # An override that fires while the arithmetic is already stricter should
    # not *raise* the score, so keep the lower of the two.
    score = min(score, weighted_score)

    risk = classify(score)
    decision = decide(
        score, risk,
        sensitivity=sensitivity,
        resource_min_trust=resource_min_trust,
        resource_name=resource_name,
    )

    return TrustAssessment(
        score=round(score, 2),
        weighted_score=round(weighted_score, 2),
        risk_level=risk,
        action=decision.action,
        factors=factors,
        overrides=overrides,
        headline=_headline(score, factors, overrides),
        anomaly_score=signals.anomaly_score,
        decision=decision,
    )
