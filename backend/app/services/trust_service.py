"""Trust evaluation service: score a session, persist it, enforce the outcome.

Single entry point for everything that needs a score — the login path, the
continuous-verification worker (Phase 8), the policy enforcement point
(Phase 5) and the demo scripts (Phase 10). Each evaluation writes a
``trust_scores`` row carrying the full factor breakdown, so every decision the
platform makes stays defensible afterwards.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy.orm import Session

from app.ai import anomaly, profiling
from app.ai.scoring import TrustSignals
from app.ai.xai import TrustAssessment, assess
from app.core.context import ContextBundle
from app.models.alert import Alert
from app.models.base import utcnow
from app.models.device import Device
from app.models.enums import (
    AccessAction, AlertSeverity, RiskLevel, ScoreTrigger, Sensitivity,
    SessionStatus,
)
from app.models.session import UserSession
from app.models.trust_score import TrustScore
from app.models.user import User
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

#: Bands that warrant an alert when a session first enters them.
ALERTING_RISK = {
    RiskLevel.HIGH: AlertSeverity.HIGH,
    RiskLevel.CRITICAL: AlertSeverity.CRITICAL,
}


class TrustService:
    @staticmethod
    def evaluate(
        db: Session,
        *,
        user: User,
        session: UserSession,
        bundle: ContextBundle,
        trigger: ScoreTrigger,
        device: Device | None = None,
        sensitivity: Sensitivity | None = None,
        resource_min_trust: int | None = None,
        resource_name: str = "",
    ) -> tuple[TrustAssessment, TrustScore]:
        """Score the session as it stands right now and record the result."""
        signals = profiling.build_signals(
            db, user=user, session=session, bundle=bundle, device=device
        )

        # Ask the Isolation Forest, if one has been trained. When none has,
        # ``score`` returns None and the behaviour factor says so rather than
        # pretending the session was checked.
        features = profiling.features_for_model(signals, bundle)
        signals.anomaly_score, model_used = anomaly.score_for_user(features, user.id)

        assessment = assess(
            signals,
            sensitivity=sensitivity,
            resource_min_trust=resource_min_trust,
            resource_name=resource_name,
        )

        row = TrustScore(
            session_id=session.id,
            user_id=user.id,
            score=assessment.score,
            risk_level=assessment.risk_level,
            action=assessment.action,
            trigger=trigger,
            anomaly_score=assessment.anomaly_score,
            factors=assessment.factor_payload(),
            reason=assessment.headline,
        )
        db.add(row)

        previous_risk = session.current_risk_level
        session.current_trust_score = assessment.score
        session.current_risk_level = assessment.risk_level
        session.current_action = assessment.action
        session.last_verified_at = utcnow()
        db.flush()

        logger.debug(
            "Scored session %s at %.1f using %s",
            session.id, assessment.score, model_used,
        )
        TrustService._enforce(
            db, user=user, session=session, assessment=assessment,
            previous_risk=previous_risk, bundle=bundle, trigger=trigger,
        )
        return assessment, row

    @staticmethod
    def _enforce(
        db: Session,
        *,
        user: User,
        session: UserSession,
        assessment: TrustAssessment,
        previous_risk: RiskLevel,
        bundle: ContextBundle,
        trigger: ScoreTrigger,
    ) -> None:
        """Apply the action the score demands, mid-session if necessary."""
        risk = assessment.risk_level

        if assessment.action is AccessAction.STEP_UP_MFA:
            session.step_up_required = True

        if risk is RiskLevel.CRITICAL and session.status is SessionStatus.ACTIVE:
            from app.services.auth_service import AuthService

            AuthService.revoke_session(
                db, session,
                reason=f"Trust score fell to {assessment.score:.0f}: {assessment.headline}",
                actor_label="trust-engine",
            )

        worsened = _band_index(risk) > _band_index(previous_risk)
        if risk in ALERTING_RISK and (worsened or trigger is ScoreTrigger.LOGIN):
            db.add(
                Alert(
                    user_id=user.id,
                    session_id=session.id,
                    severity=ALERTING_RISK[risk],
                    category=(
                        assessment.overrides[0].name if assessment.overrides
                        else "low_trust_score"
                    ),
                    title=(
                        f"Trust score {assessment.score:.0f} ({risk.value}) for "
                        f"{user.username}"
                    ),
                    description=assessment.narrative(),
                    trust_score=assessment.score,
                    evidence={
                        "trigger": trigger.value,
                        "previous_risk": previous_risk.value,
                        "action": assessment.action.value,
                        "network": bundle.network.summary(),
                        "factors": [
                            {
                                "factor": f.factor.value,
                                "points": round(f.points_deducted, 2),
                                "reason": f.reason,
                            }
                            for f in assessment.top_factors(6)
                        ],
                    },
                )
            )

        AuditService.record(
            db,
            action="TRUST_EVALUATED",
            actor_id=user.id,
            actor_label=user.username,
            resource_type="session",
            resource_id=str(session.id),
            ip_address=bundle.ip_address,
            payload={
                "session_id": str(session.id),
                "trigger": trigger.value,
                "score": assessment.score,
                "weighted_score": assessment.weighted_score,
                "risk_level": risk.value,
                "action": assessment.action.value,
                "overrides": [o.name for o in assessment.overrides],
                "headline": assessment.headline,
                "factor_points": {
                    f.factor.value: round(f.points_deducted, 2)
                    for f in assessment.factors
                },
                "anomaly_score": assessment.anomaly_score,
            },
        )

    @staticmethod
    def latest(db: Session, session_id: uuid.UUID) -> TrustScore | None:
        from sqlalchemy import select

        return db.scalar(
            select(TrustScore)
            .where(TrustScore.session_id == session_id)
            .order_by(TrustScore.created_at.desc())
            .limit(1)
        )

    @staticmethod
    def history(
        db: Session, session_id: uuid.UUID, limit: int = 100
    ) -> list[TrustScore]:
        from sqlalchemy import select

        return list(
            db.scalars(
                select(TrustScore)
                .where(TrustScore.session_id == session_id)
                .order_by(TrustScore.created_at)
                .limit(limit)
            )
        )


_BAND_ORDER = {
    RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3,
}


def _band_index(level: RiskLevel) -> int:
    return _BAND_ORDER[level]
