"""Policy Enforcement Point.

One place where an access request is actually decided:

1. re-score the session against the context of *this* request;
2. put the score, the role and the resource through the policy engine;
3. record an ``access_requests`` row with the decision and its feature vector;
4. enforce — revoke a CRITICAL session, flag a step-up, count the denial;
5. append the decision to the audit chain.

Step 1 matters: the score is recomputed rather than read from the session row,
so a request arriving from a new country is judged on where it came from, not
on how the session looked at sign-in. That is the difference between
continuous verification and a login check.
"""

from __future__ import annotations

import logging
import time

from sqlalchemy.orm import Session

from app.ai import profiling
from app.core.context import ContextBundle
from app.models.access_request import AccessRequest
from app.models.base import utcnow
from app.models.device import Device
from app.models.enums import AccessAction, RiskLevel, ScoreTrigger
from app.models.resource import Resource
from app.models.session import UserSession
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.policy_engine import PolicyDecision, PolicyEngine
from app.services.trust_service import TrustService

logger = logging.getLogger(__name__)


class AccessService:
    @staticmethod
    def request_access(
        db: Session,
        *,
        user: User,
        session: UserSession,
        resource: Resource,
        bundle: ContextBundle,
        device: Device | None = None,
        method: str = "GET",
    ) -> tuple[PolicyDecision, AccessRequest]:
        started = time.perf_counter()

        assessment, score_row = TrustService.evaluate(
            db, user=user, session=session, bundle=bundle,
            trigger=ScoreTrigger.ACCESS_REQUEST, device=device,
            sensitivity=resource.sensitivity,
            resource_min_trust=resource.min_trust_score,
            resource_name=resource.name,
        )

        signals = profiling.build_signals(
            db, user=user, session=session, bundle=bundle, device=device
        )
        device_known = signals.is_known_device and signals.device_approved

        decision = PolicyEngine.evaluate(
            db,
            user=user,
            session=session,
            resource=resource,
            score=assessment.score,
            risk=assessment.risk_level,
            bundle=bundle,
            device_known=device_known,
        )

        latency_ms = (time.perf_counter() - started) * 1000.0

        row = AccessRequest(
            user_id=user.id,
            session_id=session.id,
            resource_id=resource.id,
            trust_score_id=score_row.id,
            requested_at=utcnow(),
            method=method,
            path=f"/api/resources/{resource.slug}",
            ip_address=bundle.ip_address,
            score_at_request=assessment.score,
            risk_level=assessment.risk_level,
            decision=decision.action,
            granted=decision.granted,
            reason=decision.reason,
            matched_policy=decision.matched_policy,
            latency_ms=round(latency_ms, 2),
            features=profiling.features_for_model(signals, bundle),
            is_anomalous=False,   # ground-truth label; only the seeder sets this
            scenario="",
        )
        db.add(row)

        # --- enforcement ---------------------------------------------------
        # Enumeration is measured by what was *attempted*, not by what
        # succeeded. Counting only granted requests would mean an insider
        # probing resources they are refused registers as having enumerated
        # nothing — exactly backwards for the behaviour we want to catch.
        session.distinct_resource_count = _distinct_resources(db, session)
        if not decision.granted:
            session.denied_count += 1
            if decision.action is AccessAction.STEP_UP_MFA:
                session.step_up_required = True

        if (
            decision.action is AccessAction.REVOKE_SESSION
            and assessment.risk_level is RiskLevel.CRITICAL
        ):
            # TrustService already revokes on CRITICAL; this covers a policy
            # that revokes for a reason the score alone did not reach.
            from app.models.enums import SessionStatus
            from app.services.auth_service import AuthService

            if session.status is SessionStatus.ACTIVE:
                AuthService.revoke_session(
                    db, session, reason=decision.reason, actor_label="policy-engine"
                )

        db.flush()

        AuditService.record(
            db,
            action="ACCESS_GRANTED" if decision.granted else "ACCESS_DENIED",
            actor_id=user.id,
            actor_label=user.username,
            resource_type="resource",
            resource_id=resource.slug,
            ip_address=bundle.ip_address,
            payload={
                "resource": resource.slug,
                "sensitivity": resource.sensitivity.value,
                "role": user.role.name,
                "score": assessment.score,
                "risk_level": assessment.risk_level.value,
                "action": decision.action.value,
                "granted": decision.granted,
                "gate": decision.gate,
                "matched_policy": decision.matched_policy,
                "required_score": decision.required_score,
                "reason": decision.reason,
                "latency_ms": round(latency_ms, 2),
            },
        )
        return decision, row


def _distinct_resources(db: Session, session: UserSession) -> int:
    """Distinct resources this session has *reached for*, granted or not."""
    from sqlalchemy import func, select

    return int(
        db.scalar(
            select(func.count(func.distinct(AccessRequest.resource_id))).where(
                AccessRequest.session_id == session.id,
                AccessRequest.resource_id.isnot(None),
            )
        )
        or 0
    )
