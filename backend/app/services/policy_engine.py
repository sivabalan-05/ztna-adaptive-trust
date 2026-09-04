"""Policy Decision Point.

Least privilege means an access request must clear **three independent gates**,
and failing any one of them is a refusal:

1. **Clearance** — the role's sensitivity ceiling must cover the resource.
2. **Policy** — at least one enabled ALLOW policy must match, and no DENY
   policy of equal or higher priority may match.
3. **Trust** — the live score must meet the resource's floor and every
   condition the matched policy attaches (MFA, known device, no VPN, country,
   time window).

The score is necessary but never sufficient: a contractor with a perfect 100
still cannot open the payroll database, because gate 1 stops them before the
arithmetic is consulted.

Every evaluation returns the full list of policies considered and why each was
or was not decisive, so a refusal can be explained to the person it happened to.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.ai.decision import Decision
from app.core.context import ContextBundle
from app.models.enums import (
    SENSITIVITY_MIN_TRUST, SENSITIVITY_ORDINAL, AccessAction, PolicyEffect,
    RiskLevel, Sensitivity,
)
from app.models.policy import Policy
from app.models.resource import Resource
from app.models.role import Role
from app.models.session import UserSession
from app.models.user import User

logger = logging.getLogger(__name__)


@dataclass
class PolicyEvaluation:
    """One policy that was considered, and what it contributed."""

    name: str
    effect: str
    priority: int
    matched: bool
    decisive: bool = False
    unmet_conditions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "effect": self.effect,
            "priority": self.priority,
            "matched": self.matched,
            "decisive": self.decisive,
            "unmet_conditions": list(self.unmet_conditions),
        }


@dataclass
class PolicyDecision:
    granted: bool
    action: AccessAction
    reason: str
    matched_policy: str = ""
    required_score: int = 0
    gate: str = ""                       # which gate refused: clearance/policy/trust
    evaluations: list[PolicyEvaluation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "granted": self.granted,
            "action": self.action.value,
            "reason": self.reason,
            "matched_policy": self.matched_policy,
            "required_score": self.required_score,
            "gate": self.gate,
            "policies_evaluated": [e.to_dict() for e in self.evaluations],
        }


class PolicyEngine:
    # -- policy lookup -----------------------------------------------------

    @staticmethod
    def applicable_policies(
        db: Session, role: Role, resource: Resource
    ) -> list[Policy]:
        """Enabled policies matching this role and resource, most specific first.

        A NULL match field means "any", so a policy scoped to a sensitivity
        applies to every resource at that level, and a policy with no role
        applies to everyone.
        """
        stmt = (
            select(Policy)
            .where(
                Policy.enabled.is_(True),
                or_(Policy.role_id.is_(None), Policy.role_id == role.id),
                or_(Policy.resource_id.is_(None), Policy.resource_id == resource.id),
                or_(
                    Policy.sensitivity.is_(None),
                    Policy.sensitivity == resource.sensitivity,
                ),
            )
            .order_by(Policy.priority.desc(), Policy.effect.desc(), Policy.name)
        )
        # Within a priority tier, DENY is examined before ALLOW ("DENY" sorts
        # after "ALLOW" alphabetically, so the descending order puts it first).
        return list(db.scalars(stmt))

    # -- condition checks --------------------------------------------------

    @staticmethod
    def unmet_conditions(
        policy: Policy,
        *,
        score: float,
        session: UserSession,
        bundle: ContextBundle,
        device_known: bool,
    ) -> list[str]:
        """Every condition on this policy that the request fails."""
        failures: list[str] = []

        if score < policy.min_trust_score:
            failures.append(
                f"trust score {score:.0f} is below the policy minimum of "
                f"{policy.min_trust_score}"
            )
        if policy.require_mfa and not session.mfa_passed:
            failures.append("multi-factor authentication has not been completed")
        if policy.require_known_device and not device_known:
            failures.append("the device is not a registered, approved device")
        if policy.deny_vpn and (bundle.network.intel.is_anonymised):
            failures.append(
                "the connection arrives through a VPN, proxy or Tor exit node"
            )

        allowed = policy.allowed_countries or []
        country = bundle.network.geo.country
        if allowed and country and country not in allowed:
            failures.append(
                f"sign-in country {country} is not in the permitted list "
                f"({', '.join(allowed)})"
            )

        window = policy.time_window or {}
        if window:
            hour = bundle.temporal.hour_of_day
            start = int(window.get("start_hour", 0))
            end = int(window.get("end_hour", 24))
            if not (start <= hour < end):
                failures.append(
                    f"the request is at {hour:02d}:00, outside the permitted "
                    f"window of {start:02d}:00-{end:02d}:00"
                )
            if window.get("weekdays_only") and bundle.temporal.is_weekend:
                failures.append("the policy permits weekdays only")

        return failures

    # -- the three gates ---------------------------------------------------

    @classmethod
    def evaluate(
        cls,
        db: Session,
        *,
        user: User,
        session: UserSession,
        resource: Resource,
        score: float,
        risk: RiskLevel,
        bundle: ContextBundle,
        device_known: bool,
    ) -> PolicyDecision:
        """Resolve one access request against all three gates."""
        role = user.role
        evaluations: list[PolicyEvaluation] = []

        # --- Gate 0: the resource has to be switched on --------------------
        if not resource.enabled:
            return PolicyDecision(
                granted=False,
                action=AccessAction.BLOCK,
                reason=f"{resource.name} is disabled.",
                gate="resource",
            )

        # --- Gate 1: clearance ---------------------------------------------
        # Checked before anything else: no trust score can lift a role above
        # its ceiling, so saying so first is both cheaper and more honest.
        ceiling = role.max_sensitivity_ordinal
        needed = SENSITIVITY_ORDINAL[resource.sensitivity]
        if needed > ceiling:
            return PolicyDecision(
                granted=False,
                action=AccessAction.BLOCK,
                reason=(
                    f"The {role.name} role is not cleared for "
                    f"{resource.sensitivity.value} resources, so no trust score "
                    f"can grant access to {resource.name}."
                ),
                gate="clearance",
                required_score=resource.min_trust_score,
            )

        # --- Gate 2: policy ------------------------------------------------
        # First-applicable ordering: the highest-priority tier that matches
        # decides, and the decision stops there. A lower-priority permissive
        # policy must never rescue a request that a more specific, higher
        # priority policy refused — otherwise writing a strict rule would have
        # the opposite of its intended effect.
        policies = cls.applicable_policies(db, role, resource)
        if not policies:
            return PolicyDecision(
                granted=False,
                action=AccessAction.BLOCK,
                reason=(
                    f"No policy grants the {role.name} role access to "
                    f"{resource.name}."
                ),
                gate="policy",
                required_score=resource.min_trust_score,
            )

        top_priority = policies[0].priority
        tier = [p for p in policies if p.priority == top_priority]
        lower = [p for p in policies if p.priority < top_priority]

        allowing: Policy | None = None
        near_miss: tuple[Policy, list[str]] | None = None

        for policy in tier:
            unmet = cls.unmet_conditions(
                policy, score=score, session=session, bundle=bundle,
                device_known=device_known,
            )
            evaluation = PolicyEvaluation(
                name=policy.name, effect=policy.effect.value,
                priority=policy.priority, matched=True, unmet_conditions=unmet,
            )
            evaluations.append(evaluation)

            if policy.effect is PolicyEffect.DENY:
                # A DENY needs no conditions met: it matched, so it bites, and
                # it outranks every ALLOW in the same tier.
                evaluation.decisive = True
                return PolicyDecision(
                    granted=False,
                    action=AccessAction.BLOCK,
                    reason=(
                        f"Denied by policy '{policy.name}': {policy.description}"
                        if policy.description
                        else f"Denied by policy '{policy.name}'."
                    ),
                    matched_policy=policy.name,
                    gate="policy",
                    required_score=resource.min_trust_score,
                    evaluations=evaluations,
                )

            if not unmet and allowing is None:
                allowing = policy
                evaluation.decisive = True
            elif unmet and (near_miss is None or len(unmet) < len(near_miss[1])):
                near_miss = (policy, unmet)

        # Record the lower tiers for transparency, but they are not consulted.
        for policy in lower:
            evaluations.append(
                PolicyEvaluation(
                    name=policy.name, effect=policy.effect.value,
                    priority=policy.priority, matched=True,
                    unmet_conditions=["superseded by a higher-priority policy"],
                )
            )

        if allowing is None:
            policy, unmet = near_miss if near_miss else (tier[0], ["no condition met"])
            for evaluation in evaluations:
                if evaluation.name == policy.name:
                    evaluation.decisive = True
            return PolicyDecision(
                granted=False,
                action=cls._refusal_action(risk),
                reason=(
                    f"Policy '{policy.name}' would allow this, but "
                    + "; ".join(unmet)
                    + "."
                ),
                matched_policy=policy.name,
                gate="trust",
                required_score=resource.min_trust_score,
                evaluations=evaluations,
            )

        # --- Gate 3: trust ---------------------------------------------------
        floor = max(
            resource.min_trust_score,
            SENSITIVITY_MIN_TRUST[resource.sensitivity],
        )
        if score < floor:
            return PolicyDecision(
                granted=False,
                action=cls._refusal_action(risk),
                reason=(
                    f"Trust score {score:.0f} is below the floor of {floor} that "
                    f"{resource.name} requires as a "
                    f"{resource.sensitivity.value} resource."
                ),
                matched_policy=allowing.name,
                gate="trust",
                required_score=floor,
                evaluations=evaluations,
            )

        if risk is RiskLevel.CRITICAL:
            return PolicyDecision(
                granted=False,
                action=AccessAction.REVOKE_SESSION,
                reason=(
                    f"Session is in the CRITICAL band ({score:.0f}); access is "
                    f"refused and the session revoked."
                ),
                matched_policy=allowing.name,
                gate="trust",
                required_score=floor,
                evaluations=evaluations,
            )

        action = (
            AccessAction.ALLOW_LIMITED if risk is RiskLevel.MEDIUM
            else AccessAction.ALLOW
        )
        return PolicyDecision(
            granted=True,
            action=action,
            reason=(
                f"Allowed by '{allowing.name}': trust {score:.0f} meets the "
                f"floor of {floor} and the {role.name} role is cleared for "
                f"{resource.sensitivity.value} resources."
            ),
            matched_policy=allowing.name,
            gate="",
            required_score=floor,
            evaluations=evaluations,
        )

    @staticmethod
    def _refusal_action(risk: RiskLevel) -> AccessAction:
        """Offer step-up only when re-authenticating could plausibly help."""
        if risk is RiskLevel.CRITICAL:
            return AccessAction.REVOKE_SESSION
        if risk is RiskLevel.HIGH:
            return AccessAction.BLOCK
        return AccessAction.STEP_UP_MFA

    # -- what the caller can currently reach -------------------------------

    @classmethod
    def reachable(
        cls,
        db: Session,
        *,
        user: User,
        session: UserSession,
        score: float,
        risk: RiskLevel,
        bundle: ContextBundle,
        device_known: bool,
    ) -> list[tuple[Resource, PolicyDecision]]:
        """Evaluate every resource for this session, for the catalogue view."""
        resources = db.scalars(select(Resource).order_by(Resource.name)).all()
        return [
            (
                resource,
                cls.evaluate(
                    db, user=user, session=session, resource=resource,
                    score=score, risk=risk, bundle=bundle,
                    device_known=device_known,
                ),
            )
            for resource in resources
        ]


def as_ai_decision(decision: PolicyDecision) -> Decision:
    """Adapt to the scoring layer's decision shape, for shared reporting."""
    return Decision(
        action=decision.action,
        granted=decision.granted,
        reason=decision.reason,
        required_score=decision.required_score,
    )
