"""Action decision engine: risk level plus resource sensitivity to an action.

The baseline action comes from the risk band alone. When a specific resource is
being requested, its trust floor is applied on top: a MEDIUM session may keep
browsing internal pages while still being refused the payroll database.

Role policies are evaluated separately by the policy engine in Phase 5. Both
must pass — least privilege means the score is necessary, not sufficient.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import AccessAction, RiskLevel, SENSITIVITY_MIN_TRUST, Sensitivity

#: What each risk band permits when no particular resource is named.
BASELINE_ACTION: dict[RiskLevel, AccessAction] = {
    RiskLevel.LOW: AccessAction.ALLOW,
    RiskLevel.MEDIUM: AccessAction.ALLOW_LIMITED,
    RiskLevel.HIGH: AccessAction.STEP_UP_MFA,
    RiskLevel.CRITICAL: AccessAction.REVOKE_SESSION,
}


@dataclass(frozen=True)
class Decision:
    action: AccessAction
    granted: bool
    reason: str
    required_score: int | None = None


def baseline_action(risk: RiskLevel) -> AccessAction:
    return BASELINE_ACTION[risk]


def decide(
    score: float,
    risk: RiskLevel,
    sensitivity: Sensitivity | None = None,
    resource_min_trust: int | None = None,
    resource_name: str = "",
) -> Decision:
    """Resolve the enforcement action for this score, optionally for a resource."""
    action = baseline_action(risk)

    if risk is RiskLevel.CRITICAL:
        return Decision(
            action=AccessAction.REVOKE_SESSION,
            granted=False,
            reason=(
                f"Trust score {score:.0f} is in the CRITICAL band; the session is "
                f"revoked and an alert raised."
            ),
        )

    if sensitivity is None and resource_min_trust is None:
        return Decision(
            action=action,
            granted=action in (AccessAction.ALLOW, AccessAction.ALLOW_LIMITED),
            reason=(
                f"Trust score {score:.0f} places this session in the {risk.value} band."
            ),
        )

    floor = (
        resource_min_trust
        if resource_min_trust is not None
        else SENSITIVITY_MIN_TRUST[sensitivity]  # type: ignore[index]
    )
    label = resource_name or (sensitivity.value if sensitivity else "this resource")

    if score >= floor:
        return Decision(
            action=action,
            granted=action in (AccessAction.ALLOW, AccessAction.ALLOW_LIMITED),
            reason=(
                f"Trust score {score:.0f} meets the floor of {floor} required for "
                f"{label}."
            ),
            required_score=floor,
        )

    # The score clears its band but not this resource's bar. Step-up is offered
    # when re-authenticating could plausibly close the gap; otherwise refuse.
    escalated = (
        AccessAction.STEP_UP_MFA if risk in (RiskLevel.LOW, RiskLevel.MEDIUM)
        else AccessAction.BLOCK
    )
    return Decision(
        action=escalated,
        granted=False,
        reason=(
            f"Trust score {score:.0f} is below the floor of {floor} required for "
            f"{label}."
        ),
        required_score=floor,
    )
