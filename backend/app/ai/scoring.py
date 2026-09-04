"""Adaptive trust scoring: the six factors.

    trust_score = clamp(0, 100, 100 - sum(penalty_i * weight_i / 100))

Every factor returns a normalised 0-100 penalty, a weight, the raw signals it
looked at, and plain-English reasons. A bare number is never returned: if the
score drops to 42, this module can say exactly which factors cost what.

| Factor    | Weight | What it looks at                                        |
|-----------|--------|---------------------------------------------------------|
| Identity  | 25     | password strength, MFA outcome, failed-login streak,     |
|           |        | credential age, account status                           |
| Device    | 20     | known/unknown fingerprint, approval, OS-browser drift    |
| Network   | 20     | IP reputation, VPN/proxy/Tor, ASN type, mid-session drift |
| Behaviour | 20     | anomaly score, profile deviation, request-rate spike,     |
|           |        | unusual or denied resource access                        |
| Location  | 10     | distance from usual, new country, impossible travel      |
| Temporal  | 5      | login hour vs typical window, weekend, duration outlier  |
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.config import settings
from app.models.enums import TrustFactorName


@dataclass
class TrustSignals:
    """Every input the six factors are allowed to see.

    Assembled by ``app.ai.profiling.build_signals`` from the ContextBundle, the
    user, the session and the behaviour profile. Defaults describe a clean,
    unremarkable session so that a missing signal never invents risk.
    """

    # --- Identity ---------------------------------------------------------
    mfa_passed: bool = True
    mfa_skipped: bool = False
    mfa_failures: int = 0
    failed_auth_count_24h: int = 0
    password_strength: int = 70
    credential_age_days: int = 30
    account_locked: bool = False

    # --- Device -----------------------------------------------------------
    is_known_device: bool = True
    device_approved: bool = True
    device_trusted: bool = True
    device_first_seen_days: int = 90
    os_browser_consistent: bool = True

    # --- Network ----------------------------------------------------------
    ip_reputation: int = 0
    is_vpn: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    ip_changed_mid_session: bool = False
    location_resolved: bool = True

    # --- Behaviour --------------------------------------------------------
    #: Isolation Forest output, 0-1. None until Phase 6 trains a model; the
    #: factor then falls back to measurable profile deviation alone.
    anomaly_score: float | None = None
    profile_deviation: float = 0.0
    requests_per_minute: float = 2.0
    baseline_requests_per_minute: float = 2.0
    distinct_resources: int = 3
    baseline_distinct_resources: float = 3.0
    unusual_resource_access: bool = False
    denied_access_count: int = 0

    # --- Location ---------------------------------------------------------
    distance_from_usual_km: float = 0.0
    is_new_country: bool = False
    travel_velocity_kmh: float = 0.0

    # --- Temporal ---------------------------------------------------------
    hour_of_day: int = 10
    typical_hour: float = 10.0
    hour_spread: float = 2.0
    is_weekend: bool = False
    session_duration_min: float = 60.0
    baseline_session_duration_min: float = 60.0

    #: True when the user has too little history for the profile-based signals
    #: to mean anything. Behaviour and temporal penalties are damped rather than
    #: fabricated for a brand-new account.
    profile_is_cold: bool = False


@dataclass
class FactorResult:
    """One row of the explainable breakdown."""

    factor: TrustFactorName
    weight: int
    penalty: float                       # 0-100, before weighting
    points_deducted: float               # penalty * weight / 100
    reasons: list[str] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)

    @property
    def reason(self) -> str:
        return " ".join(self.reasons) if self.reasons else (
            "Nothing unusual observed for this factor."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor": self.factor.value,
            "weight": self.weight,
            "penalty": round(self.penalty, 2),
            "points_deducted": round(self.points_deducted, 2),
            "reason": self.reason,
            "reasons": list(self.reasons),
            "signals": self.signals,
        }


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


# ---------------------------------------------------------------------------
# the six factors
# ---------------------------------------------------------------------------

def identity_factor(s: TrustSignals) -> FactorResult:
    penalty = 0.0
    reasons: list[str] = []

    if s.account_locked:
        penalty += 100
        reasons.append("Account is locked.")
    if not s.mfa_passed:
        if s.mfa_skipped:
            penalty += 55
            reasons.append("Multi-factor authentication was never completed.")
        else:
            penalty += 70
            reasons.append("Multi-factor authentication failed.")
    if s.mfa_failures:
        penalty += min(20.0, s.mfa_failures * 8.0)
        reasons.append(f"{s.mfa_failures} incorrect verification code(s) this session.")
    if s.failed_auth_count_24h:
        penalty += min(60.0, s.failed_auth_count_24h * 12.0)
        reasons.append(
            f"{s.failed_auth_count_24h} failed authentication attempt(s) in the "
            f"last 24 hours."
        )
    if s.password_strength < 50:
        penalty += 20
        reasons.append(f"Password strength is weak ({s.password_strength}/100).")
    if s.credential_age_days > 180:
        penalty += 10
        reasons.append(f"Password is {s.credential_age_days} days old.")

    return FactorResult(
        TrustFactorName.IDENTITY, 0, clamp(penalty), 0.0, reasons,
        {
            "mfa_passed": s.mfa_passed,
            "mfa_failures": s.mfa_failures,
            "failed_auth_count_24h": s.failed_auth_count_24h,
            "password_strength": s.password_strength,
            "credential_age_days": s.credential_age_days,
            "account_locked": s.account_locked,
        },
    )


def device_factor(s: TrustSignals) -> FactorResult:
    penalty = 0.0
    reasons: list[str] = []

    if not s.is_known_device:
        penalty += 85
        reasons.append("Device fingerprint has never been seen on this account.")
    elif not s.device_approved:
        penalty += 30
        reasons.append(
            "Device is registered but still awaiting administrator approval."
        )
    elif s.device_first_seen_days < 3:
        penalty += 15
        reasons.append(
            f"Device was first seen only {s.device_first_seen_days} day(s) ago."
        )
    elif not s.device_trusted:
        penalty += 8
        reasons.append("Device is approved but has not yet built a usage history.")

    if not s.os_browser_consistent:
        penalty += 40
        reasons.append(
            "Operating system or browser no longer matches the registered "
            "fingerprint, which suggests the fingerprint is being reused."
        )

    return FactorResult(
        TrustFactorName.DEVICE, 0, clamp(penalty), 0.0, reasons,
        {
            "is_known_device": s.is_known_device,
            "device_approved": s.device_approved,
            "device_trusted": s.device_trusted,
            "device_first_seen_days": s.device_first_seen_days,
            "os_browser_consistent": s.os_browser_consistent,
        },
    )


def network_factor(s: TrustSignals) -> FactorResult:
    penalty = 0.0
    reasons: list[str] = []

    if s.ip_reputation > 0:
        penalty += s.ip_reputation * 0.9
        reasons.append(
            f"Source address carries an abuse confidence of {s.ip_reputation}/100."
        )
    if s.is_tor:
        penalty += 55
        reasons.append("Connection arrives through a Tor exit node.")
    elif s.is_vpn:
        penalty += 40
        reasons.append("Connection arrives through a VPN or anonymising proxy.")
    elif s.is_datacenter:
        penalty += 30
        reasons.append(
            "Source network is a hosting provider rather than a residential ISP."
        )
    if s.ip_changed_mid_session:
        penalty += 50
        reasons.append("Source address changed in the middle of an active session.")

    return FactorResult(
        TrustFactorName.NETWORK, 0, clamp(penalty), 0.0, reasons,
        {
            "ip_reputation": s.ip_reputation,
            "is_vpn": s.is_vpn,
            "is_tor": s.is_tor,
            "is_datacenter": s.is_datacenter,
            "ip_changed_mid_session": s.ip_changed_mid_session,
        },
    )


def behavior_factor(s: TrustSignals) -> FactorResult:
    penalty = 0.0
    reasons: list[str] = []
    damping = 0.4 if s.profile_is_cold else 1.0

    if s.anomaly_score is not None:
        step = s.anomaly_score * 70.0 * damping
        penalty += step
        reasons.append(
            f"Isolation Forest scores this session {s.anomaly_score:.2f} on a "
            f"0-1 anomaly scale."
        )
    elif s.profile_deviation > 0:
        # No trained model yet: measurable deviation from the stored profile is
        # used on its own rather than inventing an anomaly score.
        step = s.profile_deviation * 70.0 * damping
        penalty += step
        reasons.append(
            f"Session deviates from this account's established behaviour "
            f"profile (deviation {s.profile_deviation:.2f})."
        )

    baseline_rpm = max(0.5, s.baseline_requests_per_minute)
    ratio = s.requests_per_minute / baseline_rpm
    if ratio > 3.0:
        penalty += min(35.0, (ratio - 3.0) * 12.0 + 15.0) * damping
        reasons.append(
            f"Request rate is {ratio:.1f} times normal "
            f"({s.requests_per_minute:.1f} against a baseline of {baseline_rpm:.1f} "
            f"per minute)."
        )

    baseline_res = max(1.0, s.baseline_distinct_resources)
    res_ratio = s.distinct_resources / baseline_res
    if res_ratio > 3.0:
        penalty += min(30.0, (res_ratio - 3.0) * 8.0 + 12.0) * damping
        reasons.append(
            f"Touched {s.distinct_resources} distinct resources against a "
            f"baseline of {baseline_res:.1f}."
        )

    if s.unusual_resource_access:
        penalty += 25 * damping
        reasons.append("Accessed resources this account has never opened before.")

    if s.denied_access_count:
        penalty += min(55.0, s.denied_access_count * 14.0)
        reasons.append(
            f"{s.denied_access_count} access attempt(s) already denied by policy "
            f"in this session."
        )

    if s.profile_is_cold and reasons:
        reasons.append(
            "Penalties are damped: this account has too little history for a "
            "reliable behavioural baseline."
        )

    return FactorResult(
        TrustFactorName.BEHAVIOR, 0, clamp(penalty), 0.0, reasons,
        {
            "anomaly_score": s.anomaly_score,
            "profile_deviation": round(s.profile_deviation, 3),
            "requests_per_minute": round(s.requests_per_minute, 2),
            "baseline_requests_per_minute": round(baseline_rpm, 2),
            "distinct_resources": s.distinct_resources,
            "baseline_distinct_resources": round(baseline_res, 2),
            "unusual_resource_access": s.unusual_resource_access,
            "denied_access_count": s.denied_access_count,
            "profile_is_cold": s.profile_is_cold,
        },
    )


def location_factor(s: TrustSignals) -> FactorResult:
    penalty = 0.0
    reasons: list[str] = []

    if not s.location_resolved:
        penalty += 15
        reasons.append(
            "Source address could not be geolocated, so location cannot be "
            "corroborated."
        )

    d = s.distance_from_usual_km
    if d > 5000:
        penalty += 70
        reasons.append(f"Sign-in is {d:,.0f} km from this account's usual location.")
    elif d > 2000:
        penalty += 50
        reasons.append(f"Sign-in is {d:,.0f} km from this account's usual location.")
    elif d > 500:
        penalty += 30
        reasons.append(f"Sign-in is {d:,.0f} km from this account's usual location.")
    elif d > 150:
        penalty += 12
        reasons.append(f"Sign-in is {d:,.0f} km from this account's usual location.")

    if s.is_new_country:
        penalty += 55
        reasons.append("First recorded sign-in from this country.")

    if s.travel_velocity_kmh > settings.impossible_travel_kmh:
        penalty += 100
        speed = (
            "an instantaneous jump" if s.travel_velocity_kmh == float("inf")
            else f"{s.travel_velocity_kmh:,.0f} km/h"
        )
        reasons.append(
            f"Impossible travel: {speed} implied since the previous sign-in."
        )

    return FactorResult(
        TrustFactorName.LOCATION, 0, clamp(penalty), 0.0, reasons,
        {
            "distance_from_usual_km": round(d, 1),
            "is_new_country": s.is_new_country,
            "travel_velocity_kmh": (
                None if s.travel_velocity_kmh == float("inf")
                else round(s.travel_velocity_kmh, 1)
            ),
            "location_resolved": s.location_resolved,
        },
    )


def temporal_factor(s: TrustSignals) -> FactorResult:
    penalty = 0.0
    reasons: list[str] = []
    damping = 0.4 if s.profile_is_cold else 1.0

    # Circular distance: 23:00 and 01:00 are two hours apart, not twenty-two.
    raw = abs(s.hour_of_day - s.typical_hour)
    hour_delta = min(raw, 24.0 - raw)
    spread = max(1.0, s.hour_spread)
    z = hour_delta / spread
    if z > 2.0:
        penalty += min(60.0, (z - 2.0) * 20.0 + 15.0) * damping
        reasons.append(
            f"Signed in at {s.hour_of_day:02d}:00, {hour_delta:.1f} hours outside "
            f"this account's usual window of around "
            f"{int(s.typical_hour):02d}:00."
        )

    if s.is_weekend:
        penalty += 20 * damping
        reasons.append("Weekend access, which is unusual for this account.")

    baseline_duration = max(5.0, s.baseline_session_duration_min)
    if s.session_duration_min > baseline_duration * 3:
        penalty += 25 * damping
        reasons.append(
            f"Session has run {s.session_duration_min:.0f} minutes against a "
            f"typical {baseline_duration:.0f}."
        )

    return FactorResult(
        TrustFactorName.TEMPORAL, 0, clamp(penalty), 0.0, reasons,
        {
            "hour_of_day": s.hour_of_day,
            "typical_hour": round(s.typical_hour, 1),
            "hour_delta_hours": round(hour_delta, 2),
            "is_weekend": s.is_weekend,
            "session_duration_min": round(s.session_duration_min, 1),
        },
    )


FACTOR_FUNCTIONS = {
    TrustFactorName.IDENTITY: identity_factor,
    TrustFactorName.DEVICE: device_factor,
    TrustFactorName.NETWORK: network_factor,
    TrustFactorName.BEHAVIOR: behavior_factor,
    TrustFactorName.LOCATION: location_factor,
    TrustFactorName.TEMPORAL: temporal_factor,
}


def evaluate_factors(
    signals: TrustSignals, weights: dict[str, int] | None = None
) -> tuple[float, list[FactorResult]]:
    """Run all six factors and return ``(weighted_score, breakdown)``."""
    weights = weights or settings.trust_weights
    breakdown: list[FactorResult] = []
    total_deduction = 0.0

    for name, func in FACTOR_FUNCTIONS.items():
        result = func(signals)
        result.weight = weights[name.value]
        result.points_deducted = result.penalty * result.weight / 100.0
        total_deduction += result.points_deducted
        breakdown.append(result)

    return clamp(100.0 - total_deduction), breakdown
