"""Unit tests for every trust factor, the classifier, the decision engine and XAI.

Each factor is tested in isolation: one signal moved at a time, so a failure
names the factor and the signal that broke.
"""

from __future__ import annotations

import pytest

from app.ai.classifier import band_bounds, bands, classify
from app.ai.decision import baseline_action, decide
from app.ai.overrides import detect as detect_overrides
from app.ai.scoring import (
    TrustSignals, behavior_factor, device_factor, evaluate_factors,
    identity_factor, location_factor, network_factor, temporal_factor,
)
from app.ai.xai import assess
from app.core.config import settings
from app.models.enums import AccessAction, RiskLevel, Sensitivity, TrustFactorName


def clean() -> TrustSignals:
    """A wholly unremarkable session."""
    return TrustSignals()


# ===========================================================================
# Factor 1 — Identity (weight 25)
# ===========================================================================

def test_identity_clean_session_costs_nothing() -> None:
    assert identity_factor(clean()).penalty == 0.0


def test_identity_penalises_failed_mfa_more_than_skipped_mfa() -> None:
    """A wrong code is worse than never reaching the step."""
    failed = identity_factor(TrustSignals(mfa_passed=False, mfa_skipped=False))
    skipped = identity_factor(TrustSignals(mfa_passed=False, mfa_skipped=True))
    assert failed.penalty > skipped.penalty
    assert "failed" in failed.reason.lower()


def test_identity_failed_login_streak_escalates_then_saturates() -> None:
    penalties = [
        identity_factor(TrustSignals(failed_auth_count_24h=n)).penalty
        for n in (0, 1, 3, 5, 20)
    ]
    assert penalties == sorted(penalties), "penalty must not decrease with failures"
    assert penalties[0] == 0.0
    assert penalties[-1] <= 100.0


def test_identity_weak_password_is_penalised() -> None:
    assert identity_factor(TrustSignals(password_strength=20)).penalty > 0
    assert identity_factor(TrustSignals(password_strength=90)).penalty == 0


def test_identity_stale_credentials_are_penalised() -> None:
    assert identity_factor(TrustSignals(credential_age_days=400)).penalty > 0
    assert identity_factor(TrustSignals(credential_age_days=30)).penalty == 0


def test_identity_locked_account_saturates() -> None:
    assert identity_factor(TrustSignals(account_locked=True)).penalty == 100.0


def test_identity_always_reports_its_signals() -> None:
    result = identity_factor(TrustSignals(failed_auth_count_24h=3))
    assert result.signals["failed_auth_count_24h"] == 3
    assert result.reasons


# ===========================================================================
# Factor 2 — Device (weight 20)
# ===========================================================================

def test_device_known_and_approved_costs_nothing() -> None:
    assert device_factor(clean()).penalty == 0.0


def test_device_unknown_fingerprint_is_the_heaviest_device_signal() -> None:
    unknown = device_factor(TrustSignals(is_known_device=False, device_approved=False))
    pending = device_factor(TrustSignals(device_approved=False))
    assert unknown.penalty > pending.penalty
    assert "never been seen" in unknown.reason


def test_device_pending_approval_is_penalised_but_not_blocked() -> None:
    result = device_factor(TrustSignals(device_approved=False))
    assert 0 < result.penalty < 85, "trust-on-first-use, not a hard gate"


def test_device_brand_new_device_carries_a_small_penalty() -> None:
    assert device_factor(TrustSignals(device_first_seen_days=1)).penalty > 0


def test_device_os_browser_drift_is_penalised() -> None:
    """A fingerprint that no longer matches its user agent is being reused."""
    result = device_factor(TrustSignals(os_browser_consistent=False))
    assert result.penalty >= 40
    assert "no longer match" in result.reason


# ===========================================================================
# Factor 3 — Network (weight 20)
# ===========================================================================

def test_network_clean_residential_costs_nothing() -> None:
    assert network_factor(clean()).penalty == 0.0


def test_network_reputation_scales_with_confidence() -> None:
    low = network_factor(TrustSignals(ip_reputation=25)).penalty
    high = network_factor(TrustSignals(ip_reputation=95)).penalty
    assert high > low > 0


def test_network_tor_outranks_vpn_outranks_datacenter() -> None:
    tor = network_factor(TrustSignals(is_tor=True)).penalty
    vpn = network_factor(TrustSignals(is_vpn=True)).penalty
    dc = network_factor(TrustSignals(is_datacenter=True)).penalty
    assert tor > vpn > dc > 0


def test_network_anonymisers_are_not_double_counted() -> None:
    """Tor is also a datacenter; it must be charged once, not three times."""
    both = network_factor(TrustSignals(is_tor=True, is_vpn=True, is_datacenter=True))
    tor_only = network_factor(TrustSignals(is_tor=True))
    assert both.penalty == tor_only.penalty


def test_network_mid_session_ip_change_is_penalised() -> None:
    result = network_factor(TrustSignals(ip_changed_mid_session=True))
    assert result.penalty >= 50
    assert "changed in the middle" in result.reason


def test_network_penalty_is_clamped_at_100() -> None:
    result = network_factor(
        TrustSignals(ip_reputation=100, is_tor=True, ip_changed_mid_session=True)
    )
    assert result.penalty == 100.0


# ===========================================================================
# Factor 4 — Behaviour (weight 20)
# ===========================================================================

def test_behavior_on_baseline_costs_nothing() -> None:
    assert behavior_factor(clean()).penalty == 0.0


def test_behavior_uses_the_anomaly_score_when_a_model_exists() -> None:
    result = behavior_factor(TrustSignals(anomaly_score=0.9))
    assert result.penalty > 50
    assert "Isolation Forest" in result.reason


def test_behavior_falls_back_to_profile_deviation_without_a_model() -> None:
    """anomaly_score is None until Phase 6; the factor must still work."""
    result = behavior_factor(TrustSignals(anomaly_score=None, profile_deviation=0.8))
    assert result.penalty > 0
    assert result.signals["anomaly_score"] is None
    assert "behaviour profile" in result.reason


def test_behavior_request_rate_spike_is_penalised() -> None:
    calm = behavior_factor(TrustSignals(requests_per_minute=2, baseline_requests_per_minute=2))
    spike = behavior_factor(
        TrustSignals(requests_per_minute=30, baseline_requests_per_minute=2)
    )
    assert spike.penalty > calm.penalty
    assert "times normal" in spike.reason


def test_behavior_resource_enumeration_is_penalised() -> None:
    result = behavior_factor(
        TrustSignals(distinct_resources=40, baseline_distinct_resources=4)
    )
    assert result.penalty > 0
    assert "distinct resources" in result.reason


def test_behavior_policy_denials_escalate() -> None:
    penalties = [
        behavior_factor(TrustSignals(denied_access_count=n)).penalty
        for n in (0, 1, 2, 4)
    ]
    assert penalties == sorted(penalties)
    assert penalties[0] == 0.0


def test_behavior_cold_profile_damps_penalties() -> None:
    """A brand-new account must not be punished for having no history."""
    warm = behavior_factor(TrustSignals(profile_deviation=0.9, profile_is_cold=False))
    cold = behavior_factor(TrustSignals(profile_deviation=0.9, profile_is_cold=True))
    assert cold.penalty < warm.penalty
    assert "too little history" in cold.reason


def test_behavior_denials_are_not_damped_by_a_cold_profile() -> None:
    """A denial is a fact, not a deviation from a baseline."""
    warm = behavior_factor(TrustSignals(denied_access_count=3, profile_is_cold=False))
    cold = behavior_factor(TrustSignals(denied_access_count=3, profile_is_cold=True))
    assert cold.penalty == warm.penalty


# ===========================================================================
# Factor 5 — Location (weight 10)
# ===========================================================================

def test_location_at_home_costs_nothing() -> None:
    assert location_factor(clean()).penalty == 0.0


def test_location_distance_bands_escalate() -> None:
    penalties = [
        location_factor(TrustSignals(distance_from_usual_km=d)).penalty
        for d in (0, 100, 300, 1000, 3000, 9000)
    ]
    assert penalties == sorted(penalties)
    assert penalties[0] == 0.0


def test_location_new_country_is_penalised() -> None:
    result = location_factor(TrustSignals(is_new_country=True))
    assert result.penalty >= 55
    assert "First recorded sign-in from this country" in result.reason


def test_location_impossible_travel_saturates_the_factor() -> None:
    result = location_factor(TrustSignals(travel_velocity_kmh=42_000))
    assert result.penalty == 100.0
    assert "Impossible travel" in result.reason


def test_location_speed_just_below_the_threshold_does_not_fire() -> None:
    below = location_factor(
        TrustSignals(travel_velocity_kmh=settings.impossible_travel_kmh - 1)
    )
    assert "Impossible travel" not in below.reason


def test_location_unresolvable_address_is_penalised_not_assumed_local() -> None:
    result = location_factor(TrustSignals(location_resolved=False))
    assert result.penalty > 0
    assert "could not be geolocated" in result.reason


def test_location_reports_infinite_velocity_as_null_not_infinity() -> None:
    """JSON has no Infinity; a null is honest and serialises."""
    result = location_factor(TrustSignals(travel_velocity_kmh=float("inf")))
    assert result.signals["travel_velocity_kmh"] is None


# ===========================================================================
# Factor 6 — Temporal (weight 5)
# ===========================================================================

def test_temporal_normal_hour_costs_nothing() -> None:
    assert temporal_factor(TrustSignals(hour_of_day=10, typical_hour=10.0)).penalty == 0.0


def test_temporal_uses_circular_hour_distance() -> None:
    """23:00 and 01:00 are two hours apart, not twenty-two."""
    across_midnight = temporal_factor(
        TrustSignals(hour_of_day=1, typical_hour=23.0, hour_spread=1.0)
    )
    far = temporal_factor(
        TrustSignals(hour_of_day=11, typical_hour=23.0, hour_spread=1.0)
    )
    assert across_midnight.penalty < far.penalty
    assert across_midnight.signals["hour_delta_hours"] == 2.0


def test_temporal_three_am_for_a_nine_to_five_user_is_penalised() -> None:
    result = temporal_factor(
        TrustSignals(hour_of_day=3, typical_hour=9.5, hour_spread=1.5)
    )
    assert result.penalty > 0
    assert "outside" in result.reason


def test_temporal_weekend_access_is_penalised() -> None:
    assert temporal_factor(TrustSignals(is_weekend=True)).penalty >= 20


def test_temporal_marathon_session_is_penalised() -> None:
    result = temporal_factor(
        TrustSignals(session_duration_min=600, baseline_session_duration_min=90)
    )
    assert result.penalty > 0
    assert "minutes against a typical" in result.reason


def test_temporal_wide_spread_tolerates_irregular_hours() -> None:
    """A shift worker with no fixed pattern should not be penalised for it."""
    tight = temporal_factor(TrustSignals(hour_of_day=3, typical_hour=9.0, hour_spread=1.0))
    loose = temporal_factor(TrustSignals(hour_of_day=3, typical_hour=9.0, hour_spread=6.0))
    assert loose.penalty < tight.penalty


# ===========================================================================
# The weighted sum
# ===========================================================================

def test_clean_session_scores_100() -> None:
    score, _ = evaluate_factors(clean())
    assert score == 100.0


def test_weights_match_the_specification() -> None:
    _, factors = evaluate_factors(clean())
    weights = {f.factor: f.weight for f in factors}
    assert weights == {
        TrustFactorName.IDENTITY: 25,
        TrustFactorName.DEVICE: 20,
        TrustFactorName.NETWORK: 20,
        TrustFactorName.BEHAVIOR: 20,
        TrustFactorName.LOCATION: 10,
        TrustFactorName.TEMPORAL: 5,
    }
    assert sum(weights.values()) == 100


def test_all_six_factors_are_always_reported() -> None:
    """Even a perfect session returns every factor, so the UI never has gaps."""
    _, factors = evaluate_factors(clean())
    assert len(factors) == 6
    assert {f.factor for f in factors} == set(TrustFactorName)


def test_a_single_factor_cannot_exceed_its_weight() -> None:
    """The cap that makes overrides necessary — asserted, not assumed."""
    for signals, factor in [
        (TrustSignals(account_locked=True), TrustFactorName.IDENTITY),
        (TrustSignals(travel_velocity_kmh=99_999, is_new_country=True,
                      distance_from_usual_km=20_000), TrustFactorName.LOCATION),
    ]:
        _, factors = evaluate_factors(signals)
        result = next(f for f in factors if f.factor == factor)
        assert result.points_deducted <= result.weight


def test_score_is_clamped_to_zero() -> None:
    everything = TrustSignals(
        account_locked=True, mfa_passed=False, failed_auth_count_24h=50,
        is_known_device=False, device_approved=False, os_browser_consistent=False,
        ip_reputation=100, is_tor=True, ip_changed_mid_session=True,
        profile_deviation=1.0, denied_access_count=20, distinct_resources=200,
        distance_from_usual_km=20_000, is_new_country=True,
        travel_velocity_kmh=99_999, hour_of_day=3, typical_hour=10.0,
        hour_spread=1.0, is_weekend=True, session_duration_min=10_000,
    )
    score, factors = evaluate_factors(everything)
    assert score == 0.0
    assert all(f.penalty == 100.0 for f in factors), (
        "every factor must be individually saturated for the total to reach 0"
    )


def test_score_never_goes_negative() -> None:
    """Even if every factor saturates, the floor holds."""
    for spread in (1.0, 2.0, 6.0):
        score, _ = evaluate_factors(
            TrustSignals(
                account_locked=True, mfa_passed=False, failed_auth_count_24h=50,
                is_known_device=False, os_browser_consistent=False,
                ip_reputation=100, is_tor=True, ip_changed_mid_session=True,
                profile_deviation=1.0, denied_access_count=20,
                distance_from_usual_km=20_000, is_new_country=True,
                travel_velocity_kmh=99_999, hour_of_day=3, typical_hour=10.0,
                hour_spread=spread, is_weekend=True, session_duration_min=10_000,
            )
        )
        assert score >= 0.0


# ===========================================================================
# Classification
# ===========================================================================

@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (100, RiskLevel.LOW), (80, RiskLevel.LOW),
        (79, RiskLevel.MEDIUM), (60, RiskLevel.MEDIUM),
        (59, RiskLevel.HIGH), (40, RiskLevel.HIGH),
        (39, RiskLevel.CRITICAL), (0, RiskLevel.CRITICAL),
    ],
)
def test_band_boundaries(score: float, expected: RiskLevel) -> None:
    assert classify(score) is expected


def test_bands_are_contiguous_and_cover_zero_to_one_hundred() -> None:
    table = bands()
    assert table[0]["max"] == 100
    assert table[-1]["min"] == 0
    for upper, lower in zip(table, table[1:]):
        assert upper["min"] == lower["max"] + 1, "no gaps, no overlaps"


def test_band_bounds_round_trip() -> None:
    for level in RiskLevel:
        low, high = band_bounds(level)
        assert classify(low) is level
        assert classify(high) is level


# ===========================================================================
# Decision engine
# ===========================================================================

def test_baseline_actions_follow_the_specification() -> None:
    assert baseline_action(RiskLevel.LOW) is AccessAction.ALLOW
    assert baseline_action(RiskLevel.MEDIUM) is AccessAction.ALLOW_LIMITED
    assert baseline_action(RiskLevel.HIGH) is AccessAction.STEP_UP_MFA
    assert baseline_action(RiskLevel.CRITICAL) is AccessAction.REVOKE_SESSION


def test_critical_always_revokes_regardless_of_resource() -> None:
    decision = decide(20, RiskLevel.CRITICAL, sensitivity=Sensitivity.PUBLIC)
    assert decision.action is AccessAction.REVOKE_SESSION
    assert decision.granted is False


def test_sensitivity_floors_are_enforced_on_top_of_the_band() -> None:
    """A LOW-risk 85 still cannot open a RESTRICTED resource needing 90."""
    ok = decide(85, RiskLevel.LOW, sensitivity=Sensitivity.CONFIDENTIAL)
    assert ok.granted is True

    refused = decide(85, RiskLevel.LOW, sensitivity=Sensitivity.RESTRICTED)
    assert refused.granted is False
    assert refused.required_score == 90
    assert refused.action is AccessAction.STEP_UP_MFA


def test_public_resources_have_no_floor() -> None:
    assert decide(5, RiskLevel.HIGH, sensitivity=Sensitivity.PUBLIC).required_score == 0


def test_high_risk_below_a_floor_blocks_rather_than_offering_step_up() -> None:
    decision = decide(45, RiskLevel.HIGH, sensitivity=Sensitivity.RESTRICTED)
    assert decision.action is AccessAction.BLOCK


def test_decision_always_states_the_numbers() -> None:
    decision = decide(72, RiskLevel.MEDIUM, sensitivity=Sensitivity.CONFIDENTIAL)
    assert "72" in decision.reason and "75" in decision.reason


# ===========================================================================
# Overrides
# ===========================================================================

def test_no_overrides_on_a_clean_session() -> None:
    assert detect_overrides(clean()) == []


def test_impossible_travel_override_forces_critical() -> None:
    result = assess(TrustSignals(travel_velocity_kmh=42_000))
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.was_overridden is True
    assert "impossible_travel" in [o.name for o in result.overrides]


def test_insider_enumeration_reaches_critical_despite_clean_credentials() -> None:
    """The case the weighted sum alone cannot express: valid creds, approved
    device, clean network, wildly abnormal behaviour."""
    signals = TrustSignals(
        distinct_resources=40, baseline_distinct_resources=4,
        profile_deviation=0.95, requests_per_minute=25,
        baseline_requests_per_minute=2, hour_of_day=3, typical_hour=9.5,
    )
    weighted, _ = evaluate_factors(signals)
    assert weighted > 70, "the arithmetic alone cannot reach CRITICAL here"

    result = assess(signals)
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.score < weighted


def test_enumeration_needs_both_volume_and_ratio() -> None:
    """A busy admin with a high baseline is not an insider threat."""
    busy_admin = TrustSignals(distinct_resources=25, baseline_distinct_resources=20)
    assert detect_overrides(busy_admin) == []

    # Below the absolute floor: a handful of resources is a working session,
    # however low the baseline.
    small_burst = TrustSignals(distinct_resources=5, baseline_distinct_resources=1)
    assert detect_overrides(small_burst) == []


def test_enumeration_is_reachable_in_this_catalogue() -> None:
    """Regression: the threshold was calibrated to a narrative, not to the
    catalogue. With twelve resources published, a floor of 20 meant the
    override could never fire in this deployment."""
    from app.ai.overrides import ENUMERATION_MIN_RESOURCES

    catalogue_size = 12
    assert ENUMERATION_MIN_RESOURCES <= catalogue_size, (
        "the enumeration floor must be reachable within the catalogue it protects"
    )

    insider = TrustSignals(
        distinct_resources=catalogue_size, baseline_distinct_resources=4.0
    )
    assert "mass_enumeration" in [o.name for o in detect_overrides(insider)]


def test_session_hijack_needs_both_ip_change_and_unknown_device() -> None:
    """A roaming user on the train changes IP without being a hijack."""
    roaming = TrustSignals(ip_changed_mid_session=True, is_known_device=True)
    assert "session_hijack" not in [o.name for o in detect_overrides(roaming)]

    hijack = TrustSignals(ip_changed_mid_session=True, is_known_device=False)
    assert "session_hijack" in [o.name for o in detect_overrides(hijack)]


def test_override_never_raises_a_score_that_is_already_lower() -> None:
    signals = TrustSignals(
        account_locked=True, mfa_passed=False, failed_auth_count_24h=50,
        is_known_device=False, is_tor=True, ip_reputation=100,
        denied_access_count=10, distinct_resources=100,
        baseline_distinct_resources=2, travel_velocity_kmh=99_999,
    )
    result = assess(signals)
    assert result.score <= result.weighted_score


# ===========================================================================
# Explainability
# ===========================================================================

def test_every_factor_carries_a_reason() -> None:
    result = assess(TrustSignals(is_known_device=False, is_vpn=True))
    for factor in result.factors:
        assert factor.reason, f"{factor.factor} returned no explanation"


def test_narrative_names_the_factors_that_moved_the_score() -> None:
    result = assess(
        TrustSignals(
            is_known_device=False, device_approved=False, is_vpn=True,
            distance_from_usual_km=6000, is_new_country=True,
        )
    )
    narrative = result.narrative()
    assert "device" in narrative
    assert "points" in narrative
    assert str(int(result.score)) in narrative


def test_narrative_of_a_clean_session_says_so_plainly() -> None:
    assert "normal range" in assess(clean()).narrative()


def test_overridden_score_explains_the_override_not_the_arithmetic() -> None:
    result = assess(TrustSignals(travel_velocity_kmh=42_000))
    assert "Impossible travel" in result.narrative()


def test_payload_records_the_pre_override_score() -> None:
    """A reviewer must be able to see what the arithmetic said before the clamp."""
    result = assess(TrustSignals(travel_velocity_kmh=42_000))
    override_row = next(f for f in result.factor_payload() if f["factor"] == "override")
    assert override_row["signals"]["weighted_score"] > result.score
    assert override_row["signals"]["clamped_to"] == result.score


def test_serialised_assessment_is_json_safe() -> None:
    import json

    result = assess(TrustSignals(travel_velocity_kmh=float("inf"), is_new_country=True))
    json.dumps(result.to_dict())   # must not raise on Infinity


def test_top_factors_are_ordered_worst_first() -> None:
    result = assess(
        TrustSignals(is_known_device=False, is_tor=True, is_weekend=True)
    )
    points = [f.points_deducted for f in result.top_factors()]
    assert points == sorted(points, reverse=True)


# ===========================================================================
# Signal assembly: absence of evidence is not evidence
# ===========================================================================

def test_unparseable_user_agent_is_not_treated_as_device_drift() -> None:
    """An API client or an unrecognised browser must not be charged 40 points
    for a fingerprint mismatch that was never actually observed."""
    from types import SimpleNamespace

    from app.ai.profiling import _os_browser_consistent

    device = SimpleNamespace(os="macOS", browser="Safari 18")
    safari = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/18.0 Safari/605.1.15"
    )
    chrome_on_windows = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )

    assert _os_browser_consistent(device, safari) is True
    assert _os_browser_consistent(device, "curl/8.4.0") is True, "unparseable"
    assert _os_browser_consistent(device, "") is True, "absent"
    assert _os_browser_consistent(None, safari) is True, "no device yet"
    assert _os_browser_consistent(device, chrome_on_windows) is False, "real drift"


def test_device_recorded_with_an_unknown_agent_never_reports_drift() -> None:
    """A device first registered by an API client has no parsed OS to compare."""
    from types import SimpleNamespace

    from app.ai.profiling import _os_browser_consistent

    device = SimpleNamespace(os="Unknown OS", browser="Unknown browser")
    assert _os_browser_consistent(
        device,
        "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    ) is True
