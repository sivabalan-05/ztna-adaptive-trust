"""Behaviour profiling and signal assembly.

Two jobs:

* read a user's rolling ``BehaviorProfile`` and measure how far the session in
  front of us sits from it;
* gather every signal the six factors need — from the user row, the session,
  the device, the context bundle and recent history — into one ``TrustSignals``.

The profile itself is *built* from historical sessions by the seeder and, from
Phase 6, refreshed nightly by the retrain worker. Nothing here writes to it.
"""

from __future__ import annotations

import logging
import math
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.scoring import TrustSignals
from app.core.context import ContextBundle
from app.models.base import as_aware, utcnow
from app.models.behavior_profile import BehaviorProfile
from app.models.device import Device
from app.models.enums import DeviceStatus, SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.services.geo_math import haversine_km, travel_velocity_kmh

logger = logging.getLogger(__name__)

#: Below this many recorded events, profile-derived signals are not trustworthy
#: and the behaviour and temporal factors are damped rather than fabricated.
COLD_PROFILE_EVENTS = 15


@dataclass
class ProfileDeviation:
    """How far this session sits from the account's baseline, 0-1 per axis."""

    device: float = 0.0
    location: float = 0.0
    temporal: float = 0.0
    activity: float = 0.0

    @property
    def combined(self) -> float:
        """Mean of the axes, so no single one saturates the whole signal."""
        axes = (self.device, self.location, self.temporal, self.activity)
        return min(1.0, sum(axes) / len(axes))


def get_profile(db: Session, user_id: uuid.UUID) -> BehaviorProfile | None:
    return db.scalar(
        select(BehaviorProfile).where(BehaviorProfile.user_id == user_id)
    )


def circular_hour_distance(a: float, b: float) -> float:
    """Hours between two clock positions, the short way round."""
    raw = abs(a - b)
    return min(raw, 24.0 - raw)


def measure_deviation(
    profile: BehaviorProfile | None,
    *,
    fingerprint: str,
    latitude: float | None,
    longitude: float | None,
    hour_of_day: int,
    requests_per_minute: float,
    distinct_resources: int,
) -> ProfileDeviation:
    """Compare one session against the stored baseline."""
    if profile is None:
        return ProfileDeviation()

    deviation = ProfileDeviation()

    known = set(profile.usual_device_fingerprints or [])
    if known:
        deviation.device = 0.0 if fingerprint in known else 1.0

    if (
        latitude is not None
        and longitude is not None
        and profile.centroid_latitude is not None
        and profile.centroid_longitude is not None
    ):
        distance = haversine_km(
            profile.centroid_latitude, profile.centroid_longitude, latitude, longitude
        )
        radius = max(25.0, profile.radius_km_p95)
        # Full deviation once the session is ten radii out.
        deviation.location = min(1.0, distance / (radius * 10.0))

    if profile.login_hour_concentration > 0.1:
        delta = circular_hour_distance(hour_of_day, profile.typical_login_hour)
        deviation.temporal = min(1.0, delta / 8.0)

    baseline_rpm = max(0.5, profile.avg_requests_per_minute)
    baseline_res = max(1.0, profile.avg_distinct_resources)
    rate_ratio = requests_per_minute / baseline_rpm
    res_ratio = distinct_resources / baseline_res
    deviation.activity = min(1.0, max(0.0, (max(rate_ratio, res_ratio) - 1.0) / 6.0))

    return deviation


def previous_session(
    db: Session, user_id: uuid.UUID, exclude_id: uuid.UUID | None = None
) -> UserSession | None:
    """The most recent earlier session, used for the impossible-travel check."""
    stmt = (
        select(UserSession)
        .where(UserSession.user_id == user_id)
        .order_by(UserSession.started_at.desc())
        .limit(2)
    )
    for candidate in db.scalars(stmt):
        if exclude_id is None or candidate.id != exclude_id:
            return candidate
    return None


def failed_auth_count_24h(db: Session, user: User) -> int:
    """Failed sign-ins in the last day.

    ``users.failed_login_count`` resets on a success, which is right for
    lockout but wrong for scoring: an attacker who eventually guesses the
    password would zero it out. The audit log keeps the real history.
    """
    from app.models.audit_log import AuditLog

    since = utcnow() - timedelta(hours=24)
    count = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.actor_id == user.id,
            AuditLog.action.in_(("LOGIN_FAILED", "MFA_FAILED")),
            AuditLog.timestamp >= since,
        )
    )
    return int(count or 0)


#: What the user-agent parser returns when it recognises nothing.
_UNPARSED = {"Unknown OS", "Unknown browser", ""}


def _os_browser_consistent(device: Device | None, user_agent: str) -> bool:
    """Whether the client still looks like the device this fingerprint belongs to.

    Only a *positive* mismatch counts. A missing or unrecognised user agent
    proves nothing: an API client, a curl call or a browser this parser has
    never seen would otherwise be charged 40 penalty points for a drift that
    was never observed. Absence of evidence is not evidence of change.
    """
    if device is None or not user_agent:
        return True

    from app.services.device_service import parse_browser, parse_os

    observed_os, observed_browser = parse_os(user_agent), parse_browser(user_agent)
    if observed_os in _UNPARSED or observed_browser in _UNPARSED:
        return True
    if device.os in _UNPARSED or device.browser in _UNPARSED:
        return True

    return device.os == observed_os and device.browser == observed_browser


def _touched_unfamiliar_resources(
    db: Session, session_id: uuid.UUID, typical: set[str]
) -> bool:
    """True when this session opened a resource the account normally does not.

    With no baseline yet, every resource is "new", which would penalise a
    first-day user for doing their job; that case returns False.
    """
    if not typical:
        return False

    from app.models.access_request import AccessRequest
    from app.models.resource import Resource

    slugs = db.scalars(
        select(Resource.slug)
        .join(AccessRequest, AccessRequest.resource_id == Resource.id)
        .where(AccessRequest.session_id == session_id)
        .distinct()
    ).all()
    return any(slug not in typical for slug in slugs)


def build_signals(
    db: Session,
    *,
    user: User,
    session: UserSession,
    bundle: ContextBundle,
    device: Device | None = None,
    profile: BehaviorProfile | None = None,
    denied_access_count: int | None = None,
    anomaly_score: float | None = None,
) -> TrustSignals:
    """Gather every signal the six factors need for this session, right now."""
    now = utcnow()
    profile = profile if profile is not None else get_profile(db, user.id)
    network = bundle.network
    temporal = bundle.temporal

    started = as_aware(session.started_at) or now
    duration_min = max(0.0, (now - started).total_seconds() / 60.0)
    requests_per_minute = (
        session.request_count / duration_min if duration_min >= 1.0
        else float(session.request_count)
    )

    # --- device ------------------------------------------------------------
    presented_fingerprint = bundle.device_fingerprint
    if device is None and session.device_id is not None:
        device = db.get(Device, session.device_id)

    known_fingerprints = set(profile.usual_device_fingerprints or []) if profile else set()
    is_known_device = bool(
        device is not None
        and device.seen_count > 1
        or (device is not None and device.fingerprint in known_fingerprints)
    )
    device_first_seen_days = (
        (now - (as_aware(device.first_seen_at) or now)).days if device else 0
    )
    os_consistent = _os_browser_consistent(device, bundle.user_agent)

    # --- network -----------------------------------------------------------
    ip_changed = bool(
        session.ip_address
        and network.ip_address
        and session.ip_address != network.ip_address
    )
    fingerprint_changed = bool(
        device is not None
        and presented_fingerprint
        and presented_fingerprint != device.fingerprint
    )

    # --- location ----------------------------------------------------------
    distance = 0.0
    origin_lat, origin_lon = None, None
    if profile is not None and profile.centroid_latitude is not None:
        origin_lat, origin_lon = profile.centroid_latitude, profile.centroid_longitude
    elif user.home_latitude is not None:
        origin_lat, origin_lon = user.home_latitude, user.home_longitude

    if (
        origin_lat is not None and origin_lon is not None
        and network.geo.has_coordinates and not network.geo.is_private
    ):
        distance = haversine_km(
            origin_lat, origin_lon,
            network.geo.latitude, network.geo.longitude,  # type: ignore[arg-type]
        )

    usual_countries = set(profile.usual_countries or []) if profile else set()
    if not usual_countries:
        usual_countries = {user.home_country}
    is_new_country = bool(
        network.geo.country
        and not network.geo.is_private
        and network.geo.country not in usual_countries
    )

    velocity = 0.0
    prior = previous_session(db, user.id, exclude_id=session.id)
    if (
        prior is not None
        and prior.latitude is not None
        and network.geo.has_coordinates
        and not network.geo.is_private
    ):
        prior_at = as_aware(prior.started_at)
        hop = haversine_km(
            prior.latitude, prior.longitude,  # type: ignore[arg-type]
            network.geo.latitude, network.geo.longitude,  # type: ignore[arg-type]
        )
        if prior_at is not None:
            velocity = travel_velocity_kmh(hop, prior_at, now)

    # --- behaviour ---------------------------------------------------------
    deviation = measure_deviation(
        profile,
        fingerprint=presented_fingerprint or (device.fingerprint if device else ""),
        latitude=network.geo.latitude,
        longitude=network.geo.longitude,
        hour_of_day=temporal.hour_of_day,
        requests_per_minute=requests_per_minute,
        distinct_resources=session.distinct_resource_count,
    )
    typical_resources = set(profile.typical_resources or []) if profile else set()
    unusual_access = _touched_unfamiliar_resources(db, session.id, typical_resources)
    event_count = profile.event_count if profile else 0
    cold = event_count < COLD_PROFILE_EVENTS

    credential_age = (
        (now - (as_aware(user.password_changed_at) or now)).days
        if user.password_changed_at
        else 0
    )

    return TrustSignals(
        # identity
        mfa_passed=session.mfa_passed,
        mfa_skipped=not session.mfa_passed and session.mfa_failures == 0,
        mfa_failures=session.mfa_failures,
        failed_auth_count_24h=failed_auth_count_24h(db, user),
        password_strength=user.password_strength,
        credential_age_days=credential_age,
        account_locked=user.is_locked,
        # device
        is_known_device=is_known_device,
        device_approved=bool(device and device.status is DeviceStatus.APPROVED),
        device_trusted=bool(device and device.is_trusted),
        device_first_seen_days=device_first_seen_days,
        os_browser_consistent=os_consistent,
        # network
        ip_reputation=network.reputation.abuse_confidence,
        is_vpn=network.intel.is_vpn,
        is_tor=network.intel.is_tor,
        is_datacenter=network.intel.is_datacenter,
        ip_changed_mid_session=ip_changed and fingerprint_changed,
        location_resolved=network.geo.resolved,
        # behaviour
        anomaly_score=anomaly_score,
        profile_deviation=deviation.combined,
        requests_per_minute=requests_per_minute,
        baseline_requests_per_minute=(
            profile.avg_requests_per_minute if profile else 2.0
        ),
        distinct_resources=session.distinct_resource_count,
        baseline_distinct_resources=(
            profile.avg_distinct_resources if profile else 3.0
        ),
        unusual_resource_access=unusual_access,
        denied_access_count=(
            denied_access_count if denied_access_count is not None
            else session.denied_count
        ),
        # location
        distance_from_usual_km=distance,
        is_new_country=is_new_country,
        travel_velocity_kmh=velocity,
        # temporal
        hour_of_day=temporal.hour_of_day,
        typical_hour=profile.typical_login_hour if profile else 10.0,
        hour_spread=(
            max(1.0, 6.0 * (1.0 - profile.login_hour_concentration))
            if profile else 3.0
        ),
        is_weekend=temporal.is_weekend,
        session_duration_min=duration_min,
        baseline_session_duration_min=(
            profile.avg_session_minutes if profile else 60.0
        ),
        profile_is_cold=cold,
    )


def features_for_model(signals: TrustSignals, bundle: ContextBundle) -> dict[str, float]:
    """The Isolation Forest feature vector for this session (Phase 6 consumes it)."""
    hour = bundle.temporal.hour_of_day
    return {
        "hour_sin": math.sin(2 * math.pi * hour / 24),
        "hour_cos": math.cos(2 * math.pi * hour / 24),
        "day_of_week": float(bundle.temporal.day_of_week),
        "is_known_device": float(signals.is_known_device),
        "geo_distance_from_usual_km": signals.distance_from_usual_km,
        "is_new_country": float(signals.is_new_country),
        "ip_reputation_score": float(signals.ip_reputation),
        "is_vpn": float(signals.is_vpn),
        "requests_per_minute": signals.requests_per_minute,
        "session_duration_min": signals.session_duration_min,
        "num_distinct_resources": float(signals.distinct_resources),
        "failed_auth_count_24h": float(signals.failed_auth_count_24h),
        "travel_velocity_kmh": (
            99999.0 if signals.travel_velocity_kmh == float("inf")
            else signals.travel_velocity_kmh
        ),
    }
