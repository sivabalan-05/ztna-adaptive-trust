"""Hard overrides that bypass the weighted sum.

The specification caps each factor's influence so that no single signal can
dominate. That cap has a consequence worth stating plainly: location is worth
10 points, so impossible travel on its own can only ever cost 10 points, and an
insider with valid credentials, an approved device and a clean network can
never fall below roughly 77 no matter how anomalous their behaviour is.

The weighted sum expresses *graded* risk. A small set of conditions are not
graded risk at all — they are evidence that the session is not who it claims to
be, or that an account is under active attack. Those clamp the score into the
band that forces the required enforcement action, and each records its own
reason so the dashboard can always explain why a score ignored the arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings
from app.ai.scoring import TrustSignals


@dataclass(frozen=True)
class Override:
    name: str
    cap: float
    reason: str


OVERRIDES: dict[str, Override] = {
    "account_lockout": Override(
        "account_lockout", 18.0,
        "Credential attack: repeated authentication failures exceeded the "
        "lockout threshold for this account.",
    ),
    "impossible_travel": Override(
        "impossible_travel", 22.0,
        "Impossible travel: the implied speed between consecutive sign-ins "
        "exceeds 900 km/h, so these two sessions cannot both be the same person.",
    ),
    "session_hijack": Override(
        "session_hijack", 28.0,
        "Session context mismatch: the presented token arrived from a different "
        "device fingerprint and a different network than it was issued to.",
    ),
    "malicious_ip": Override(
        "malicious_ip", 30.0,
        "Source address appears on an active abuse blocklist with high confidence.",
    ),
    "mass_enumeration": Override(
        "mass_enumeration", 32.0,
        "Mass resource enumeration: this session touched an order of magnitude "
        "more distinct resources than the account's established baseline.",
    ),
    "privilege_probing": Override(
        "privilege_probing", 48.0,
        "Lateral movement: a sustained run of policy denials shows this session "
        "walking up the sensitivity ladder rather than doing its normal work.",
    ),
}

#: A session must enumerate at least this many resources, *and* exceed its
#: baseline by this multiple, before mass enumeration fires. Either alone is
#: ordinary: a busy admin touches many resources, a quiet user's baseline is low.
#
# Both numbers are calibrated to the size of the catalogue being protected. The
# original 20-and-5x came from the seeded attack narrative, where an insider
# opens "40 confidential files" — but this deployment publishes twelve
# resources, so a floor of 20 could never be reached and the override was dead
# code. In a twelve-resource system, touching ten of them when you normally
# touch four *is* mass enumeration. A deployment with thousands of resources
# should raise both numbers.
ENUMERATION_MIN_RESOURCES = 8
ENUMERATION_RATIO = 2.5
PROBING_DENIALS = 5
MALICIOUS_IP_CONFIDENCE = 90


def detect(signals: TrustSignals) -> list[Override]:
    """Return every override this set of signals triggers."""
    hits: list[Override] = []

    if (
        signals.failed_auth_count_24h >= settings.max_failed_logins
        and not signals.mfa_passed
    ):
        hits.append(OVERRIDES["account_lockout"])

    if signals.travel_velocity_kmh > settings.impossible_travel_kmh:
        hits.append(OVERRIDES["impossible_travel"])

    if signals.ip_changed_mid_session and not signals.is_known_device:
        hits.append(OVERRIDES["session_hijack"])

    if signals.ip_reputation >= MALICIOUS_IP_CONFIDENCE:
        hits.append(OVERRIDES["malicious_ip"])

    baseline = max(1.0, signals.baseline_distinct_resources)
    if (
        signals.distinct_resources >= ENUMERATION_MIN_RESOURCES
        and signals.distinct_resources / baseline >= ENUMERATION_RATIO
    ):
        hits.append(OVERRIDES["mass_enumeration"])

    if signals.denied_access_count >= PROBING_DENIALS:
        hits.append(OVERRIDES["privilege_probing"])

    return hits


def apply(score: float, signals: TrustSignals) -> tuple[float, list[Override]]:
    """Clamp the score to the strictest triggered override, if any."""
    hits = detect(signals)
    if not hits:
        return score, []
    strictest = min(hits, key=lambda o: o.cap)
    return (min(score, strictest.cap), hits)
