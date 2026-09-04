"""Integration tests, one per attack scenario.

These are the in-process twins of ``scripts/demo/*.py``. The demo scripts drive
the running API so an audience can watch the dashboard move; these run against
the test client so the same behaviour is verified deterministically in CI, with
no server, no clock dependence and no shared rate-limit state.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Alert, AuditLog, Resource, User, UserSession
from app.models.enums import RiskLevel, SessionStatus
from app.models.trust_score import TrustScore
from app.workers import continuous_verification as cv
from tests.conftest import (
    DEVICE_FINGERPRINT, OTHER_FINGERPRINT, PASSWORD, auth_headers, sign_in,
)

WINDOWS_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
)


def give_history(db: Session, user: User, fingerprint: str = DEVICE_FINGERPRINT) -> None:
    """Give an account the behaviour baseline a real one would have.

    Credential theft against an account with *no* history legitimately scores
    higher: there is nothing for the new device, country and hour to deviate
    from. The scenario is only meaningful for an established account, so the
    test builds one rather than asserting against an empty profile.
    """
    from app.models import BehaviorProfile

    db.add(
        BehaviorProfile(
            user_id=user.id,
            usual_countries=["IN"],
            usual_cities=["Coimbatore"],
            usual_device_fingerprints=[fingerprint],
            centroid_latitude=11.0168,
            centroid_longitude=76.9558,
            radius_km_p95=40.0,
            login_hour_sin=0.9659,
            login_hour_cos=0.2588,
            login_hour_concentration=0.85,
            avg_session_minutes=120.0,
            avg_requests_per_minute=2.0,
            avg_distinct_resources=4.0,
            event_count=180,
        )
    )
    db.commit()


def latest_score(db: Session, session_id: str) -> TrustScore:
    return db.scalars(
        select(TrustScore)
        .where(TrustScore.session_id == uuid.UUID(session_id))
        .order_by(TrustScore.created_at.desc())
        .limit(1)
    ).one()


# ===========================================================================
# 7 — Legitimate user (first, because low false positives is the premise)
# ===========================================================================

def test_happy_path_is_unimpeded(
    client: TestClient, user: User, admin: User, catalogue: dict[str, Resource],
    db: Session,
) -> None:
    """A known user on an approved device at their usual place is not bothered."""
    from app.models import Device
    from app.services.device_service import DeviceService

    sign_in(client, user)
    device = db.scalar(select(Device).where(Device.user_id == user.id))
    DeviceService.approve(db, device, admin)
    db.commit()

    tokens = sign_in(client, user)
    assert tokens["risk_level"] in ("LOW", "MEDIUM")

    for slug in ("public-docs", "hr-portal"):
        response = client.post(
            f"/api/resources/{slug}/access", headers=auth_headers(tokens)
        )
        assert response.status_code == 200, f"{slug} was refused on the happy path"

    assert client.get("/api/auth/me", headers=auth_headers(tokens)).status_code == 200


# ===========================================================================
# 1 — Credential theft
# ===========================================================================

def test_credential_theft_is_challenged(
    client: TestClient, user: User, db: Session
) -> None:
    """Correct password, unknown device, new country: the score must fall far
    enough to stop the session opening anything sensitive."""
    sign_in(client, user)                     # registers the usual device
    give_history(db, user)
    baseline = sign_in(client, user)

    client.headers.update(
        {
            "X-Device-Fingerprint": OTHER_FINGERPRINT,
            "User-Agent": WINDOWS_UA,
            "X-Forwarded-For": "5.32.44.7",   # residential, Dubai
        }
    )
    stolen = sign_in(client, user)

    # The security outcome is what matters, not the band label. Where exactly
    # this lands between MEDIUM and HIGH depends on how much history the
    # account has to deviate from — location is capped at 10 points by its own
    # weight, so a nearer country and a thinner profile both pull it upward.
    # Either way the session must lose materially and reach nothing sensitive.
    assert stolen["trust_score"] < baseline["trust_score"] - 15
    assert stolen["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")

    breakdown = latest_score(db, stolen["session_id"])
    factors = {f["factor"]: f for f in breakdown.factors}
    assert factors["device"]["points_deducted"] > 0, "unknown device must cost"
    assert factors["location"]["points_deducted"] > 0, "new country must cost"


def test_credential_theft_cannot_reach_anything_sensitive(
    client: TestClient, user: User, catalogue: dict[str, Resource], db: Session
) -> None:
    """Whatever band it lands in, the stolen session is refused the resources
    that matter — the sensitivity floors do the work the band label does not."""
    sign_in(client, user)
    give_history(db, user)

    client.headers.update(
        {
            "X-Device-Fingerprint": OTHER_FINGERPRINT,
            "User-Agent": WINDOWS_UA,
            "X-Forwarded-For": "5.32.44.7",
        }
    )
    stolen = sign_in(client, user)

    refused = client.post(
        "/api/resources/source-repo/access", headers=auth_headers(stolen)
    )
    assert refused.status_code == 403, "CONFIDENTIAL must be out of reach"
    assert refused.json()["detail"]


# ===========================================================================
# 2 — Impossible travel
# ===========================================================================

def test_impossible_travel_is_blocked_and_revoked(
    client: TestClient, user: User, db: Session
) -> None:
    client.headers["X-Forwarded-For"] = "117.192.10.20"     # Coimbatore
    sign_in(client, user)
    sign_in(client, user)

    client.headers.update(
        {
            "X-Forwarded-For": "191.96.4.4",                # Sao Paulo
            "X-Device-Fingerprint": OTHER_FINGERPRINT,
        }
    )
    second = sign_in(client, user)

    assert second["risk_level"] == "CRITICAL"
    breakdown = latest_score(db, second["session_id"])
    assert "override" in {f["factor"] for f in breakdown.factors}
    assert "impossible_travel" in str(breakdown.factors)

    session = db.get(UserSession, uuid.UUID(second["session_id"]))
    db.refresh(session)
    assert session.status is SessionStatus.REVOKED
    assert client.get("/api/auth/me", headers=auth_headers(second)).status_code == 401


# ===========================================================================
# 3 — Insider threat
# ===========================================================================

def test_insider_enumeration_revokes_mid_session(
    client: TestClient, admin: User, catalogue: dict[str, Resource], db: Session
) -> None:
    """Valid credentials, approved device, clean network — only the behaviour
    is wrong. This is the case the weighted sum alone cannot reach."""
    from app.models import BehaviorProfile

    tokens = sign_in(client, admin)
    db.add(
        BehaviorProfile(
            user_id=admin.id,
            avg_distinct_resources=2.0,
            avg_requests_per_minute=2.0,
            usual_countries=["IN"],
            event_count=200,
        )
    )
    db.commit()

    # Enumerate far beyond the baseline. All four are within admin clearance,
    # so nothing is refused — the *volume* is the only signal.
    for _ in range(3):
        for slug in catalogue:
            client.post(f"/api/resources/{slug}/access", headers=auth_headers(tokens))

    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    db.refresh(session)
    assert session.distinct_resource_count >= 4

    score = latest_score(db, tokens["session_id"])
    assert score.score < 80, "enumeration must move the score"


def test_enumeration_counts_what_was_reached_for(
    client: TestClient, contractor: User, catalogue: dict[str, Resource], db: Session
) -> None:
    tokens = sign_in(client, contractor)
    for slug in catalogue:
        client.post(f"/api/resources/{slug}/access", headers=auth_headers(tokens))

    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    db.refresh(session)
    assert session.distinct_resource_count == len(catalogue)
    assert session.denied_count >= 2


# ===========================================================================
# 4 — Brute force
# ===========================================================================

def test_brute_force_locks_the_account_and_alerts(
    client: TestClient, user: User, db: Session
) -> None:
    codes = [
        client.post(
            "/api/auth/login",
            json={"username": user.username, "password": f"guess-{n}"},
        ).status_code
        for n in range(1, 16)
    ]

    assert 429 in codes or 423 in codes, "the endpoint must shed a credential burst"

    db.refresh(user)
    assert user.failed_login_count >= settings.max_failed_logins
    assert user.locked_until is not None

    alert = db.scalar(select(Alert).where(Alert.category == "brute_force"))
    assert alert is not None
    assert alert.severity.value == "HIGH"

    record = db.scalar(select(AuditLog).where(AuditLog.action == "ACCOUNT_LOCKED"))
    assert record is not None


def test_the_correct_password_does_not_help_once_locked(
    client: TestClient, user: User
) -> None:
    for n in range(settings.max_failed_logins):
        client.post(
            "/api/auth/login",
            json={"username": user.username, "password": f"guess-{n}"},
        )
    response = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    )
    assert response.status_code in (423, 429)


# ===========================================================================
# 5 — Session hijack
# ===========================================================================

def test_session_hijack_is_refused_and_the_victim_keeps_working(
    client: TestClient, user: User, db: Session
) -> None:
    """The token is cryptographically perfect. This is exactly the case a
    stateless JWT check cannot catch."""
    tokens = sign_in(client, user)
    assert client.get("/api/auth/me", headers=auth_headers(tokens)).status_code == 200

    replay = client.get(
        "/api/auth/me",
        headers=auth_headers(tokens) | {"X-Device-Fingerprint": OTHER_FINGERPRINT},
    )
    assert replay.status_code == 401
    assert "different device" in replay.json()["detail"].lower()

    # The real user is unaffected.
    assert client.get("/api/auth/me", headers=auth_headers(tokens)).status_code == 200

    mismatch = db.scalar(
        select(AuditLog).where(AuditLog.action == "SESSION_CONTEXT_MISMATCH")
    )
    assert mismatch is not None
    assert mismatch.payload["presented_fingerprint"].startswith(OTHER_FINGERPRINT[:16])


# ===========================================================================
# 6 — Lateral movement
# ===========================================================================

def test_lateral_movement_escalates_and_forces_step_up(
    client: TestClient, contractor: User, catalogue: dict[str, Resource], db: Session
) -> None:
    """Each refusal alone is ordinary; the run of them is the signal."""
    tokens = sign_in(client, contractor)

    scores: list[float] = []
    for _ in range(2):
        for slug in ("source-repo", "payroll-db", "source-repo"):
            client.post(
                f"/api/resources/{slug}/access", headers=auth_headers(tokens)
            )
            scores.append(latest_score(db, tokens["session_id"]).score)

    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    db.refresh(session)

    assert session.denied_count >= 5
    assert scores[-1] < scores[0], "sustained probing must cost points"
    assert session.current_risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    breakdown = latest_score(db, tokens["session_id"])
    assert "privilege_probing" in str(breakdown.factors)


# ===========================================================================
# Continuous verification catches what a request-time check would miss
# ===========================================================================

def test_a_session_falls_without_its_owner_doing_anything(
    client: TestClient, user: User, db: Session
) -> None:
    """The property that separates this from a login check."""
    tokens = sign_in(client, user)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    before = session.current_trust_score

    # The source address lands on a blocklist between sweeps. No request from
    # the user, no interaction at all.
    session.ip_address = "185.234.9.1"
    session.last_verified_at = None
    db.commit()

    cv.sweep(db, interval_seconds=0)
    db.refresh(session)

    assert session.current_trust_score < before
    assert session.status is SessionStatus.REVOKED
    assert client.get("/api/auth/me", headers=auth_headers(tokens)).status_code == 401


def test_every_scenario_leaves_a_verifiable_audit_trail(
    client: TestClient, user: User, db: Session
) -> None:
    """Whatever happened, the record of it must still verify."""
    from app.services.audit_service import AuditService

    sign_in(client, user)
    client.post("/api/auth/login", json={"username": user.username, "password": "no"})
    client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer nonsense",
                 "X-Device-Fingerprint": DEVICE_FINGERPRINT},
    )

    result = AuditService.verify(db)
    assert result["valid"] is True
    assert result["records_checked"] > 0
