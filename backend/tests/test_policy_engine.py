"""Policy engine: the three gates, their conditions, and enforcement.

Least privilege means clearance, policy and trust must *all* pass. Each gate is
tested in isolation, and then together — a request that satisfies two of three
must still be refused.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import ContextBundle, NetworkContext, TemporalContext
from app.external.geoip import GeoLocation
from app.external.ip_reputation import IPReputation
from app.external.network_intel import ASNType, NetworkIntel
from app.models import AccessRequest, AuditLog, Policy, Resource, User
from app.models.base import utcnow
from app.models.enums import (
    AccessAction, PolicyEffect, RiskLevel, SessionStatus, Sensitivity,
)
from app.models.session import UserSession
from app.services.policy_engine import PolicyEngine
from tests.conftest import DEVICE_FINGERPRINT, PASSWORD, auth_headers, sign_in


def make_bundle(
    *, country: str = "IN", city: str = "Coimbatore", hour: int | None = None,
    is_vpn: bool = False, weekend: bool = False,
) -> ContextBundle:
    """A context bundle with the network and time we want to test against."""
    temporal = TemporalContext.from_utc(utcnow())
    if hour is not None or weekend:
        temporal = TemporalContext(
            at=temporal.at,
            local_time=temporal.local_time,
            hour_of_day=hour if hour is not None else temporal.hour_of_day,
            day_of_week=5 if weekend else 2,
            is_weekend=weekend,
            is_business_hours=(not weekend and 8 <= (hour or 10) < 20),
        )
    return ContextBundle(
        request_id="test",
        method="GET",
        path="/test",
        user_agent="",
        network=NetworkContext(
            ip_address="117.192.1.1",
            geo=GeoLocation(
                ip="117.192.1.1", country=country, city=city,
                latitude=11.0, longitude=76.9, resolved=True, provider="test",
            ),
            intel=NetworkIntel(
                asn="AS9829",
                asn_type=ASNType.VPN if is_vpn else ASNType.RESIDENTIAL,
                is_vpn=is_vpn, is_proxy=is_vpn,
            ),
            reputation=IPReputation(ip="117.192.1.1", provider="test"),
        ),
        temporal=temporal,
    )


def make_session(db: Session, user: User, *, mfa: bool = True) -> UserSession:
    session = UserSession(
        user_id=user.id, status=SessionStatus.ACTIVE, ip_address="117.192.1.1",
        country="IN", city="Coimbatore", started_at=utcnow(),
        last_seen_at=utcnow(), expires_at=utcnow().replace(year=2030),
        mfa_passed=mfa,
    )
    db.add(session)
    db.commit()
    return session


def evaluate(db, user, session, resource, score, risk=None, bundle=None, device_known=True):
    from app.ai.classifier import classify

    return PolicyEngine.evaluate(
        db, user=user, session=session, resource=resource, score=score,
        risk=risk or classify(score), bundle=bundle or make_bundle(),
        device_known=device_known,
    )


# ===========================================================================
# Gate 1 — clearance
# ===========================================================================

def test_contractor_cannot_reach_confidential_even_at_a_perfect_score(
    db: Session, contractor: User, catalogue: dict[str, Resource]
) -> None:
    """The headline least-privilege case: the score is necessary, not sufficient."""
    session = make_session(db, contractor)
    decision = evaluate(db, contractor, session, catalogue["source-repo"], 100.0)

    assert decision.granted is False
    assert decision.gate == "clearance"
    assert "not cleared" in decision.reason
    assert "no trust score can grant access" in decision.reason


def test_contractor_can_reach_internal_at_a_good_score(
    db: Session, contractor: User, catalogue: dict[str, Resource]
) -> None:
    session = make_session(db, contractor)
    decision = evaluate(db, contractor, session, catalogue["hr-portal"], 95.0)
    assert decision.granted is True


def test_employee_cannot_reach_restricted(
    db: Session, user: User, catalogue: dict[str, Resource]
) -> None:
    session = make_session(db, user)
    decision = evaluate(db, user, session, catalogue["payroll-db"], 100.0)
    assert decision.granted is False
    assert decision.gate == "clearance"


def test_admin_clearance_covers_restricted(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    session = make_session(db, admin)
    decision = evaluate(db, admin, session, catalogue["payroll-db"], 95.0)
    assert decision.granted is True


def test_clearance_is_checked_before_the_score(
    db: Session, contractor: User, catalogue: dict[str, Resource]
) -> None:
    """A cleared refusal must not depend on the arithmetic having been run."""
    session = make_session(db, contractor)
    for score in (0.0, 50.0, 100.0):
        decision = evaluate(db, contractor, session, catalogue["source-repo"], score)
        assert decision.gate == "clearance"


# ===========================================================================
# Gate 2 — policy
# ===========================================================================

def test_deny_policy_beats_allow_at_higher_priority(
    db: Session, user: User, catalogue: dict[str, Resource]
) -> None:
    db.add(
        Policy(
            name="Block the repo for everyone", resource_id=catalogue["source-repo"].id,
            effect=PolicyEffect.DENY, priority=900,
        )
    )
    db.commit()

    session = make_session(db, user)
    decision = evaluate(db, user, session, catalogue["source-repo"], 100.0)
    assert decision.granted is False
    assert decision.gate == "policy"
    assert decision.matched_policy == "Block the repo for everyone"


def test_no_matching_allow_policy_refuses(
    db: Session, user: User, catalogue: dict[str, Resource]
) -> None:
    for policy in db.scalars(select(Policy)):
        db.delete(policy)
    db.commit()

    session = make_session(db, user)
    decision = evaluate(db, user, session, catalogue["hr-portal"], 100.0)
    assert decision.granted is False
    assert decision.gate == "policy"
    assert "No policy grants" in decision.reason


def test_disabled_policies_are_ignored(
    db: Session, user: User, catalogue: dict[str, Resource]
) -> None:
    db.add(
        Policy(
            name="Disabled block", resource_id=catalogue["hr-portal"].id,
            effect=PolicyEffect.DENY, priority=900, enabled=False,
        )
    )
    db.commit()
    session = make_session(db, user)
    assert evaluate(db, user, session, catalogue["hr-portal"], 100.0).granted is True


def test_disabled_resources_are_refused(
    db: Session, user: User, catalogue: dict[str, Resource]
) -> None:
    catalogue["hr-portal"].enabled = False
    db.commit()
    session = make_session(db, user)
    decision = evaluate(db, user, session, catalogue["hr-portal"], 100.0)
    assert decision.granted is False
    assert decision.gate == "resource"


def test_every_policy_considered_is_reported(
    db: Session, user: User, catalogue: dict[str, Resource]
) -> None:
    """A refusal must be explainable: which policies were looked at, and why."""
    session = make_session(db, user)
    decision = evaluate(db, user, session, catalogue["hr-portal"], 100.0)
    assert decision.evaluations
    assert any(e.decisive for e in decision.evaluations)


# ===========================================================================
# Gate 3 — trust, and policy conditions
# ===========================================================================

def test_score_below_the_sensitivity_floor_refuses(
    db: Session, user: User, catalogue: dict[str, Resource]
) -> None:
    session = make_session(db, user)
    decision = evaluate(db, user, session, catalogue["source-repo"], 70.0)
    assert decision.granted is False
    assert decision.gate == "trust"
    assert decision.required_score == 75


def test_public_resources_are_reachable_at_a_low_score(
    db: Session, user: User, catalogue: dict[str, Resource]
) -> None:
    session = make_session(db, user)
    assert evaluate(db, user, session, catalogue["public-docs"], 45.0).granted is True


def test_each_sensitivity_enforces_its_own_floor(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    session = make_session(db, admin)
    expectations = [
        ("public-docs", 0), ("hr-portal", 60),
        ("source-repo", 75), ("payroll-db", 90),
    ]
    for slug, floor in expectations:
        if floor > 0:
            just_below = evaluate(db, admin, session, catalogue[slug], float(floor - 1))
            assert just_below.granted is False, f"{slug} allowed at {floor - 1}"
            just_at = evaluate(db, admin, session, catalogue[slug], float(floor))
            assert just_at.granted is True, f"{slug} refused at its own floor {floor}"
        else:
            # A zero floor still needs a session that is not CRITICAL: the band
            # is checked independently of the resource's own requirement.
            assert evaluate(db, admin, session, catalogue[slug], 45.0).granted is True
            assert evaluate(db, admin, session, catalogue[slug], 20.0).granted is False


def test_a_critical_session_is_refused_even_by_public_resources(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    """A zero trust floor is not a bypass: CRITICAL means the session is over."""
    session = make_session(db, admin)
    decision = evaluate(db, admin, session, catalogue["public-docs"], 15.0)
    assert decision.granted is False
    assert decision.action is AccessAction.REVOKE_SESSION


def test_require_mfa_condition(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    db.add(
        Policy(
            name="Payroll needs MFA", resource_id=catalogue["payroll-db"].id,
            effect=PolicyEffect.ALLOW, priority=500, min_trust_score=90,
            require_mfa=True,
        )
    )
    db.commit()

    without_mfa = make_session(db, admin, mfa=False)
    decision = evaluate(db, admin, without_mfa, catalogue["payroll-db"], 95.0)
    assert decision.granted is False
    assert "multi-factor" in decision.reason


def test_require_known_device_condition(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    db.add(
        Policy(
            name="Repo needs a managed device",
            resource_id=catalogue["source-repo"].id, effect=PolicyEffect.ALLOW,
            priority=500, require_known_device=True,
        )
    )
    db.commit()
    session = make_session(db, admin)

    assert evaluate(
        db, admin, session, catalogue["source-repo"], 95.0, device_known=True
    ).granted is True
    refused = evaluate(
        db, admin, session, catalogue["source-repo"], 95.0, device_known=False
    )
    assert refused.granted is False
    assert "registered, approved device" in refused.reason


def test_deny_vpn_condition(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    db.add(
        Policy(
            name="Payroll denies VPN", resource_id=catalogue["payroll-db"].id,
            effect=PolicyEffect.ALLOW, priority=500, deny_vpn=True,
        )
    )
    db.commit()
    session = make_session(db, admin)

    refused = evaluate(
        db, admin, session, catalogue["payroll-db"], 95.0,
        bundle=make_bundle(is_vpn=True),
    )
    assert refused.granted is False
    assert "VPN" in refused.reason


def test_country_restriction(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    db.add(
        Policy(
            name="Payroll India only", resource_id=catalogue["payroll-db"].id,
            effect=PolicyEffect.ALLOW, priority=500, allowed_countries=["IN"],
        )
    )
    db.commit()
    session = make_session(db, admin)

    assert evaluate(
        db, admin, session, catalogue["payroll-db"], 95.0,
        bundle=make_bundle(country="IN"),
    ).granted is True

    refused = evaluate(
        db, admin, session, catalogue["payroll-db"], 95.0,
        bundle=make_bundle(country="SG", city="Singapore"),
    )
    assert refused.granted is False
    assert "SG" in refused.reason


def test_time_window_condition(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    db.add(
        Policy(
            name="Payroll business hours",
            resource_id=catalogue["payroll-db"].id, effect=PolicyEffect.ALLOW,
            priority=500,
            time_window={"start_hour": 8, "end_hour": 20, "weekdays_only": True},
        )
    )
    db.commit()
    session = make_session(db, admin)

    assert evaluate(
        db, admin, session, catalogue["payroll-db"], 95.0, bundle=make_bundle(hour=11)
    ).granted is True

    at_night = evaluate(
        db, admin, session, catalogue["payroll-db"], 95.0, bundle=make_bundle(hour=3)
    )
    assert at_night.granted is False
    assert "outside the permitted window" in at_night.reason

    at_weekend = evaluate(
        db, admin, session, catalogue["payroll-db"], 95.0,
        bundle=make_bundle(hour=11, weekend=True),
    )
    assert at_weekend.granted is False
    assert "weekdays only" in at_weekend.reason


def test_critical_session_is_refused_and_revoked(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    session = make_session(db, admin)
    decision = evaluate(
        db, admin, session, catalogue["public-docs"], 20.0, risk=RiskLevel.CRITICAL
    )
    assert decision.granted is False
    assert decision.action is AccessAction.REVOKE_SESSION


def test_medium_risk_grants_limited_access(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    session = make_session(db, admin)
    decision = evaluate(db, admin, session, catalogue["hr-portal"], 70.0)
    assert decision.granted is True
    assert decision.action is AccessAction.ALLOW_LIMITED


def test_a_refusal_names_what_would_have_to_change(
    db: Session, admin: User, catalogue: dict[str, Resource]
) -> None:
    db.add(
        Policy(
            name="Payroll needs MFA and a device",
            resource_id=catalogue["payroll-db"].id, effect=PolicyEffect.ALLOW,
            priority=500, require_mfa=True, require_known_device=True,
        )
    )
    db.commit()
    session = make_session(db, admin, mfa=False)
    decision = evaluate(
        db, admin, session, catalogue["payroll-db"], 95.0, device_known=False
    )
    assert "multi-factor" in decision.reason
    assert "device" in decision.reason


# ===========================================================================
# The enforcement point, over HTTP
# ===========================================================================

def test_access_endpoint_grants_and_records(
    client: TestClient, user: User, catalogue: dict[str, Resource], db: Session
) -> None:
    tokens = sign_in(client, user)
    response = client.post(
        "/api/resources/public-docs/access", headers=auth_headers(tokens)
    )
    assert response.status_code == 200
    body = response.json()
    assert body["granted"] is True
    assert body["trust_score"] > 0
    assert body["policies_evaluated"]

    row = db.scalar(select(AccessRequest).where(AccessRequest.granted.is_(True)))
    assert row is not None
    assert row.features, "the Isolation Forest feature vector must be recorded"
    assert row.latency_ms > 0


def test_access_denial_returns_403_and_survives_it(
    client: TestClient, contractor: User, catalogue: dict[str, Resource], db: Session
) -> None:
    """The evidence for a refusal must not be rolled back with the refusal."""
    tokens = sign_in(client, contractor)
    response = client.post(
        "/api/resources/source-repo/access", headers=auth_headers(tokens)
    )
    assert response.status_code == 403
    assert response.headers["X-Access-Gate"] == "clearance"
    assert "not cleared" in response.json()["detail"]

    row = db.scalar(select(AccessRequest).where(AccessRequest.granted.is_(False)))
    assert row is not None, "the denied attempt must be recorded"
    assert row.score_at_request > 0

    audit = db.scalar(select(AuditLog).where(AuditLog.action == "ACCESS_DENIED"))
    assert audit is not None
    assert audit.payload["gate"] == "clearance"


def test_denials_increment_the_session_counter(
    client: TestClient, contractor: User, catalogue: dict[str, Resource], db: Session
) -> None:
    """This counter is what the behaviour factor reads for lateral movement."""
    tokens = sign_in(client, contractor)
    for _ in range(3):
        client.post("/api/resources/source-repo/access", headers=auth_headers(tokens))

    import uuid as _uuid

    session = db.get(UserSession, _uuid.UUID(tokens["session_id"]))
    db.refresh(session)
    assert session.denied_count >= 3


def test_catalogue_annotates_reachability_per_session(
    client: TestClient, contractor: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, contractor)
    rows = client.get("/api/resources", headers=auth_headers(tokens)).json()
    by_slug = {r["slug"]: r for r in rows}

    assert by_slug["public-docs"]["reachable"] is True
    assert by_slug["source-repo"]["reachable"] is False
    assert by_slug["source-repo"]["gate"] == "clearance"
    assert by_slug["payroll-db"]["reachable"] is False
    for row in rows:
        assert row["reason"], "every row must explain itself"


def test_unknown_resource_is_404(client: TestClient, user: User) -> None:
    tokens = sign_in(client, user)
    response = client.post(
        "/api/resources/no-such-thing/access", headers=auth_headers(tokens)
    )
    assert response.status_code == 404


def test_access_history_is_recorded(
    client: TestClient, user: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, user)
    client.post("/api/resources/public-docs/access", headers=auth_headers(tokens))
    history = client.get(
        "/api/resources/access/history", headers=auth_headers(tokens)
    ).json()
    assert history
    assert history[0]["resource"] == "public-docs"


# ===========================================================================
# Policy administration
# ===========================================================================

def test_admin_can_create_and_delete_a_policy(
    client: TestClient, admin: User, catalogue: dict[str, Resource], db: Session
) -> None:
    tokens = sign_in(client, admin)
    created = client.post(
        "/api/policies",
        headers=auth_headers(tokens),
        json={
            "name": "Test lockdown", "description": "Blocks the HR portal.",
            "resource": "hr-portal", "effect": "DENY", "priority": 900,
        },
    )
    assert created.status_code == 201
    policy_id = created.json()["id"]

    audit = db.scalar(select(AuditLog).where(AuditLog.action == "POLICY_CREATED"))
    assert audit is not None

    assert client.delete(
        f"/api/policies/{policy_id}", headers=auth_headers(tokens)
    ).status_code == 204


def test_non_admin_cannot_write_policies(
    client: TestClient, user: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, user)
    response = client.post(
        "/api/policies",
        headers=auth_headers(tokens),
        json={"name": "Sneaky", "effect": "ALLOW"},
    )
    assert response.status_code == 403


def test_a_new_deny_policy_takes_effect_immediately(
    client: TestClient, admin: User, user: User, catalogue: dict[str, Resource]
) -> None:
    """Policy is evaluated per request, so a change lands without a restart."""
    user_tokens = sign_in(client, user)
    assert client.post(
        "/api/resources/hr-portal/access", headers=auth_headers(user_tokens)
    ).status_code == 200

    admin_tokens = sign_in(client, admin)
    client.post(
        "/api/policies",
        headers=auth_headers(admin_tokens),
        json={
            "name": "Emergency HR lockdown", "resource": "hr-portal",
            "effect": "DENY", "priority": 999,
        },
    )

    blocked = client.post(
        "/api/resources/hr-portal/access", headers=auth_headers(user_tokens)
    )
    assert blocked.status_code == 403
    assert "Emergency HR lockdown" in blocked.json()["detail"]


def test_enumeration_counts_attempts_not_successes(
    client: TestClient, contractor: User, catalogue: dict[str, Resource], db: Session
) -> None:
    """Regression: counting only *granted* requests meant an insider probing
    resources they are refused registered as having enumerated nothing —
    exactly backwards for the behaviour the override exists to catch."""
    import uuid as _uuid

    tokens = sign_in(client, contractor)
    for slug in ("public-docs", "hr-portal", "source-repo", "payroll-db"):
        client.post(f"/api/resources/{slug}/access", headers=auth_headers(tokens))

    session = db.get(UserSession, _uuid.UUID(tokens["session_id"]))
    db.refresh(session)
    # Two were granted and two refused at the clearance gate; all four count.
    assert session.distinct_resource_count == 4
    assert session.denied_count == 2
