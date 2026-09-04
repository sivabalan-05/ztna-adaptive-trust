"""The context collector middleware and the ContextBundle it builds."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import TemporalContext, anonymous_bundle
from app.models import AuditLog, User, UserSession
from app.models.base import utcnow
from tests.conftest import PASSWORD, sign_in


def test_request_id_is_returned_on_every_response(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers.get("X-Request-ID")


def test_supplied_request_id_is_preserved(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "trace-me-123"})
    assert response.headers["X-Request-ID"] == "trace-me-123"


def test_health_reports_which_providers_are_live(client: TestClient) -> None:
    providers = client.get("/health").json()["providers"]
    assert {"geoip", "ip_reputation", "notification", "anomaly_model"} <= set(providers)
    assert providers["geoip"] in ("offline-prefix-table", "maxmind-geolite2")


# --- the session records where the request really came from -----------------

def test_login_stamps_the_session_with_the_resolved_location(
    client: TestClient, user: User, db: Session
) -> None:
    """Regression: Phase 2 copied the account's home city onto every session,
    which would have made the location trust factor a no-op."""
    challenge = client.post(
        "/api/auth/login",
        json={"username": user.username, "password": PASSWORD},
        headers={"X-Forwarded-For": "185.234.9.1"},
    ).json()

    session = db.get(UserSession, uuid.UUID(challenge["session_id"]))
    db.refresh(session)
    assert session.ip_address == "185.234.9.1"
    assert session.country == "UA"
    assert session.city == "Kyiv"
    assert session.latitude is not None
    assert session.is_datacenter is True
    assert session.ip_reputation == 95
    # The user's home is Coimbatore; the session must not claim to be there.
    assert session.city != user.home_city


def test_login_from_a_vpn_records_the_vpn_flag(
    client: TestClient, user: User, db: Session
) -> None:
    challenge = client.post(
        "/api/auth/login",
        json={"username": user.username, "password": PASSWORD},
        headers={"X-Forwarded-For": "45.83.91.7"},
    ).json()

    session = db.get(UserSession, uuid.UUID(challenge["session_id"]))
    db.refresh(session)
    assert session.is_vpn is True
    assert session.country == "NL"
    assert session.asn == "AS9009"


def test_login_from_a_residential_indian_isp_is_clean(
    client: TestClient, user: User, db: Session
) -> None:
    challenge = client.post(
        "/api/auth/login",
        json={"username": user.username, "password": PASSWORD},
        headers={"X-Forwarded-For": "117.192.10.20"},
    ).json()

    session = db.get(UserSession, uuid.UUID(challenge["session_id"]))
    db.refresh(session)
    assert session.country == "IN"
    assert session.city == "Coimbatore"
    assert session.is_vpn is False
    assert session.is_datacenter is False
    assert session.ip_reputation == 0


def test_network_context_is_written_into_the_audit_record(
    client: TestClient, user: User, db: Session
) -> None:
    client.post(
        "/api/auth/login",
        json={"username": user.username, "password": PASSWORD},
        headers={"X-Forwarded-For": "191.96.4.4"},
    )
    record = db.scalar(
        select(AuditLog).where(AuditLog.action == "PASSWORD_ACCEPTED")
    )
    network = record.payload["network"]
    assert network["country"] == "BR"
    assert network["asn_type"] == "hosting"
    assert network["abuse_confidence"] == 76
    assert network["geoip_provider"] == "offline-prefix-table"


def test_only_the_first_forwarded_hop_is_trusted(
    client: TestClient, user: User, db: Session
) -> None:
    """A client can append to X-Forwarded-For; only the leftmost entry is used."""
    challenge = client.post(
        "/api/auth/login",
        json={"username": user.username, "password": PASSWORD},
        headers={"X-Forwarded-For": "117.192.10.20, 185.234.9.1, 10.0.0.1"},
    ).json()
    session = db.get(UserSession, uuid.UUID(challenge["session_id"]))
    db.refresh(session)
    assert session.ip_address == "117.192.10.20"


# --- temporal context -------------------------------------------------------

def test_temporal_context_uses_the_business_timezone() -> None:
    from datetime import datetime, timezone

    # 22:00 UTC on a Friday is 03:30 Saturday in Asia/Kolkata.
    at = datetime(2026, 3, 6, 22, 0, tzinfo=timezone.utc)
    temporal = TemporalContext.from_utc(at)
    assert temporal.hour_of_day == 3
    assert temporal.is_weekend is True
    assert temporal.is_business_hours is False


def test_business_hours_are_weekday_daytime() -> None:
    from datetime import datetime, timezone

    at = datetime(2026, 3, 4, 5, 0, tzinfo=timezone.utc)   # 10:30 Wed IST
    temporal = TemporalContext.from_utc(at)
    assert temporal.is_business_hours is True
    assert temporal.is_weekend is False


def test_current_time_produces_a_coherent_bundle() -> None:
    temporal = TemporalContext.from_utc(utcnow())
    assert 0 <= temporal.hour_of_day <= 23
    assert 0 <= temporal.day_of_week <= 6


# --- internal callers -------------------------------------------------------

def test_anonymous_bundle_is_usable_without_a_request() -> None:
    """The worker and demo scripts have no HTTP request to collect from."""
    bundle = anonymous_bundle()
    assert bundle.method == "INTERNAL"
    assert bundle.ip_address == ""
    assert bundle.device_fingerprint == ""
    summary = bundle.summary()
    assert summary["network"]["country"] == ""
    assert summary["temporal"]["hour_of_day"] >= 0


def test_authenticated_request_still_works_end_to_end(
    client: TestClient, user: User
) -> None:
    tokens = sign_in(client, user)
    me = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert me.status_code == 200


def test_verification_never_runs_in_the_api_under_test_env() -> None:
    """Guard: the sweep writes through the global session factory, which points
    at the real database. It must never start inside a test process."""
    from app.core.config import Settings

    assert Settings(app_env="test").verification_in_api is False
    assert Settings(app_env="test", run_verification_in_api=True).verification_in_api is False


def test_verification_placement_follows_redis() -> None:
    """Without Redis the API owns the sweep; with Redis the worker does."""
    from app.core.config import Settings

    assert Settings(redis_url=None).verification_in_api is True
    assert Settings(redis_url="redis://localhost:6379/0").verification_in_api is False
