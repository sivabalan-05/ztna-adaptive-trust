"""Continuous verification, live push and session revocation.

The property under test is the one that separates Zero Trust from a login
check: a session's standing changes while it is open, without its owner doing
anything, and the change is enforced and pushed immediately.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, User, UserSession
from app.models.base import utcnow
from app.models.enums import RiskLevel, ScoreTrigger, SessionStatus
from app.models.trust_score import TrustScore
from app.services.events import Event, InProcessBus
from app.services.session_service import SessionService
from app.workers import continuous_verification as cv
from tests.conftest import DEVICE_FINGERPRINT, auth_headers, sign_in


# --- what is due for re-verification ---------------------------------------

def test_a_never_verified_session_is_due(
    client: TestClient, user: User, db: Session
) -> None:
    tokens = sign_in(client, user)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    session.last_verified_at = None
    db.commit()

    due = SessionService.due_for_verification(db)
    assert session.id in {s.id for s in due}


def test_a_recently_verified_session_is_not_due(
    client: TestClient, user: User, db: Session
) -> None:
    tokens = sign_in(client, user)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    session.last_verified_at = utcnow()
    db.commit()

    due = SessionService.due_for_verification(db, interval_seconds=30)
    assert session.id not in {s.id for s in due}


def test_a_session_past_the_interval_is_due_again(
    client: TestClient, user: User, db: Session
) -> None:
    tokens = sign_in(client, user)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    session.last_verified_at = utcnow() - timedelta(seconds=90)
    db.commit()

    due = SessionService.due_for_verification(db, interval_seconds=30)
    assert session.id in {s.id for s in due}


def test_sessions_pending_mfa_are_not_counted_as_active(
    client: TestClient, user: User, db: Session
) -> None:
    """They exist and are scored, but they are not 'who is logged in'."""
    from tests.conftest import PASSWORD

    client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    )
    assert SessionService.active(db, mfa_only=True) == []
    assert SessionService.active(db, mfa_only=False) != []


# --- the sweep --------------------------------------------------------------

def test_sweep_rescores_without_the_user_doing_anything(
    client: TestClient, user: User, db: Session
) -> None:
    """The headline property: trust is re-evaluated on a timer, not on request."""
    tokens = sign_in(client, user)
    session_id = uuid.UUID(tokens["session_id"])

    before = db.scalar(
        select(TrustScore)
        .where(TrustScore.session_id == session_id)
        .order_by(TrustScore.created_at.desc())
    )
    result = cv.sweep(db, interval_seconds=0)

    assert result.checked >= 1
    after = db.scalars(
        select(TrustScore)
        .where(
            TrustScore.session_id == session_id,
            TrustScore.trigger == ScoreTrigger.PERIODIC,
        )
    ).all()
    assert after, "the sweep must record a PERIODIC score"
    assert after[-1].id != before.id


def test_sweep_updates_last_verified_at(
    client: TestClient, user: User, db: Session
) -> None:
    tokens = sign_in(client, user)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    session.last_verified_at = None
    db.commit()

    cv.sweep(db, interval_seconds=0)
    db.refresh(session)
    assert session.last_verified_at is not None


def test_sweep_revokes_a_session_that_falls_to_critical(
    client: TestClient, user: User, db: Session
) -> None:
    """Mid-session enforcement: the user is not asked, they are cut off."""
    tokens = sign_in(client, user)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))

    # The session's source address moves onto a blocklisted range between
    # sweeps — no request from the user, no interaction at all.
    session.ip_address = "185.234.9.1"
    session.last_verified_at = None
    db.commit()

    result = cv.sweep(db, interval_seconds=0)
    db.refresh(session)

    assert session.current_risk_level is RiskLevel.CRITICAL
    assert session.status is SessionStatus.REVOKED
    assert result.revoked >= 1

    # ...and the next request from that user is refused.
    response = client.get("/api/auth/me", headers=auth_headers(tokens))
    assert response.status_code == 401


def test_sweep_expires_an_idle_session(
    client: TestClient, user: User, db: Session
) -> None:
    tokens = sign_in(client, user)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    session.last_seen_at = utcnow() - timedelta(hours=4)
    db.commit()

    result = cv.sweep(db, interval_seconds=0)
    db.refresh(session)

    assert result.expired >= 1
    assert session.status is SessionStatus.EXPIRED
    assert "Idle" in session.revoked_reason


def test_sweep_survives_one_bad_session(
    client: TestClient, user: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One failing session must not stop the others being verified."""
    sign_in(client, user)
    calls = {"n": 0}
    original = cv.verify_session

    def flaky(db_, session):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return original(db_, session)

    monkeypatch.setattr(cv, "verify_session", flaky)
    result = cv.sweep(db, interval_seconds=0)
    assert result.errors == 1


def test_sweep_writes_an_audit_record(
    client: TestClient, user: User, db: Session
) -> None:
    sign_in(client, user)
    cv.sweep(db, interval_seconds=0)
    record = db.scalar(
        select(AuditLog).where(AuditLog.action == "TRUST_EVALUATED")
    )
    assert record is not None
    assert record.payload["trigger"] in ("LOGIN", "PERIODIC")


def test_the_context_is_rebuilt_not_reused(
    client: TestClient, user: User, db: Session
) -> None:
    """The sweep re-resolves the network, so a reputation change is picked up
    even though the user never made a request."""
    tokens = sign_in(client, user)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    session.ip_address = "45.83.91.7"      # VPN, blocklisted
    db.commit()

    bundle = cv.bundle_for_session(session, None)
    assert bundle.network.intel.is_vpn is True
    assert bundle.network.reputation.abuse_confidence > 0
    assert bundle.method == "INTERNAL"


# --- the API ----------------------------------------------------------------

def test_verify_now_endpoint_runs_the_same_sweep(
    client: TestClient, admin: User
) -> None:
    tokens = sign_in(client, admin)
    body = client.post(
        "/api/sessions/verify-now", headers=auth_headers(tokens)
    ).json()
    assert body["checked"] >= 1
    assert body["duration_ms"] >= 0


def test_live_sessions_listing_requires_permission(
    client: TestClient, user: User
) -> None:
    tokens = sign_in(client, user)
    assert client.get("/api/sessions", headers=auth_headers(tokens)).status_code == 403
    # ...but anyone may see their own.
    assert client.get(
        "/api/sessions/me", headers=auth_headers(tokens)
    ).status_code == 200


def test_summary_counts_live_sessions(client: TestClient, admin: User) -> None:
    tokens = sign_in(client, admin)
    body = client.get("/api/sessions/summary", headers=auth_headers(tokens)).json()
    assert body["active_sessions"] >= 1
    assert set(body["by_risk_level"]) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert body["verification_interval_seconds"] > 0


def test_admin_revocation_takes_effect_on_the_next_request(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    user_tokens = sign_in(client, user)
    admin_tokens = sign_in(client, admin)

    assert client.get(
        "/api/auth/me", headers=auth_headers(user_tokens)
    ).status_code == 200

    revoked = client.post(
        f"/api/sessions/{user_tokens['session_id']}/revoke",
        headers=auth_headers(admin_tokens),
        json={"reason": "Suspected credential compromise."},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "REVOKED"

    denied = client.get("/api/auth/me", headers=auth_headers(user_tokens))
    assert denied.status_code == 401
    assert "revoked" in denied.json()["detail"].lower()


def test_revoking_twice_is_a_conflict(
    client: TestClient, admin: User, user: User
) -> None:
    user_tokens = sign_in(client, user)
    admin_tokens = sign_in(client, admin)
    path = f"/api/sessions/{user_tokens['session_id']}/revoke"

    assert client.post(
        path, headers=auth_headers(admin_tokens), json={"reason": "First."}
    ).status_code == 200
    assert client.post(
        path, headers=auth_headers(admin_tokens), json={"reason": "Second."}
    ).status_code == 409


def test_revocation_is_audited_with_its_reason(
    client: TestClient, admin: User, user: User, db: Session
) -> None:
    user_tokens = sign_in(client, user)
    admin_tokens = sign_in(client, admin)
    client.post(
        f"/api/sessions/{user_tokens['session_id']}/revoke",
        headers=auth_headers(admin_tokens),
        json={"reason": "Laptop reported stolen."},
    )
    record = db.scalar(
        select(AuditLog)
        .where(AuditLog.action == "SESSION_REVOKED")
        .order_by(AuditLog.seq.desc())
    )
    assert record.payload["reason"] == "Laptop reported stolen."
    assert record.actor_label == admin.username


def test_a_user_cannot_read_another_users_session(
    client: TestClient, user: User, admin: User
) -> None:
    admin_tokens = sign_in(client, admin)
    user_tokens = sign_in(client, user)
    response = client.get(
        f"/api/sessions/{admin_tokens['session_id']}",
        headers=auth_headers(user_tokens),
    )
    assert response.status_code == 403


# --- WebSocket tickets ------------------------------------------------------

def test_ticket_requires_authentication(client: TestClient) -> None:
    assert client.post("/api/ws/ticket").status_code == 401


def test_ticket_is_issued_and_is_single_use(
    client: TestClient, user: User
) -> None:
    """A ticket in a URL is far less dangerous than a bearer token in a URL,
    and only if it cannot be replayed."""
    from app.api.ws import _consume_ticket

    tokens = sign_in(client, user)
    body = client.post("/api/ws/ticket", headers=auth_headers(tokens)).json()
    assert body["expires_in"] == 30

    assert _consume_ticket(body["ticket"]) is not None
    assert _consume_ticket(body["ticket"]) is None, "a ticket must not be reusable"


def test_unknown_ticket_is_rejected() -> None:
    from app.api.ws import _consume_ticket

    assert _consume_ticket("not-a-real-ticket") is None


def test_websocket_refuses_a_bad_ticket(client: TestClient, user: User) -> None:
    from starlette.websockets import WebSocketDisconnect as WSDisconnect

    sign_in(client, user)
    with pytest.raises(WSDisconnect):
        with client.websocket_connect("/ws/live?ticket=nonsense") as ws:
            ws.receive_text()


def test_websocket_opens_and_greets(client: TestClient, user: User) -> None:
    import json

    tokens = sign_in(client, user)
    ticket = client.post("/api/ws/ticket", headers=auth_headers(tokens)).json()["ticket"]

    with client.websocket_connect(f"/ws/live?ticket={ticket}") as ws:
        message = json.loads(ws.receive_text())
        assert message["type"] == "connected"
        assert message["payload"]["username"] == user.username
        assert message["payload"]["scope"] == "own-session"


def test_operators_see_every_session_users_only_their_own(
    client: TestClient, admin: User, user: User
) -> None:
    import json

    admin_tokens = sign_in(client, admin)
    ticket = client.post(
        "/api/ws/ticket", headers=auth_headers(admin_tokens)
    ).json()["ticket"]

    with client.websocket_connect(f"/ws/live?ticket={ticket}") as ws:
        assert json.loads(ws.receive_text())["payload"]["scope"] == "all-sessions"


# --- event routing ----------------------------------------------------------

def test_events_are_addressed_to_an_audience() -> None:
    event = Event("session.score", {"score": 40}, audience_user_ids=("abc",))
    assert event.visible_to("abc", is_operator=False) is True
    assert event.visible_to("xyz", is_operator=False) is False
    assert event.visible_to("xyz", is_operator=True) is True


def test_events_round_trip_through_json() -> None:
    original = Event("session.revoked", {"reason": "test"}, ("u1", "u2"))
    restored = Event.from_json(original.to_json())
    assert restored.type == original.type
    assert restored.payload == original.payload
    assert restored.audience_user_ids == original.audience_user_ids


def test_bus_delivers_to_subscribers() -> None:
    async def scenario() -> Event:
        local = InProcessBus()
        async with local.subscribe() as queue:
            await local.publish(Event("session.score", {"score": 12}))
            return await asyncio.wait_for(queue.get(), timeout=1)

    event = asyncio.run(scenario())
    assert event.payload["score"] == 12


def test_a_saturated_subscriber_is_dropped_not_blocking() -> None:
    """One slow dashboard must not stall every other subscriber."""
    async def scenario() -> int:
        local = InProcessBus()
        async with local.subscribe() as queue:
            for i in range(600):        # more than SUBSCRIBER_QUEUE_SIZE
                await local.publish(Event("session.score", {"i": i}))
            return queue.qsize()

    size = asyncio.run(scenario())
    assert size <= 256


def test_subscribers_are_removed_on_exit() -> None:
    async def scenario() -> int:
        local = InProcessBus()
        async with local.subscribe():
            pass
        return local.subscriber_count

    assert asyncio.run(scenario()) == 0
