"""End-to-end authentication behaviour through the HTTP API."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.external import mfa
from app.models import Alert, AuditLog, Device, User, UserSession
from app.models.enums import DeviceStatus, SessionStatus
from tests.conftest import (
    DEVICE_FINGERPRINT, OTHER_FINGERPRINT, PASSWORD, auth_headers, sign_in,
)


# --- the two-step login ----------------------------------------------------

def test_password_alone_does_not_grant_access(client: TestClient, user: User) -> None:
    response = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    assert "access_token" not in body
    assert "refresh_token" not in body
    assert body["mfa_token"]


def test_mfa_token_cannot_be_used_as_an_access_token(
    client: TestClient, user: User
) -> None:
    challenge = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    ).json()
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {challenge['mfa_token']}"},
    )
    assert response.status_code == 401


def test_full_login_returns_tokens_and_identity(
    client: TestClient, user: User
) -> None:
    tokens = sign_in(client, user)
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] == settings.access_token_expire_minutes * 60
    assert tokens["role"] == "employee"
    assert tokens["is_admin"] is False

    me = client.get("/api/auth/me", headers=auth_headers(tokens))
    assert me.status_code == 200
    assert me.json()["username"] == user.username
    assert me.json()["session"]["mfa_passed"] is True


def test_wrong_password_is_rejected_without_saying_which_field(
    client: TestClient, user: User
) -> None:
    response = client.post(
        "/api/auth/login", json={"username": user.username, "password": "wrong-one"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


def test_unknown_user_gives_the_identical_message(client: TestClient, user: User) -> None:
    response = client.post(
        "/api/auth/login", json={"username": "no.such.person", "password": PASSWORD}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


def test_login_requires_a_device_fingerprint(client: TestClient, user: User) -> None:
    client.headers.pop("X-Device-Fingerprint")
    response = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    )
    assert response.status_code == 400
    assert "fingerprint" in response.json()["detail"].lower()


def test_wrong_mfa_code_is_rejected(client: TestClient, user: User) -> None:
    challenge = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    ).json()
    response = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": challenge["mfa_token"], "code": "000000"},
    )
    assert response.status_code in (401, 429)


def test_mfa_token_is_single_use(client: TestClient, user: User) -> None:
    challenge = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    ).json()
    body = {
        "mfa_token": challenge["mfa_token"],
        "code": mfa.current_code(user.mfa_secret),
    }
    assert client.post("/api/auth/mfa/verify", json=body).status_code == 200
    replay = client.post("/api/auth/mfa/verify", json=body)
    assert replay.status_code == 401


def test_three_bad_codes_revoke_the_pending_session(
    client: TestClient, user: User, db: Session
) -> None:
    challenge = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    ).json()
    for _ in range(3):
        client.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": challenge["mfa_token"], "code": "000000"},
        )
    session = db.get(UserSession, uuid.UUID(challenge["session_id"]))
    db.refresh(session)
    assert session.status is SessionStatus.REVOKED
    assert "MFA" in session.revoked_reason


# --- lockout ---------------------------------------------------------------

def test_account_locks_after_repeated_failures(
    client: TestClient, user: User, db: Session
) -> None:
    for _ in range(settings.max_failed_logins):
        client.post(
            "/api/auth/login",
            json={"username": user.username, "password": "wrong-one"},
        )

    db.refresh(user)
    assert user.failed_login_count >= settings.max_failed_logins
    assert user.locked_until is not None

    # Even the correct password is refused while locked.
    response = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    )
    assert response.status_code == 423
    assert "locked" in response.json()["detail"].lower()

    alert = db.scalar(select(Alert).where(Alert.category == "brute_force"))
    assert alert is not None
    assert alert.evidence["failed_attempts"] >= settings.max_failed_logins


def test_successful_login_clears_the_failure_counter(
    client: TestClient, user: User, db: Session
) -> None:
    client.post(
        "/api/auth/login", json={"username": user.username, "password": "wrong-one"}
    )
    db.refresh(user)
    assert user.failed_login_count == 1

    sign_in(client, user)
    db.refresh(user)
    assert user.failed_login_count == 0
    assert user.last_login_at is not None


# --- device registration ---------------------------------------------------

def test_first_use_registers_the_device_as_pending(
    client: TestClient, user: User, db: Session
) -> None:
    challenge = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    ).json()
    assert challenge["device_known"] is False
    assert challenge["device_status"] == "PENDING"

    device = db.scalar(select(Device).where(Device.user_id == user.id))
    assert device is not None
    assert device.fingerprint == DEVICE_FINGERPRINT
    assert device.status is DeviceStatus.PENDING
    assert device.is_trusted is False
    assert device.os == "macOS"
    assert device.browser.startswith("Safari")


def test_new_device_raises_an_alert(client: TestClient, user: User, db: Session) -> None:
    client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    )
    alert = db.scalar(select(Alert).where(Alert.category == "new_device"))
    assert alert is not None
    assert alert.user_id == user.id


def test_second_login_recognises_the_device(
    client: TestClient, user: User, db: Session
) -> None:
    sign_in(client, user)
    challenge = client.post(
        "/api/auth/login", json={"username": user.username, "password": PASSWORD}
    ).json()
    assert challenge["device_known"] is True

    device = db.scalar(select(Device).where(Device.user_id == user.id))
    assert device.seen_count == 2


def test_admin_can_approve_a_device(
    client: TestClient, user: User, admin: User, db: Session
) -> None:
    sign_in(client, user)
    device = db.scalar(select(Device).where(Device.user_id == user.id))

    admin_tokens = sign_in(client, admin)
    response = client.post(
        f"/api/devices/{device.id}/approve", headers=auth_headers(admin_tokens)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"

    db.refresh(device)
    assert device.approved_by_id == admin.id


def test_non_admin_cannot_approve_a_device(
    client: TestClient, user: User, db: Session
) -> None:
    tokens = sign_in(client, user)
    device = db.scalar(select(Device).where(Device.user_id == user.id))
    response = client.post(
        f"/api/devices/{device.id}/approve", headers=auth_headers(tokens)
    )
    assert response.status_code == 403


# --- session binding and revocation ----------------------------------------

def test_token_is_bound_to_the_device_it_was_issued_to(
    client: TestClient, user: User, db: Session
) -> None:
    """A stolen token replayed from another fingerprint is refused."""
    tokens = sign_in(client, user)
    headers = auth_headers(tokens) | {"X-Device-Fingerprint": OTHER_FINGERPRINT}
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 401
    assert "different device" in response.json()["detail"].lower()

    mismatch = db.scalar(
        select(AuditLog).where(AuditLog.action == "SESSION_CONTEXT_MISMATCH")
    )
    assert mismatch is not None


def test_logout_ends_the_session_immediately(
    client: TestClient, user: User, db: Session
) -> None:
    tokens = sign_in(client, user)
    assert client.post("/api/auth/logout", headers=auth_headers(tokens)).status_code == 204

    # The access token is still cryptographically valid, but the session is not.
    response = client.get("/api/auth/me", headers=auth_headers(tokens))
    assert response.status_code == 401

    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    db.refresh(session)
    assert session.status is SessionStatus.LOGGED_OUT


def test_admin_revocation_takes_effect_on_the_next_request(
    client: TestClient, user: User, db: Session
) -> None:
    from app.services.auth_service import AuthService

    tokens = sign_in(client, user)
    assert client.get("/api/auth/me", headers=auth_headers(tokens)).status_code == 200

    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    AuthService.revoke_session(db, session, "Revoked by an administrator.")
    db.commit()

    response = client.get("/api/auth/me", headers=auth_headers(tokens))
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"].lower()


# --- refresh rotation ------------------------------------------------------

def test_refresh_rotates_both_tokens(client: TestClient, user: User) -> None:
    tokens = sign_in(client, user)
    response = client.post(
        "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert response.status_code == 200
    rotated = response.json()
    assert rotated["refresh_token"] != tokens["refresh_token"]
    assert rotated["access_token"] != tokens["access_token"]
    assert client.get("/api/auth/me", headers=auth_headers(rotated)).status_code == 200


def test_replaying_an_old_refresh_token_revokes_the_session(
    client: TestClient, user: User, db: Session
) -> None:
    tokens = sign_in(client, user)
    client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})

    replay = client.post(
        "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert replay.status_code == 401

    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    db.refresh(session)
    assert session.status is SessionStatus.REVOKED

    alert = db.scalar(select(Alert).where(Alert.category == "token_replay"))
    assert alert is not None
    assert alert.severity.value == "CRITICAL"


# --- registration and enrolment -------------------------------------------

def test_registration_requires_an_administrator(
    client: TestClient, user: User
) -> None:
    tokens = sign_in(client, user)
    response = client.post(
        "/api/auth/register",
        headers=auth_headers(tokens),
        json={
            "username": "new.person", "email": "new.person@ztna-demo.in",
            "full_name": "New Person", "password": "A-Long-Enough-Passphrase-9!",
        },
    )
    assert response.status_code == 403


def test_admin_can_register_and_weak_passwords_are_refused(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)

    weak = client.post(
        "/api/auth/register",
        headers=auth_headers(tokens),
        json={
            "username": "weak.user", "email": "weak@ztna-demo.in",
            "full_name": "Weak User", "password": "password1234",
        },
    )
    assert weak.status_code == 422
    assert "weak" in weak.json()["detail"].lower()

    good = client.post(
        "/api/auth/register",
        headers=auth_headers(tokens),
        json={
            "username": "new.person", "email": "new.person@ztna-demo.in",
            "full_name": "New Person", "password": "A-Long-Enough-Passphrase-9!",
            "role": "employee",
        },
    )
    assert good.status_code == 201
    created = db.scalar(select(User).where(User.username == "new.person"))
    assert created is not None
    assert created.mfa_secret is None, "MFA must be enrolled by the user, not preset"


def test_mfa_enrolment_round_trip(client: TestClient, admin: User, db: Session) -> None:
    tokens = sign_in(client, admin)
    enrol = client.post("/api/auth/mfa/enrol", headers=auth_headers(tokens))
    assert enrol.status_code == 200
    body = enrol.json()
    assert body["qr_code_svg_data_uri"].startswith("data:image/svg+xml;base64,")

    confirm = client.post(
        "/api/auth/mfa/confirm",
        headers=auth_headers(tokens),
        json={"code": mfa.current_code(body["secret"])},
    )
    assert confirm.status_code == 204
    db.refresh(admin)
    assert admin.mfa_confirmed_at is not None


# --- rate limiting ---------------------------------------------------------

def test_login_endpoint_is_rate_limited(client: TestClient, user: User) -> None:
    codes = [
        client.post(
            "/api/auth/login",
            json={"username": user.username, "password": "wrong-one"},
        ).status_code
        for _ in range(15)
    ]
    assert 429 in codes, "the login endpoint must shed load under a burst"


def test_error_responses_preserve_their_headers(
    client: TestClient, user: User
) -> None:
    """WWW-Authenticate tells the client *why* a 401 happened.

    The browser's token-refresh logic keys on `token_expired` to decide whether
    retrying would help; without the header every 401 looks the same and a
    revoked session would be retried forever.
    """
    response = client.get("/api/auth/me", headers={"Authorization": "Bearer nonsense"})
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert "invalid_token" in response.headers["WWW-Authenticate"]


def test_rate_limit_response_carries_retry_after(
    client: TestClient, user: User
) -> None:
    last = None
    for _ in range(15):
        last = client.post(
            "/api/auth/login",
            json={"username": user.username, "password": "wrong-one"},
        )
        if last.status_code == 429:
            break
    assert last is not None and last.status_code == 429
    assert int(last.headers["Retry-After"]) > 0
