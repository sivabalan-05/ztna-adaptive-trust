"""Token issue, verification, typing and revocation."""

from __future__ import annotations

import uuid

import pytest

from app.core import jwt as jwt_service


@pytest.fixture
def ids() -> tuple[uuid.UUID, uuid.UUID]:
    return uuid.uuid4(), uuid.uuid4()


def test_access_token_round_trips(ids: tuple[uuid.UUID, uuid.UUID]) -> None:
    user_id, session_id = ids
    token, jti, expires_at = jwt_service.create_access_token(
        user_id, session_id, "employee", "f" * 64
    )
    payload = jwt_service.decode_token(token, "access")
    assert payload["sub"] == str(user_id)
    assert payload["sid"] == str(session_id)
    assert payload["role"] == "employee"
    assert payload["fp"] == "f" * 64
    assert payload["jti"] == jti
    assert expires_at.tzinfo is not None


def test_token_type_is_enforced(ids: tuple[uuid.UUID, uuid.UUID]) -> None:
    """An MFA token must never be usable as an access token."""
    token, _, _ = jwt_service.create_mfa_token(*ids)
    with pytest.raises(jwt_service.TokenError) as exc:
        jwt_service.decode_token(token, "access")
    assert exc.value.code == "wrong_token_type"


def test_refresh_token_is_not_an_access_token(ids: tuple[uuid.UUID, uuid.UUID]) -> None:
    token, _, _ = jwt_service.create_refresh_token(*ids)
    with pytest.raises(jwt_service.TokenError):
        jwt_service.decode_token(token, "access")


def test_revoked_token_is_rejected(ids: tuple[uuid.UUID, uuid.UUID]) -> None:
    token, jti, expires_at = jwt_service.create_access_token(*ids, "employee")
    assert jwt_service.decode_token(token, "access")["jti"] == jti

    jwt_service.revoke_jti(jti, expires_at)
    with pytest.raises(jwt_service.TokenError) as exc:
        jwt_service.decode_token(token, "access")
    assert exc.value.code == "token_revoked"


def test_tampered_token_is_rejected(ids: tuple[uuid.UUID, uuid.UUID]) -> None:
    token, _, _ = jwt_service.create_access_token(*ids, "employee")
    head, payload, signature = token.split(".")
    forged = f"{head}.{payload}.{'A' * len(signature)}"
    with pytest.raises(jwt_service.TokenError) as exc:
        jwt_service.decode_token(forged, "access")
    assert exc.value.code == "invalid_token"


def test_garbage_is_rejected() -> None:
    with pytest.raises(jwt_service.TokenError):
        jwt_service.decode_token("not.a.token", "access")


def test_revoke_token_helper_accepts_raw_string(
    ids: tuple[uuid.UUID, uuid.UUID],
) -> None:
    token, _, _ = jwt_service.create_refresh_token(*ids)
    jwt_service.revoke_token(token)
    with pytest.raises(jwt_service.TokenError) as exc:
        jwt_service.decode_token(token, "refresh")
    assert exc.value.code == "token_revoked"
