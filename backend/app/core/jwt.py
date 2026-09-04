"""JWT issue / verify / revoke.

Three token types share one signing key but are never interchangeable, because
``typ`` is checked on every decode:

* ``access``  — 15 minutes, carries the session id and role, sent on every request;
* ``refresh`` — 7 days, rotated on use, one live token per session;
* ``mfa``     — 5 minutes, issued after a correct password and exchanged for the
  pair above once the TOTP code is verified. It grants no access on its own.

Revocation is a denylist of ``jti`` values in the cache, each expiring exactly
when the token it blocks would have expired, so the list cannot grow without
bound.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from app.core.cache import cache
from app.core.config import settings

TokenType = Literal["access", "refresh", "mfa"]

MFA_TOKEN_EXPIRE_MINUTES = 5
_DENYLIST_PREFIX = "jwt:denylist:"


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired, revoked or wrong-typed."""

    def __init__(self, message: str, code: str = "invalid_token") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _encode(
    subject: str,
    token_type: TokenType,
    expires_delta: timedelta,
    extra: dict[str, Any] | None = None,
) -> tuple[str, str, datetime]:
    """Return ``(token, jti, expires_at)``."""
    issued_at = _now()
    expires_at = issued_at + expires_delta
    jti = uuid.uuid4().hex
    payload: dict[str, Any] = {
        "sub": subject,
        "typ": token_type,
        "jti": jti,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": "ztna",
    }
    if extra:
        payload.update(extra)
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, jti, expires_at


def create_access_token(
    user_id: uuid.UUID, session_id: uuid.UUID, role: str,
    device_fingerprint: str | None = None,
) -> tuple[str, str, datetime]:
    return _encode(
        str(user_id), "access",
        timedelta(minutes=settings.access_token_expire_minutes),
        {"sid": str(session_id), "role": role, "fp": device_fingerprint},
    )


def create_refresh_token(
    user_id: uuid.UUID, session_id: uuid.UUID,
) -> tuple[str, str, datetime]:
    return _encode(
        str(user_id), "refresh",
        timedelta(days=settings.refresh_token_expire_days),
        {"sid": str(session_id)},
    )


def create_mfa_token(
    user_id: uuid.UUID, session_id: uuid.UUID,
) -> tuple[str, str, datetime]:
    """Short-lived proof that the password step succeeded. Grants no access."""
    return _encode(
        str(user_id), "mfa", timedelta(minutes=MFA_TOKEN_EXPIRE_MINUTES),
        {"sid": str(session_id)},
    )


def decode_token(
    token: str, expected_type: TokenType, *, allow_revoked: bool = False
) -> dict[str, Any]:
    """Verify signature, expiry, type and revocation.

    ``allow_revoked`` skips only the denylist check, so a caller that needs
    to *react* to a revoked token — refresh-token replay is the case that
    matters — can still read its claims instead of getting a bare 401.

    Raises ``TokenError`` with a client-safe message; the caller turns that into
    a 401 without leaking which check failed beyond the coarse code.
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer="ztna",
            options={"require": ["exp", "iat", "nbf", "sub", "jti"]},
        )
    except ExpiredSignatureError as exc:
        raise TokenError("Token has expired.", "token_expired") from exc
    except InvalidTokenError as exc:
        raise TokenError("Token is invalid.", "invalid_token") from exc

    if payload.get("typ") != expected_type:
        raise TokenError(
            f"Expected a {expected_type} token.", "wrong_token_type"
        )
    if not allow_revoked and is_revoked(payload["jti"]):
        raise TokenError("Token has been revoked.", "token_revoked")
    return payload


def revoke_jti(jti: str, expires_at: datetime | int | None = None) -> None:
    """Add a token id to the denylist until the token would expire anyway."""
    if isinstance(expires_at, int):
        expires_at = datetime.fromtimestamp(expires_at, tz=timezone.utc)
    if expires_at is None:
        ttl = settings.refresh_token_expire_days * 86400
    else:
        ttl = int((expires_at - _now()).total_seconds())
    if ttl <= 0:
        return   # already expired; nothing to block
    cache.set(f"{_DENYLIST_PREFIX}{jti}", "1", ttl)


def is_revoked(jti: str) -> bool:
    return cache.exists(f"{_DENYLIST_PREFIX}{jti}")


def revoke_token(token: str) -> None:
    """Best-effort revocation of a raw token string, ignoring its type."""
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.jwt_algorithm],
            issuer="ztna", options={"verify_exp": False},
        )
    except InvalidTokenError:
        return
    revoke_jti(payload["jti"], payload.get("exp"))
