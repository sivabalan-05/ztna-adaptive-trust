"""FastAPI dependencies: request context, authentication, authorisation.

``get_principal`` is the enforcement point every protected route goes through.
It re-checks the session on *every* request rather than trusting the token
alone — that is what makes revocation take effect within seconds instead of
waiting out the access token's 15-minute life.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core import jwt as jwt_service
from app.core.config import settings
from app.core.context import ContextBundle
from app.core.database import get_db
from app.models.base import as_aware, utcnow
from app.models.device import Device
from app.models.enums import SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.middleware.context import build_bundle
from app.services.audit_service import AuditService
from app.services.auth_service import RequestContext

bearer_scheme = HTTPBearer(auto_error=False)


def get_context_bundle(request: Request) -> ContextBundle:
    """The bundle the collector middleware attached to this request."""
    bundle = getattr(request.state, "context", None)
    if bundle is None:
        # The middleware is always installed on the real app; this path only
        # runs if a route is exercised without it, and building the bundle here
        # is better than handing the scoring engine an empty context.
        return build_bundle(request, getattr(request.state, "request_id", "unknown"))
    return bundle


def get_request_context(
    bundle: ContextBundle = Depends(get_context_bundle),
) -> RequestContext:
    """Narrow view of the bundle, for the services that only need these fields."""
    return RequestContext(
        ip_address=bundle.ip_address,
        user_agent=bundle.user_agent,
        device=bundle.device,
        bundle=bundle,
    )


@dataclass
class Principal:
    """The authenticated caller plus the session being enforced."""

    user: User
    session: UserSession
    device: Device | None
    access_jti: str

    @property
    def is_admin(self) -> bool:
        return self.user.role.is_admin

    def has_permission(self, permission: str) -> bool:
        return self.is_admin or permission in (self.user.role.permissions or [])


def _unauthorised(detail: str, code: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": f'Bearer error="{code}"'},
    )


def get_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> Principal:
    if credentials is None or not credentials.credentials:
        raise _unauthorised("Not authenticated.", "missing_token")

    try:
        payload = jwt_service.decode_token(credentials.credentials, "access")
    except jwt_service.TokenError as exc:
        raise _unauthorised(exc.message, exc.code) from exc

    user = db.get(User, uuid.UUID(payload["sub"]))
    session = db.get(UserSession, uuid.UUID(payload["sid"]))
    if user is None or session is None:
        raise _unauthorised("Session no longer exists.", "session_not_found")

    # --- continuous verification of the session itself --------------------
    if session.status is not SessionStatus.ACTIVE:
        raise _unauthorised(
            f"Session is {session.status.value.lower()}: {session.revoked_reason}".strip(": "),
            "session_revoked",
        )
    if not session.mfa_passed:
        raise _unauthorised("Multi-factor authentication is not complete.", "mfa_required")

    now = utcnow()
    expires_at = as_aware(session.expires_at)
    if expires_at and expires_at <= now:
        session.status = SessionStatus.EXPIRED
        session.ended_at = now
        session.revoked_reason = "Session lifetime elapsed."
        raise _unauthorised("Session has expired.", "session_expired")

    last_seen = as_aware(session.last_seen_at) or now
    idle_limit = timedelta(minutes=settings.session_idle_timeout_minutes)
    if now - last_seen > idle_limit:
        session.status = SessionStatus.EXPIRED
        session.ended_at = now
        session.revoked_reason = (
            f"Idle for more than {settings.session_idle_timeout_minutes} minutes."
        )
        raise _unauthorised("Session timed out through inactivity.", "session_idle")

    device = db.get(Device, session.device_id) if session.device_id else None

    # --- session binding: the token must come back on the device it was issued to
    presented = context.device.fingerprint if context.device else ""
    bound = payload.get("fp")
    if bound and presented and presented != bound:
        AuditService.record(
            db, action="SESSION_CONTEXT_MISMATCH", actor_id=user.id,
            actor_label=user.username, resource_type="session",
            resource_id=str(session.id), ip_address=context.ip_address,
            payload={
                "expected_fingerprint": bound[:16] + "...",
                "presented_fingerprint": presented[:16] + "...",
                "ip": context.ip_address,
                "network": context.bundle.network.summary() if context.bundle else None,
            },
        )
        # Commit before raising: get_db rolls back on exception, and the
        # evidence for a rejected request is exactly what must be kept.
        db.commit()
        raise _unauthorised(
            "Session is bound to a different device.", "device_mismatch"
        )

    session.last_seen_at = now
    session.request_count += 1

    return Principal(
        user=user, session=session, device=device, access_jti=payload["jti"]
    )


def require_admin(principal: Principal = Depends(get_principal)) -> Principal:
    if not principal.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges are required.",
        )
    return principal


def require_permission(permission: str):
    """Dependency factory for least-privilege checks on a named capability."""

    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires the '{permission}' permission.",
            )
        return principal

    return dependency
