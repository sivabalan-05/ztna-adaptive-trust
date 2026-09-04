"""Authentication, MFA, session lifecycle and token issuance.

The login flow is deliberately two-step, because a correct password is not an
authentication decision on its own:

    POST /api/auth/login       username + password + X-Device-Fingerprint
        -> session created (mfa_passed = False), short-lived MFA token returned
    POST /api/auth/mfa/verify  MFA token + 6-digit TOTP code
        -> access + refresh tokens issued, session marked mfa_passed

The session row exists between those two calls on purpose: an un-verified
session is real, visible on the dashboard, and scored — which is exactly what
"never trust, always verify" means. It grants no access until MFA completes.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import jwt as jwt_service
from app.core.config import settings
from app.core.context import ContextBundle
from app.core.security import verify_password
from app.external import mfa
from app.models.alert import Alert
from app.models.base import as_aware, utcnow
from app.models.device import Device
from app.models.enums import (
    AccessAction, AccountStatus, AlertSeverity, DeviceStatus, RiskLevel,
    ScoreTrigger, SessionStatus,
)
from app.models.session import UserSession
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.device_service import DeviceContext, DeviceService

logger = logging.getLogger(__name__)

#: Consecutive wrong TOTP codes before the pending session is torn down.
MAX_MFA_FAILURES = 3


class AuthError(Exception):
    """Client-safe authentication failure."""

    def __init__(self, message: str, code: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class RequestContext:
    """Network and device context for one request.

    ``bundle`` is the full ContextBundle assembled by the collector middleware
    (geo, ASN type, VPN/Tor flags, IP reputation, time of day). It is optional
    so that internal callers with no HTTP request behind them — the background
    worker, the demo scripts — can still authenticate.
    """

    ip_address: str = ""
    user_agent: str = ""
    device: DeviceContext | None = None
    bundle: ContextBundle | None = None


@dataclass
class LoginChallenge:
    """Password accepted; MFA still required."""

    mfa_required: bool
    mfa_token: str
    session_id: uuid.UUID
    device_id: uuid.UUID | None
    device_known: bool
    device_status: str
    expires_in: int


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 0
    session_id: uuid.UUID | None = None
    extra: dict[str, object] = field(default_factory=dict)


class AuthService:
    # -- password step -----------------------------------------------------

    @staticmethod
    def _find_user(db: Session, username: str) -> User | None:
        cleaned = (username or "").strip().lower()
        if not cleaned:
            return None
        return db.scalar(
            select(User).where(
                (User.username == cleaned) | (User.email == cleaned)
            )
        )

    @classmethod
    def _register_failure(
        cls, db: Session, user: User, context: RequestContext, reason: str
    ) -> None:
        """Count a failed attempt and lock the account past the threshold."""
        now = utcnow()
        user.failed_login_count += 1
        user.last_failed_login_at = now

        if user.failed_login_count >= settings.max_failed_logins:
            user.locked_until = now + timedelta(minutes=settings.account_lockout_minutes)
            db.add(
                Alert(
                    user_id=user.id,
                    severity=AlertSeverity.HIGH,
                    category="brute_force",
                    title=f"Account locked after {user.failed_login_count} failed sign-ins",
                    description=(
                        f"{user.failed_login_count} consecutive authentication "
                        f"failures for {user.username} from {context.ip_address}. "
                        f"The account is locked for "
                        f"{settings.account_lockout_minutes} minutes."
                    ),
                    evidence={
                        "failed_attempts": user.failed_login_count,
                        "ip": context.ip_address,
                        "user_agent": context.user_agent,
                        "reason": reason,
                        "lockout_minutes": settings.account_lockout_minutes,
                    },
                )
            )
            AuditService.record(
                db, action="ACCOUNT_LOCKED", actor_id=user.id,
                actor_label=user.username, resource_type="user",
                resource_id=str(user.id), ip_address=context.ip_address,
                payload={
                    "failed_attempts": user.failed_login_count,
                    "locked_until": user.locked_until.isoformat(),
                    "reason": reason,
                },
            )
        else:
            AuditService.record(
                db, action="LOGIN_FAILED", actor_id=user.id,
                actor_label=user.username, resource_type="user",
                resource_id=str(user.id), ip_address=context.ip_address,
                payload={
                    "reason": reason,
                    "failed_attempts": user.failed_login_count,
                    "attempts_remaining": max(
                        0, settings.max_failed_logins - user.failed_login_count
                    ),
                },
            )

    @classmethod
    def login(
        cls, db: Session, username: str, password: str, context: RequestContext
    ) -> LoginChallenge:
        user = cls._find_user(db, username)

        if user is None:
            # Still spend time hashing so a missing account is not detectable
            # by response timing, and never say which half was wrong.
            verify_password(password, "$argon2id$v=19$m=65536,t=2,p=4$" + "A" * 22 + "$" + "B" * 43)
            AuditService.record(
                db, action="LOGIN_FAILED", actor_label=username or "unknown",
                ip_address=context.ip_address,
                payload={"reason": "unknown_user", "username_tried": username},
            )
            raise AuthError("Invalid username or password.", "invalid_credentials")

        if user.account_status is AccountStatus.DISABLED:
            raise AuthError("This account is disabled.", "account_disabled", 403)

        if user.is_locked:
            locked_until = as_aware(user.locked_until)
            remaining = (
                int((locked_until - utcnow()).total_seconds() // 60) + 1
                if locked_until else settings.account_lockout_minutes
            )
            raise AuthError(
                f"Account is locked. Try again in {remaining} minute(s).",
                "account_locked", 423,
            )

        if not verify_password(password, user.hashed_password):
            cls._register_failure(db, user, context, "bad_password")
            raise AuthError("Invalid username or password.", "invalid_credentials")

        if context.device is None or not context.device.fingerprint:
            raise AuthError(
                "A device fingerprint is required. Enable JavaScript and retry.",
                "missing_device_fingerprint", 400,
            )

        # Password is correct: reset the failure counter before MFA.
        user.failed_login_count = 0
        user.locked_until = None

        resolution = DeviceService.register_or_touch(db, user, context.device)

        # Where the request actually came from, not where the user usually is.
        # Falling back to the account's home location would make every session
        # look local and quietly disable the location trust factor.
        network = context.bundle.network if context.bundle else None
        session = UserSession(
            user_id=user.id,
            device_id=resolution.device.id,
            status=SessionStatus.ACTIVE,
            ip_address=context.ip_address,
            country=network.geo.country if network else "",
            city=network.geo.city if network else "",
            latitude=network.geo.latitude if network else None,
            longitude=network.geo.longitude if network else None,
            asn=(network.intel.asn or network.geo.asn) if network else "",
            isp=network.geo.isp if network else "",
            is_vpn=network.intel.is_vpn if network else False,
            is_datacenter=network.intel.is_datacenter if network else False,
            ip_reputation=network.reputation.abuse_confidence if network else 0,
            started_at=utcnow(),
            last_seen_at=utcnow(),
            expires_at=utcnow() + timedelta(days=settings.refresh_token_expire_days),
            mfa_passed=False,
            step_up_required=True,
            # Trust scoring lands in Phase 4; a session legitimately starts at
            # 100 and is only decremented once the engine has run.
            current_trust_score=100.0,
            current_risk_level=RiskLevel.LOW,
            current_action=AccessAction.STEP_UP_MFA,
        )
        db.add(session)
        db.flush()

        if not user.mfa_enabled or not user.mfa_secret:
            raise AuthError(
                "MFA is not enrolled for this account. Contact an administrator.",
                "mfa_not_enrolled", 403,
            )

        token, _, expires_at = jwt_service.create_mfa_token(user.id, session.id)

        AuditService.record(
            db, action="PASSWORD_ACCEPTED", actor_id=user.id,
            actor_label=user.username, resource_type="session",
            resource_id=str(session.id), ip_address=context.ip_address,
            payload={
                "session_id": str(session.id),
                "device_known": not resolution.is_new,
                "device_status": resolution.device.status.value,
                "device_label": resolution.device.label,
                "mfa_required": True,
                "network": network.summary() if network else None,
            },
        )
        if resolution.is_new:
            db.add(
                Alert(
                    user_id=user.id, session_id=session.id,
                    severity=AlertSeverity.MEDIUM, category="new_device",
                    title=f"New device used by {user.username}",
                    description=(
                        f"A previously unseen device fingerprint signed in as "
                        f"{user.username} from {context.ip_address}. The device is "
                        f"registered as PENDING and awaits administrator approval."
                    ),
                    evidence={
                        "fingerprint": context.device.fingerprint[:16] + "...",
                        "label": resolution.device.label,
                        "ip": context.ip_address,
                        "user_agent": context.user_agent,
                    },
                )
            )

        return LoginChallenge(
            mfa_required=True,
            mfa_token=token,
            session_id=session.id,
            device_id=resolution.device.id,
            device_known=not resolution.is_new,
            device_status=resolution.device.status.value,
            expires_in=int((expires_at - utcnow()).total_seconds()),
        )

    # -- MFA step ----------------------------------------------------------

    @classmethod
    def verify_mfa(
        cls, db: Session, mfa_token: str, code: str, context: RequestContext
    ) -> TokenPair:
        try:
            payload = jwt_service.decode_token(mfa_token, "mfa")
        except jwt_service.TokenError as exc:
            raise AuthError(exc.message, exc.code) from exc

        user = db.get(User, uuid.UUID(payload["sub"]))
        session = db.get(UserSession, uuid.UUID(payload["sid"]))
        if user is None or session is None:
            raise AuthError("Session no longer exists.", "session_not_found")
        if session.status is not SessionStatus.ACTIVE:
            raise AuthError("Session is no longer active.", "session_inactive")
        if not user.mfa_secret:
            raise AuthError("MFA is not enrolled.", "mfa_not_enrolled", 403)

        if not mfa.verify_code(user.mfa_secret, code):
            session.mfa_failures += 1
            AuditService.record(
                db, action="MFA_FAILED", actor_id=user.id, actor_label=user.username,
                resource_type="session", resource_id=str(session.id),
                ip_address=context.ip_address,
                payload={"attempt": session.mfa_failures,
                         "max_attempts": MAX_MFA_FAILURES},
            )
            if session.mfa_failures >= MAX_MFA_FAILURES:
                cls.revoke_session(
                    db, session,
                    reason=f"{MAX_MFA_FAILURES} consecutive MFA failures.",
                    actor_label="auth-service",
                )
                cls._register_failure(db, user, context, "mfa_failed")
                jwt_service.revoke_jti(payload["jti"], payload.get("exp"))
                raise AuthError(
                    "Too many incorrect codes. Sign in again.", "mfa_locked", 429,
                )
            raise AuthError("Incorrect verification code.", "invalid_mfa_code")

        # Correct code: the MFA token is single-use.
        jwt_service.revoke_jti(payload["jti"], payload.get("exp"))

        device = db.get(Device, session.device_id) if session.device_id else None
        fingerprint = device.fingerprint if device else None

        access, _, _ = jwt_service.create_access_token(
            user.id, session.id, user.role.name, fingerprint
        )
        refresh, refresh_jti, _ = jwt_service.create_refresh_token(user.id, session.id)

        session.mfa_passed = True
        session.step_up_required = False
        session.mfa_failures = 0
        session.refresh_jti = refresh_jti
        session.last_seen_at = utcnow()
        user.last_login_at = utcnow()
        user.failed_login_count = 0
        db.flush()

        # Score the session now that authentication is complete. Imported here
        # rather than at module scope because the trust engine calls back into
        # this service to revoke a CRITICAL session.
        from app.services.trust_service import TrustService

        assessment = None
        if context.bundle is not None:
            assessment, _ = TrustService.evaluate(
                db, user=user, session=session, bundle=context.bundle,
                trigger=ScoreTrigger.LOGIN, device=device,
            )
        else:
            session.current_action = AccessAction.ALLOW

        AuditService.record(
            db, action="LOGIN_SUCCESS", actor_id=user.id, actor_label=user.username,
            resource_type="session", resource_id=str(session.id),
            ip_address=context.ip_address,
            payload={
                "session_id": str(session.id),
                "device": device.label if device else None,
                "device_status": device.status.value if device else None,
                "mfa": "totp",
                "trust_score": assessment.score if assessment else None,
                "risk_level": assessment.risk_level.value if assessment else None,
            },
        )

        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            expires_in=settings.access_token_expire_minutes * 60,
            session_id=session.id,
            extra={
                "username": user.username,
                "full_name": user.full_name,
                "role": user.role.name,
                "is_admin": user.role.is_admin,
                "permissions": user.role.permissions,
                "device_status": device.status.value if device else None,
                "device_approved": (
                    device.status is DeviceStatus.APPROVED if device else False
                ),
                "trust_score": assessment.score if assessment else None,
                "risk_level": assessment.risk_level.value if assessment else None,
                "action": assessment.action.value if assessment else None,
                "trust_reason": assessment.headline if assessment else None,
            },
        )

    # -- token lifecycle ---------------------------------------------------

    @classmethod
    def refresh(
        cls, db: Session, refresh_token: str, context: RequestContext
    ) -> TokenPair:
        """Rotate the refresh token; the presented one is immediately revoked.

        A revoked token is decoded anyway rather than refused outright: an
        already-used refresh token coming back is the replay signal, and
        reacting to it needs the session id inside the token.
        """
        try:
            payload = jwt_service.decode_token(
                refresh_token, "refresh", allow_revoked=True
            )
        except jwt_service.TokenError as exc:
            raise AuthError(exc.message, exc.code) from exc

        already_revoked = jwt_service.is_revoked(payload["jti"])

        session = db.get(UserSession, uuid.UUID(payload["sid"]))
        user = db.get(User, uuid.UUID(payload["sub"]))
        if session is None or user is None:
            raise AuthError("Session no longer exists.", "session_not_found")
        if session.status is not SessionStatus.ACTIVE:
            raise AuthError("Session has been revoked or expired.", "session_inactive")
        if not session.mfa_passed:
            raise AuthError("Session never completed MFA.", "mfa_required")

        # Refresh-token reuse: the token was already spent, or it is no longer
        # the live one for this session. Either way it was replayed, so the
        # session is killed rather than merely refused.
        if already_revoked or (
            session.refresh_jti and session.refresh_jti != payload["jti"]
        ):
            cls.revoke_session(
                db, session, reason="Refresh token reuse detected.",
                actor_label="auth-service",
            )
            db.add(
                Alert(
                    user_id=user.id, session_id=session.id,
                    severity=AlertSeverity.CRITICAL, category="token_replay",
                    title="Replayed refresh token",
                    description=(
                        f"A superseded refresh token for {user.username} was "
                        f"presented from {context.ip_address}. The session was "
                        f"revoked."
                    ),
                    evidence={"ip": context.ip_address, "jti": payload["jti"]},
                )
            )
            raise AuthError("Refresh token has already been used.", "token_replay")

        jwt_service.revoke_jti(payload["jti"], payload.get("exp"))

        device = db.get(Device, session.device_id) if session.device_id else None
        access, _, _ = jwt_service.create_access_token(
            user.id, session.id, user.role.name,
            device.fingerprint if device else None,
        )
        new_refresh, new_jti, _ = jwt_service.create_refresh_token(user.id, session.id)
        session.refresh_jti = new_jti
        session.last_seen_at = utcnow()

        AuditService.record(
            db, action="TOKEN_REFRESHED", actor_id=user.id, actor_label=user.username,
            resource_type="session", resource_id=str(session.id),
            ip_address=context.ip_address, payload={"session_id": str(session.id)},
        )
        return TokenPair(
            access_token=access, refresh_token=new_refresh,
            expires_in=settings.access_token_expire_minutes * 60,
            session_id=session.id,
        )

    @classmethod
    def logout(
        cls, db: Session, session: UserSession, user: User,
        access_jti: str | None, context: RequestContext,
    ) -> None:
        if session.refresh_jti:
            jwt_service.revoke_jti(session.refresh_jti)
        if access_jti:
            jwt_service.revoke_jti(
                access_jti,
                utcnow() + timedelta(minutes=settings.access_token_expire_minutes),
            )
        session.status = SessionStatus.LOGGED_OUT
        session.ended_at = utcnow()
        session.revoked_reason = "User signed out."
        AuditService.record(
            db, action="LOGOUT", actor_id=user.id, actor_label=user.username,
            resource_type="session", resource_id=str(session.id),
            ip_address=context.ip_address, payload={"session_id": str(session.id)},
        )

    @staticmethod
    def revoke_session(
        db: Session, session: UserSession, reason: str,
        actor_id: uuid.UUID | None = None, actor_label: str = "system",
    ) -> UserSession:
        """Terminate a session immediately and deny its refresh token."""
        if session.refresh_jti:
            jwt_service.revoke_jti(session.refresh_jti)
        session.status = SessionStatus.REVOKED
        session.ended_at = utcnow()
        session.revoked_reason = reason
        session.current_action = AccessAction.REVOKE_SESSION
        db.flush()
        AuditService.record(
            db, action="SESSION_REVOKED", actor_id=actor_id, actor_label=actor_label,
            resource_type="session", resource_id=str(session.id),
            payload={"session_id": str(session.id), "reason": reason},
        )
        return session
