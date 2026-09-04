"""Active session queries and administrative revocation."""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.base import as_aware, utcnow
from app.models.enums import RiskLevel, SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.services.auth_service import AuthService
from app.services.events import Event, publish_sync

logger = logging.getLogger(__name__)


class SessionService:
    @staticmethod
    def active(
        db: Session,
        *,
        user_id: uuid.UUID | None = None,
        risk_level: RiskLevel | None = None,
        mfa_only: bool = True,
        limit: int = 200,
    ) -> list[UserSession]:
        """Sessions currently in play.

        ``mfa_only`` excludes sessions stuck between the password and MFA steps.
        Those are real and are scored, but they are not what an operator means
        by "who is logged in right now".
        """
        stmt = (
            select(UserSession)
            .where(UserSession.status == SessionStatus.ACTIVE)
            .order_by(UserSession.last_seen_at.desc())
            .limit(limit)
        )
        if mfa_only:
            stmt = stmt.where(UserSession.mfa_passed.is_(True))
        if user_id is not None:
            stmt = stmt.where(UserSession.user_id == user_id)
        if risk_level is not None:
            stmt = stmt.where(UserSession.current_risk_level == risk_level)
        return list(db.scalars(stmt))

    @staticmethod
    def due_for_verification(
        db: Session, *, interval_seconds: int | None = None, limit: int = 500
    ) -> list[UserSession]:
        """Active sessions not re-scored within the verification interval."""
        # `or` would turn an explicit 0 — "everything is due, sweep now" — back
        # into the default interval, which is exactly what /verify-now asks for.
        interval = (
            settings.continuous_verification_interval_seconds
            if interval_seconds is None
            else interval_seconds
        )
        cutoff = utcnow() - timedelta(seconds=interval)
        stmt = (
            select(UserSession)
            .where(
                UserSession.status == SessionStatus.ACTIVE,
                UserSession.mfa_passed.is_(True),
            )
            .order_by(UserSession.last_verified_at.asc().nulls_first())
            .limit(limit)
        )
        return [
            session
            for session in db.scalars(stmt)
            if session.last_verified_at is None
            or (as_aware(session.last_verified_at) or utcnow()) <= cutoff
        ]

    @staticmethod
    def stale(db: Session, limit: int = 500) -> list[UserSession]:
        """Active sessions past their expiry or idle timeout."""
        now = utcnow()
        idle_cutoff = now - timedelta(minutes=settings.session_idle_timeout_minutes)
        rows = db.scalars(
            select(UserSession)
            .where(UserSession.status == SessionStatus.ACTIVE)
            .limit(limit)
        )
        out: list[UserSession] = []
        for session in rows:
            expires = as_aware(session.expires_at)
            last_seen = as_aware(session.last_seen_at) or now
            if (expires and expires <= now) or last_seen <= idle_cutoff:
                out.append(session)
        return out

    @staticmethod
    def revoke(
        db: Session,
        session: UserSession,
        *,
        reason: str,
        actor: User | None = None,
        actor_label: str | None = None,
    ) -> UserSession:
        """Kill a session and tell every live listener immediately.

        The database change alone already stops the next HTTP request, because
        every protected route re-reads the session. The event is what closes the
        user's open WebSocket without waiting for them to make one.
        """
        AuthService.revoke_session(
            db, session, reason=reason,
            actor_id=actor.id if actor else None,
            actor_label=actor_label or (actor.username if actor else "system"),
        )
        publish_sync(
            Event(
                type="session.revoked",
                payload={
                    "session_id": str(session.id),
                    "user_id": str(session.user_id),
                    "reason": reason,
                    "revoked_by": actor_label or (actor.username if actor else "system"),
                },
                audience_user_ids=(str(session.user_id),),
            )
        )
        logger.info("Session %s revoked: %s", session.id, reason)
        return session

    @staticmethod
    def summary(db: Session) -> dict[str, object]:
        """Live counters for the dashboard header."""
        live = (
            UserSession.status == SessionStatus.ACTIVE,
            UserSession.mfa_passed.is_(True),
        )
        total = int(
            db.scalar(select(func.count(UserSession.id)).where(*live)) or 0
        )
        by_risk = {
            level.value: int(
                db.scalar(
                    select(func.count(UserSession.id)).where(
                        *live, UserSession.current_risk_level == level
                    )
                )
                or 0
            )
            for level in RiskLevel
        }
        mean = db.scalar(
            select(func.avg(UserSession.current_trust_score)).where(*live)
        )
        return {
            "active_sessions": total,
            "by_risk_level": by_risk,
            "average_trust_score": round(float(mean), 1) if mean is not None else None,
        }
