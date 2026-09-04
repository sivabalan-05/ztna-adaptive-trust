"""Continuous verification.

Every active session is re-scored on a fixed interval, whether or not its owner
has made a request. This is what separates Zero Trust from an ordinary login
check: trust is not something you earn once at the door.

Each sweep, for every session due:

1. rebuild the context — the session's last known network re-resolved through
   the live providers, and the time *now*;
2. re-score it through the same engine a request would use;
3. enforce any band change immediately, including revoking mid-session;
4. publish the new score so open dashboards and the user's own client see it.

Re-resolving the network matters. A score that only ever changed when the user
did something would not be continuous — it would be lazy evaluation with a
timer. Re-resolving means a session whose source address lands on a blocklist
between sweeps drops without the user touching anything.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.context import ContextBundle, TemporalContext
from app.core.database import SessionLocal
from app.models.base import as_aware, utcnow
from app.models.device import Device
from app.models.enums import RiskLevel, ScoreTrigger, SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.middleware.context import collect_network_context
from app.services.device_service import DeviceContext
from app.services.events import Event, publish_sync
from app.services.session_service import SessionService
from app.services.trust_service import TrustService

logger = logging.getLogger(__name__)

_BAND_ORDER = {
    RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3,
}


@dataclass
class SweepResult:
    checked: int = 0
    revoked: int = 0
    expired: int = 0
    escalated: int = 0
    improved: int = 0
    errors: int = 0
    duration_ms: float = 0.0
    changes: list[dict[str, object]] = field(default_factory=list)

    def line(self) -> str:
        return (
            f"checked {self.checked}, escalated {self.escalated}, "
            f"revoked {self.revoked}, expired {self.expired}, "
            f"errors {self.errors} in {self.duration_ms:.0f}ms"
        )


def bundle_for_session(session: UserSession, device: Device | None) -> ContextBundle:
    """Rebuild a request-shaped context for a session with no request behind it.

    The network is the session's last known address, re-resolved now, so a
    reputation change between sweeps is picked up. The time is the time of this
    sweep, so a session drifting outside its owner's usual hours is noticed
    while it is still open.
    """
    return ContextBundle(
        request_id=f"sweep-{session.id.hex[:12]}",
        method="INTERNAL",
        path="/worker/continuous-verification",
        user_agent=device.user_agent if device else "",
        network=collect_network_context(session.ip_address),
        temporal=TemporalContext.from_utc(utcnow()),
        device=(
            DeviceContext(
                fingerprint=device.fingerprint,
                user_agent=device.user_agent,
                platform=device.platform,
                screen_resolution=device.screen_resolution,
                timezone=device.device_timezone,
                language=device.language,
            )
            if device
            else None
        ),
    )


def expire_stale(db: Session) -> int:
    """Close sessions past their lifetime or idle timeout."""
    count = 0
    for session in SessionService.stale(db):
        now = utcnow()
        expires = as_aware(session.expires_at)
        session.status = SessionStatus.EXPIRED
        session.ended_at = now
        session.revoked_reason = (
            "Session lifetime elapsed."
            if expires and expires <= now
            else "Idle timeout."
        )
        count += 1
        publish_sync(
            Event(
                type="session.expired",
                payload={
                    "session_id": str(session.id),
                    "user_id": str(session.user_id),
                    "reason": session.revoked_reason,
                },
                audience_user_ids=(str(session.user_id),),
            )
        )
    if count:
        db.flush()
    return count


def verify_session(db: Session, session: UserSession) -> dict[str, object] | None:
    """Re-score one session and enforce the result. Returns the change, if any."""
    user = db.get(User, session.user_id)
    if user is None:
        return None

    device = db.get(Device, session.device_id) if session.device_id else None
    previous_score = session.current_trust_score
    previous_band = session.current_risk_level

    assessment, _ = TrustService.evaluate(
        db,
        user=user,
        session=session,
        bundle=bundle_for_session(session, device),
        trigger=ScoreTrigger.PERIODIC,
        device=device,
    )

    change = {
        "session_id": str(session.id),
        "user_id": str(user.id),
        "username": user.username,
        "score": assessment.score,
        "previous_score": previous_score,
        "risk_level": assessment.risk_level.value,
        "previous_risk_level": previous_band.value,
        "action": assessment.action.value,
        "reason": assessment.headline,
        "anomaly_score": assessment.anomaly_score,
        "band_changed": assessment.risk_level is not previous_band,
        "escalated": (
            _BAND_ORDER[assessment.risk_level] > _BAND_ORDER[previous_band]
        ),
        "revoked": session.status is not SessionStatus.ACTIVE,
    }

    # Operators see every session; the owner sees their own.
    publish_sync(
        Event(
            type="session.score",
            payload=change,
            audience_user_ids=(str(user.id),),
        )
    )
    return change


def sweep(db: Session, *, interval_seconds: int | None = None) -> SweepResult:
    """One pass over every session due for re-verification."""
    import time

    started = time.perf_counter()
    result = SweepResult()

    result.expired = expire_stale(db)

    for session in SessionService.due_for_verification(
        db, interval_seconds=interval_seconds
    ):
        try:
            change = verify_session(db, session)
        except Exception:
            result.errors += 1
            logger.exception("Failed to verify session %s", session.id)
            db.rollback()
            continue

        if change is None:
            continue

        result.checked += 1
        if change["revoked"]:
            result.revoked += 1
        if change["escalated"]:
            result.escalated += 1
        elif change["band_changed"]:
            result.improved += 1
        if change["band_changed"]:
            result.changes.append(change)

    db.commit()
    result.duration_ms = (time.perf_counter() - started) * 1000
    return result


def sweep_once(interval_seconds: int | None = None, factory=None) -> SweepResult:
    """Run one sweep on its own database session, for the loop."""
    factory = factory or SessionLocal
    with factory() as db:
        return sweep(db, interval_seconds=interval_seconds)


async def verification_loop(stop, interval_seconds: int | None = None) -> None:
    """Sweep forever on the configured interval."""
    import asyncio

    from app.core.config import settings

    interval = (
        settings.continuous_verification_interval_seconds
        if interval_seconds is None
        else interval_seconds
    )
    logger.info("Continuous verification running every %ds.", interval)

    while not stop.is_set():
        try:
            result = await asyncio.to_thread(sweep_once, interval)
            if result.checked or result.expired:
                logger.info("Verification sweep: %s", result.line())
            for change in result.changes:
                logger.info(
                    "  %s %.0f -> %.0f (%s -> %s) %s",
                    change["username"], change["previous_score"], change["score"],
                    change["previous_risk_level"], change["risk_level"],
                    "REVOKED" if change["revoked"] else "",
                )
        except Exception:
            # One bad sweep must not stop continuous verification for good.
            logger.exception("Verification sweep failed; continuing.")

        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            continue
