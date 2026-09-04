"""Live session monitoring and administrative revocation."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_principal, require_permission,
)
from app.models.device import Device
from app.models.enums import RiskLevel, SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.schemas.sessions import (
    LiveSessionOut, RevokeRequest, SessionSummary, SweepOut,
)
from app.services.events import bus
from app.services.session_service import SessionService
from app.workers import continuous_verification

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


def _to_out(db: Session, session: UserSession) -> LiveSessionOut:
    user = db.get(User, session.user_id)
    device = db.get(Device, session.device_id) if session.device_id else None
    return LiveSessionOut(
        id=session.id,
        user_id=session.user_id,
        username=user.username if user else "(deleted)",
        full_name=user.full_name if user else "",
        role=user.role.name if user else "",
        status=session.status.value,
        ip_address=session.ip_address,
        city=session.city,
        country=session.country,
        is_vpn=session.is_vpn,
        device_label=device.label if device else None,
        device_status=device.status.value if device else None,
        started_at=session.started_at,
        last_seen_at=session.last_seen_at,
        last_verified_at=session.last_verified_at,
        expires_at=session.expires_at,
        current_trust_score=session.current_trust_score,
        current_risk_level=session.current_risk_level.value,
        current_action=session.current_action.value,
        mfa_passed=session.mfa_passed,
        step_up_required=session.step_up_required,
        request_count=session.request_count,
        denied_count=session.denied_count,
        revoked_reason=session.revoked_reason,
    )


@router.get(
    "",
    response_model=list[LiveSessionOut],
    summary="Active sessions (analysts, admins)",
)
def list_sessions(
    principal: Principal = Depends(require_permission("sessions:read")),
    db: Session = Depends(get_db),
    risk_level: RiskLevel | None = Query(default=None),
    include_pending_mfa: bool = Query(
        default=False,
        description="Include sessions still between the password and MFA steps",
    ),
    limit: int = Query(default=200, ge=1, le=500),
) -> list[LiveSessionOut]:
    rows = SessionService.active(
        db, risk_level=risk_level, mfa_only=not include_pending_mfa, limit=limit
    )
    return [_to_out(db, s) for s in rows]


@router.get("/summary", response_model=SessionSummary, summary="Live counters")
def summary(
    principal: Principal = Depends(require_permission("sessions:read")),
    db: Session = Depends(get_db),
) -> SessionSummary:
    data = SessionService.summary(db)
    return SessionSummary(
        **data,
        verification_interval_seconds=(
            settings.continuous_verification_interval_seconds
        ),
        live_subscribers=bus.subscriber_count,
    )


@router.get("/me", response_model=list[LiveSessionOut], summary="Your own sessions")
def my_sessions(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> list[LiveSessionOut]:
    rows = SessionService.active(db, user_id=principal.user.id, mfa_only=False)
    return [_to_out(db, s) for s in rows]


@router.get("/{session_id}", response_model=LiveSessionOut, summary="One session")
def get_session(
    session_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> LiveSessionOut:
    session = db.get(UserSession, session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found.")
    # A user may read their own session; anyone else needs the permission.
    if session.user_id != principal.user.id and not principal.has_permission(
        "sessions:read"
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your session.")
    return _to_out(db, session)


@router.post(
    "/{session_id}/revoke",
    response_model=LiveSessionOut,
    summary="Terminate a session immediately",
)
def revoke(
    session_id: uuid.UUID,
    payload: RevokeRequest,
    principal: Principal = Depends(require_permission("sessions:revoke")),
    db: Session = Depends(get_db),
) -> LiveSessionOut:
    """Kill a session now.

    The database change alone stops the next HTTP request, because every
    protected route re-reads the session rather than trusting the token. The
    published event closes the user's open WebSocket without waiting for them
    to make a request at all.
    """
    session = db.get(UserSession, session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found.")
    if session.status is not SessionStatus.ACTIVE:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Session is already {session.status.value.lower()}.",
        )

    SessionService.revoke(
        db, session, reason=payload.reason, actor=principal.user
    )
    db.commit()
    return _to_out(db, session)


@router.post(
    "/verify-now",
    response_model=SweepOut,
    summary="Run a verification sweep immediately",
)
def verify_now(
    principal: Principal = Depends(require_permission("sessions:read")),
    db: Session = Depends(get_db),
) -> SweepOut:
    """Trigger the sweep the worker runs on its interval.

    Identical code path — this exists so the effect can be shown on demand
    instead of waiting out the interval in front of an audience.
    """
    result = continuous_verification.sweep(db, interval_seconds=0)
    return SweepOut(
        checked=result.checked, revoked=result.revoked, expired=result.expired,
        escalated=result.escalated, improved=result.improved,
        errors=result.errors, duration_ms=round(result.duration_ms, 2),
        changes=result.changes,
    )
