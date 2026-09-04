"""Trust score API: current score, live re-evaluation, history and config."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import anomaly
from app.ai.classifier import bands
from app.ai.overrides import OVERRIDES
from app.core.config import settings
from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_context_bundle, get_principal, require_permission,
)
from app.models.enums import SENSITIVITY_MIN_TRUST, ScoreTrigger
from app.models.session import UserSession
from app.models.trust_score import TrustScore
from app.models.user import User
from app.schemas.trust import (
    TrustAssessmentOut, TrustConfigOut, TrustHistoryPoint, TrustScoreOut,
)
from app.services.trust_service import TrustService

router = APIRouter(prefix="/api/trust", tags=["trust"])


@router.get(
    "/config",
    response_model=TrustConfigOut,
    summary="Scoring weights, risk bands, sensitivity floors and overrides",
)
def config(_: Principal = Depends(get_principal)) -> TrustConfigOut:
    """Everything the dashboard needs to explain the model, read from settings.

    The UI renders its legend from this rather than hardcoding numbers that
    could drift out of step with the engine.
    """
    return TrustConfigOut(
        weights=settings.trust_weights,
        bands=bands(),
        sensitivity_floors={
            sensitivity.value: floor
            for sensitivity, floor in SENSITIVITY_MIN_TRUST.items()
        },
        overrides=[
            {"name": o.name, "clamps_to": o.cap, "reason": o.reason}
            for o in sorted(OVERRIDES.values(), key=lambda o: o.cap)
        ],
        anomaly_model_available=anomaly.is_available(),
        anomaly_model=anomaly.model_info(),
        continuous_verification_interval_seconds=(
            settings.continuous_verification_interval_seconds
        ),
    )


@router.get(
    "/me",
    response_model=TrustScoreOut,
    summary="The most recent score for the caller's session",
)
def my_score(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> TrustScore:
    row = TrustService.latest(db, principal.session.id)
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "This session has not been scored yet."
        )
    return row


@router.post(
    "/me/evaluate",
    response_model=TrustAssessmentOut,
    summary="Re-score the caller's session right now",
)
def evaluate_me(
    principal: Principal = Depends(get_principal),
    bundle: ContextBundle = Depends(get_context_bundle),
    db: Session = Depends(get_db),
) -> TrustAssessmentOut:
    """Continuous verification on demand.

    The background worker runs this same path every 30 seconds from Phase 8;
    the endpoint exists so the effect can be demonstrated immediately.
    """
    assessment, _ = TrustService.evaluate(
        db,
        user=principal.user,
        session=principal.session,
        bundle=bundle,
        trigger=ScoreTrigger.CONTEXT_CHANGE,
        device=principal.device,
    )
    return TrustAssessmentOut(**assessment.to_dict())


@router.get(
    "/sessions/{session_id}",
    response_model=TrustScoreOut,
    summary="Latest score for any session (analysts, admins)",
)
def session_score(
    session_id: uuid.UUID,
    principal: Principal = Depends(require_permission("sessions:read")),
    db: Session = Depends(get_db),
) -> TrustScore:
    row = TrustService.latest(db, session_id)
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "No score recorded for that session."
        )
    return row


@router.get(
    "/sessions/{session_id}/history",
    response_model=list[TrustHistoryPoint],
    summary="Every recalculation for a session, oldest first",
)
def session_history(
    session_id: uuid.UUID,
    principal: Principal = Depends(require_permission("sessions:read")),
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[TrustHistoryPoint]:
    if db.get(UserSession, session_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found.")

    return [
        TrustHistoryPoint(
            at=row.created_at, score=row.score, risk_level=row.risk_level.value,
            action=row.action.value, trigger=row.trigger.value, reason=row.reason,
        )
        for row in TrustService.history(db, session_id, limit)
    ]


@router.get(
    "/users/{user_id}/history",
    response_model=list[TrustHistoryPoint],
    summary="A user's score over time across all sessions",
)
def user_history(
    user_id: uuid.UUID,
    principal: Principal = Depends(require_permission("users:read")),
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[TrustHistoryPoint]:
    if db.get(User, user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")

    rows = db.scalars(
        select(TrustScore)
        .where(TrustScore.user_id == user_id)
        .order_by(TrustScore.created_at.desc())
        .limit(limit)
    ).all()

    return [
        TrustHistoryPoint(
            at=row.created_at, score=row.score, risk_level=row.risk_level.value,
            action=row.action.value, trigger=row.trigger.value, reason=row.reason,
        )
        for row in reversed(rows)
    ]
