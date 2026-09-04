"""Dashboard aggregates: one call for the overview page."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai import anomaly
from app.api.alerts import to_row
from app.core.config import settings
from app.core.database import get_db
from app.core.dependencies import Principal, require_permission
from app.models.access_request import AccessRequest
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.base import utcnow
from app.models.device import Device
from app.models.enums import (
    AccountStatus, AlertStatus, DeviceStatus, RiskLevel, SessionStatus,
)
from app.models.session import UserSession
from app.models.trust_score import TrustScore
from app.models.user import User
from app.schemas.admin import OverviewOut, RiskSlice, TrustPoint

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=OverviewOut, summary="Everything the overview needs")
def overview(
    _: Principal = Depends(require_permission("sessions:read")),
    db: Session = Depends(get_db),
    hours: int = Query(default=24, ge=1, le=720, description="Window for the trend line"),
) -> OverviewOut:
    now = utcnow()
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    since = now - timedelta(hours=hours)

    live = (
        UserSession.status == SessionStatus.ACTIVE,
        UserSession.mfa_passed.is_(True),
    )
    active = int(db.scalar(select(func.count(UserSession.id)).where(*live)) or 0)
    mean = db.scalar(select(func.avg(UserSession.current_trust_score)).where(*live))

    risk = [
        RiskSlice(
            level=level.value,
            count=int(
                db.scalar(
                    select(func.count(UserSession.id)).where(
                        *live, UserSession.current_risk_level == level
                    )
                ) or 0
            ),
        )
        for level in RiskLevel
    ]

    # Trend line: mean score per hour over the window. Bucketing in Python
    # keeps this identical on SQLite and PostgreSQL, whose date-truncation
    # functions differ.
    scores = db.scalars(
        select(TrustScore)
        .where(TrustScore.created_at >= since)
        .order_by(TrustScore.created_at)
    ).all()
    buckets: dict[str, list[float]] = {}
    stamps: dict[str, object] = {}
    for row in scores:
        key = row.created_at.strftime("%Y-%m-%dT%H")
        buckets.setdefault(key, []).append(row.score)
        stamps.setdefault(key, row.created_at.replace(minute=0, second=0, microsecond=0))

    trend: list[TrustPoint] = []
    for key in sorted(buckets):
        values = buckets[key]
        average = sum(values) / len(values)
        trend.append(
            TrustPoint(
                at=stamps[key],
                score=round(average, 2),
                risk_level=(
                    RiskLevel.LOW.value if average >= settings.risk_low_min
                    else RiskLevel.MEDIUM.value if average >= settings.risk_medium_min
                    else RiskLevel.HIGH.value if average >= settings.risk_high_min
                    else RiskLevel.CRITICAL.value
                ),
            )
        )

    model = anomaly.model_info()

    return OverviewOut(
        active_sessions=active,
        average_trust_score=round(float(mean), 1) if mean is not None else None,
        alerts_today=int(
            db.scalar(select(func.count(Alert.id)).where(Alert.created_at >= midnight))
            or 0
        ),
        open_alerts=int(
            db.scalar(
                select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
            ) or 0
        ),
        blocked_attempts_today=int(
            db.scalar(
                select(func.count(AccessRequest.id)).where(
                    AccessRequest.granted.is_(False),
                    AccessRequest.requested_at >= midnight,
                )
            ) or 0
        ),
        total_users=int(db.scalar(select(func.count(User.id))) or 0),
        locked_users=int(
            db.scalar(
                select(func.count(User.id)).where(
                    (User.account_status == AccountStatus.LOCKED)
                    | (User.locked_until.isnot(None))
                )
            ) or 0
        ),
        pending_devices=int(
            db.scalar(
                select(func.count(Device.id)).where(
                    Device.status == DeviceStatus.PENDING
                )
            ) or 0
        ),
        risk_distribution=risk,
        trust_over_time=trend,
        recent_alerts=[
            to_row(db, alert)
            for alert in db.scalars(
                select(Alert).order_by(Alert.created_at.desc()).limit(6)
            )
        ],
        verification_interval_seconds=(
            settings.continuous_verification_interval_seconds
        ),
        anomaly_model_version=(model or {}).get("version"),
        audit_records=int(db.scalar(select(func.count(AuditLog.id))) or 0),
    )
