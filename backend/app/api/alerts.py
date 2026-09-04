"""Security alerts: feed, triage and statistics."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_context_bundle, require_permission,
)
from app.models.alert import Alert
from app.models.base import utcnow
from app.models.enums import AlertSeverity, AlertStatus
from app.models.user import User
from app.schemas.admin import AlertPage, AlertResolve, AlertRow, AlertStats
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def to_row(db: Session, alert: Alert) -> AlertRow:
    def name_of(user_id: uuid.UUID | None) -> str | None:
        if user_id is None:
            return None
        user = db.get(User, user_id)
        return user.username if user else None

    return AlertRow(
        id=alert.id,
        severity=alert.severity.value,
        status=alert.status.value,
        category=alert.category,
        title=alert.title,
        description=alert.description,
        trust_score=alert.trust_score,
        evidence=alert.evidence or {},
        user_id=alert.user_id,
        username=name_of(alert.user_id),
        session_id=alert.session_id,
        created_at=alert.created_at,
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by=name_of(alert.acknowledged_by_id),
        resolved_at=alert.resolved_at,
        resolved_by=name_of(alert.resolved_by_id),
        resolution_note=alert.resolution_note,
    )


@router.get("", response_model=AlertPage, summary="Alert feed, newest first")
def list_alerts(
    _: Principal = Depends(require_permission("alerts:read")),
    db: Session = Depends(get_db),
    alert_status: AlertStatus | None = Query(default=None, alias="status"),
    severity: AlertSeverity | None = Query(default=None),
    category: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AlertPage:
    stmt = select(Alert)
    if alert_status is not None:
        stmt = stmt.where(Alert.status == alert_status)
    if severity is not None:
        stmt = stmt.where(Alert.severity == severity)
    if category:
        stmt = stmt.where(Alert.category == category)
    if since is not None:
        stmt = stmt.where(Alert.created_at >= since)

    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    rows = db.scalars(
        stmt.order_by(Alert.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return AlertPage(
        total=total, limit=limit, offset=offset,
        alerts=[to_row(db, alert) for alert in rows],
    )


@router.get("/stats", response_model=AlertStats, summary="Alert counters")
def stats(
    _: Principal = Depends(require_permission("alerts:read")),
    db: Session = Depends(get_db),
) -> AlertStats:
    def count(*where) -> int:
        return int(db.scalar(select(func.count(Alert.id)).where(*where)) or 0)

    midnight = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return AlertStats(
        open=count(Alert.status == AlertStatus.OPEN),
        acknowledged=count(Alert.status == AlertStatus.ACKNOWLEDGED),
        resolved=count(Alert.status == AlertStatus.RESOLVED),
        today=count(Alert.created_at >= midnight),
        by_severity={
            name: int(n)
            for name, n in db.execute(
                select(Alert.severity, func.count()).group_by(Alert.severity)
            ).all()
        },
        by_category={
            name: int(n)
            for name, n in db.execute(
                select(Alert.category, func.count())
                .group_by(Alert.category)
                .order_by(func.count().desc())
                .limit(12)
            ).all()
        },
    )


@router.get("/{alert_id}", response_model=AlertRow, summary="One alert")
def get_alert(
    alert_id: uuid.UUID,
    _: Principal = Depends(require_permission("alerts:read")),
    db: Session = Depends(get_db),
) -> AlertRow:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found.")
    return to_row(db, alert)


@router.post(
    "/{alert_id}/acknowledge", response_model=AlertRow, summary="Acknowledge an alert"
)
def acknowledge(
    alert_id: uuid.UUID,
    principal: Principal = Depends(require_permission("alerts:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> AlertRow:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found.")
    if alert.status is not AlertStatus.OPEN:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Alert is already {alert.status.value.lower()}.",
        )

    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = utcnow()
    alert.acknowledged_by_id = principal.user.id
    db.flush()

    AuditService.record(
        db, action="ALERT_ACKNOWLEDGED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="alert",
        resource_id=str(alert.id), ip_address=bundle.ip_address,
        payload={"category": alert.category, "severity": alert.severity.value},
    )
    return to_row(db, alert)


@router.post("/{alert_id}/resolve", response_model=AlertRow, summary="Resolve an alert")
def resolve(
    alert_id: uuid.UUID,
    payload: AlertResolve,
    principal: Principal = Depends(require_permission("alerts:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> AlertRow:
    """Resolving is allowed from OPEN as well as ACKNOWLEDGED.

    An analyst who investigates and closes an alert in one sitting should not
    have to click acknowledge first just to satisfy a state machine.
    """
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found.")
    if alert.status is AlertStatus.RESOLVED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Alert is already resolved.")

    now = utcnow()
    if alert.acknowledged_at is None:
        alert.acknowledged_at = now
        alert.acknowledged_by_id = principal.user.id
    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = now
    alert.resolved_by_id = principal.user.id
    alert.resolution_note = payload.note
    db.flush()

    AuditService.record(
        db, action="ALERT_RESOLVED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="alert",
        resource_id=str(alert.id), ip_address=bundle.ip_address,
        payload={
            "category": alert.category, "severity": alert.severity.value,
            "note": payload.note,
        },
    )
    return to_row(db, alert)
