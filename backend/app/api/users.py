"""User administration."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_context_bundle, require_permission,
)
from app.models.device import Device
from app.models.enums import AccountStatus, SessionStatus
from app.models.role import Role
from app.models.session import UserSession
from app.models.trust_score import TrustScore
from app.models.user import User
from app.schemas.admin import UserRow, UserUpdate
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/users", tags=["users"])


def _to_row(db: Session, user: User) -> UserRow:
    devices = int(
        db.scalar(select(func.count(Device.id)).where(Device.user_id == user.id)) or 0
    )
    sessions = int(
        db.scalar(
            select(func.count(UserSession.id)).where(
                UserSession.user_id == user.id,
                UserSession.status == SessionStatus.ACTIVE,
                UserSession.mfa_passed.is_(True),
            )
        ) or 0
    )
    latest = db.scalar(
        select(TrustScore)
        .where(TrustScore.user_id == user.id)
        .order_by(TrustScore.created_at.desc())
        .limit(1)
    )
    return UserRow(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        department=user.department,
        role=user.role.name,
        is_admin=user.role.is_admin,
        account_status=user.account_status.value,
        is_locked=user.is_locked,
        mfa_enabled=user.mfa_enabled,
        mfa_enrolled=user.mfa_secret is not None,
        last_login_at=user.last_login_at,
        failed_login_count=user.failed_login_count,
        home_city=user.home_city,
        home_country=user.home_country,
        device_count=devices,
        active_sessions=sessions,
        latest_trust_score=latest.score if latest else None,
        latest_risk_level=latest.risk_level.value if latest else None,
    )


@router.get("", response_model=list[UserRow], summary="All users")
def list_users(
    _: Principal = Depends(require_permission("users:read")),
    db: Session = Depends(get_db),
    q: str | None = Query(default=None, description="Search username, name or email"),
    role: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[UserRow]:
    stmt = select(User).join(Role).order_by(Role.name, User.username).limit(limit)
    if q:
        needle = f"%{q}%"
        stmt = stmt.where(
            or_(
                User.username.ilike(needle),
                User.full_name.ilike(needle),
                User.email.ilike(needle),
            )
        )
    if role:
        stmt = stmt.where(Role.name == role)
    return [_to_row(db, user) for user in db.scalars(stmt)]


@router.get("/roles", summary="Available roles")
def list_roles(
    _: Principal = Depends(require_permission("users:read")),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    return [
        {
            "name": role.name,
            "description": role.description,
            "is_admin": role.is_admin,
            "max_sensitivity_ordinal": role.max_sensitivity_ordinal,
            "permissions": role.permissions or [],
            "user_count": int(
                db.scalar(select(func.count(User.id)).where(User.role_id == role.id))
                or 0
            ),
        }
        for role in db.scalars(select(Role).order_by(Role.name))
    ]


@router.get("/{user_id}", response_model=UserRow, summary="One user")
def get_user(
    user_id: uuid.UUID,
    _: Principal = Depends(require_permission("users:read")),
    db: Session = Depends(get_db),
) -> UserRow:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return _to_row(db, user)


@router.patch("/{user_id}", response_model=UserRow, summary="Update a user")
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    principal: Principal = Depends(require_permission("users:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> UserRow:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")

    changes: dict[str, object] = {}

    if payload.role is not None:
        role = db.scalar(select(Role).where(Role.name == payload.role))
        if role is None:
            raise HTTPException(422, f"Unknown role '{payload.role}'.")
        if user.id == principal.user.id and not role.is_admin:
            # An administrator removing their own last privilege locks everyone
            # out of user management until someone edits the database by hand.
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "You cannot remove your own administrator role.",
            )
        changes["role"] = {"from": user.role.name, "to": role.name}
        user.role_id = role.id

    if payload.department is not None:
        changes["department"] = {"from": user.department, "to": payload.department}
        user.department = payload.department

    if payload.account_status is not None:
        new_status = AccountStatus(payload.account_status)
        if user.id == principal.user.id and new_status is not AccountStatus.ACTIVE:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "You cannot disable your own account."
            )
        changes["account_status"] = {
            "from": user.account_status.value, "to": new_status.value
        }
        user.account_status = new_status

    if payload.unlock:
        changes["unlock"] = {
            "failed_login_count": user.failed_login_count,
            "was_locked_until": (
                user.locked_until.isoformat() if user.locked_until else None
            ),
        }
        user.locked_until = None
        user.failed_login_count = 0
        if user.account_status is AccountStatus.LOCKED:
            user.account_status = AccountStatus.ACTIVE

    if not changes:
        raise HTTPException(422, "No changes supplied.")

    db.flush()
    if "role" in changes:
        # User.role is lazy="joined", so the old Role object is already attached.
        # Without expiring it the response would echo the previous role and the
        # UI would show the wrong value until the page was reloaded.
        db.expire(user, ["role"])
    AuditService.record(
        db, action="USER_UPDATED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="user",
        resource_id=str(user.id), ip_address=bundle.ip_address,
        payload={"username": user.username, "changes": changes},
    )
    return _to_row(db, user)
