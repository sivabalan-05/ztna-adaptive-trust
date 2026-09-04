"""Device registry: list your own devices, approve or revoke as an administrator."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_principal, get_request_context, require_permission,
)
from app.models.device import Device
from app.models.enums import DeviceStatus
from app.schemas.auth import DeviceOut
from app.services.audit_service import AuditService
from app.services.auth_service import RequestContext
from app.services.device_service import DeviceService

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/me", response_model=list[DeviceOut], summary="Your registered devices")
def my_devices(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> list[Device]:
    return list(
        db.scalars(
            select(Device)
            .where(Device.user_id == principal.user.id)
            .order_by(Device.last_seen_at.desc())
        )
    )


@router.get("", response_model=list[DeviceOut], summary="All devices (analysts, admins)")
def list_devices(
    principal: Principal = Depends(require_permission("devices:read")),
    db: Session = Depends(get_db),
    device_status: DeviceStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[Device]:
    stmt = select(Device).order_by(Device.last_seen_at.desc()).limit(limit)
    if device_status is not None:
        stmt = stmt.where(Device.status == device_status)
    return list(db.scalars(stmt))


@router.post(
    "/{device_id}/approve",
    response_model=DeviceOut,
    summary="Approve a pending device",
)
def approve_device(
    device_id: uuid.UUID,
    principal: Principal = Depends(require_permission("devices:approve")),
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found.")

    DeviceService.approve(db, device, principal.user)
    AuditService.record(
        db, action="DEVICE_APPROVED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="device",
        resource_id=str(device.id), ip_address=context.ip_address,
        payload={
            "device_label": device.label, "owner_id": str(device.user_id),
            "fingerprint": device.fingerprint[:16] + "...",
        },
    )
    return device


@router.post(
    "/{device_id}/revoke",
    response_model=DeviceOut,
    summary="Revoke a device",
)
def revoke_device(
    device_id: uuid.UUID,
    principal: Principal = Depends(require_permission("devices:revoke")),
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found.")

    DeviceService.revoke(db, device)
    AuditService.record(
        db, action="DEVICE_REVOKED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="device",
        resource_id=str(device.id), ip_address=context.ip_address,
        payload={"device_label": device.label, "owner_id": str(device.user_id)},
    )
    return device
