"""Policy administration."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_context_bundle, require_permission,
)
from app.models.enums import PolicyEffect, Sensitivity
from app.models.policy import Policy
from app.models.resource import Resource
from app.models.role import Role
from app.schemas.access import PolicyCreate, PolicyOut, PolicyUpdate
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/policies", tags=["policies"])


def _to_out(db: Session, policy: Policy) -> PolicyOut:
    role = db.get(Role, policy.role_id) if policy.role_id else None
    resource = db.get(Resource, policy.resource_id) if policy.resource_id else None
    return PolicyOut(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        role=role.name if role else None,
        resource=resource.slug if resource else None,
        sensitivity=policy.sensitivity.value if policy.sensitivity else None,
        min_trust_score=policy.min_trust_score,
        require_mfa=policy.require_mfa,
        require_known_device=policy.require_known_device,
        deny_vpn=policy.deny_vpn,
        allowed_countries=policy.allowed_countries or [],
        time_window=policy.time_window or {},
        effect=policy.effect.value,
        priority=policy.priority,
        enabled=policy.enabled,
    )


@router.get("", response_model=list[PolicyOut], summary="All policies, highest priority first")
def list_policies(
    _: Principal = Depends(require_permission("policies:read")),
    db: Session = Depends(get_db),
) -> list[PolicyOut]:
    rows = db.scalars(select(Policy).order_by(Policy.priority.desc(), Policy.name)).all()
    return [_to_out(db, p) for p in rows]


@router.post(
    "",
    response_model=PolicyOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a policy",
)
def create_policy(
    payload: PolicyCreate,
    principal: Principal = Depends(require_permission("policies:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> PolicyOut:
    if db.scalar(select(Policy).where(Policy.name == payload.name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "A policy with that name exists.")

    role = None
    if payload.role:
        role = db.scalar(select(Role).where(Role.name == payload.role))
        if role is None:
            raise HTTPException(422, f"Unknown role '{payload.role}'.")

    resource = None
    if payload.resource:
        resource = db.scalar(select(Resource).where(Resource.slug == payload.resource))
        if resource is None:
            raise HTTPException(422, f"Unknown resource '{payload.resource}'.")

    sensitivity = None
    if payload.sensitivity:
        try:
            sensitivity = Sensitivity(payload.sensitivity)
        except ValueError:
            raise HTTPException(422, f"Unknown sensitivity '{payload.sensitivity}'.") from None

    policy = Policy(
        name=payload.name,
        description=payload.description,
        role_id=role.id if role else None,
        resource_id=resource.id if resource else None,
        sensitivity=sensitivity,
        min_trust_score=payload.min_trust_score,
        require_mfa=payload.require_mfa,
        require_known_device=payload.require_known_device,
        deny_vpn=payload.deny_vpn,
        allowed_countries=payload.allowed_countries,
        time_window=payload.time_window,
        effect=PolicyEffect(payload.effect),
        priority=payload.priority,
        enabled=payload.enabled,
    )
    db.add(policy)
    db.flush()

    AuditService.record(
        db, action="POLICY_CREATED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="policy",
        resource_id=str(policy.id), ip_address=bundle.ip_address,
        payload={
            "name": policy.name, "effect": policy.effect.value,
            "priority": policy.priority, "min_trust_score": policy.min_trust_score,
        },
    )
    return _to_out(db, policy)


@router.patch("/{policy_id}", response_model=PolicyOut, summary="Update a policy")
def update_policy(
    policy_id: uuid.UUID,
    payload: PolicyUpdate,
    principal: Principal = Depends(require_permission("policies:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> PolicyOut:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found.")

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(policy, field, value)
    db.flush()

    AuditService.record(
        db, action="POLICY_UPDATED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="policy",
        resource_id=str(policy.id), ip_address=bundle.ip_address,
        payload={"name": policy.name, "changes": changes},
    )
    return _to_out(db, policy)


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a policy",
)
def delete_policy(
    policy_id: uuid.UUID,
    principal: Principal = Depends(require_permission("policies:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> Response:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found.")

    name = policy.name
    AuditService.record(
        db, action="POLICY_DELETED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="policy",
        resource_id=str(policy.id), ip_address=bundle.ip_address,
        payload={"name": name, "effect": policy.effect.value},
    )
    db.delete(policy)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
