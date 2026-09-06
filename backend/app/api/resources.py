"""Protected resource catalogue and the access enforcement endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import profiling
from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_context_bundle, get_principal, require_permission,
)
from app.models.access_request import AccessRequest
from app.models.enums import ScoreTrigger, Sensitivity
from app.models.resource import Resource
from app.schemas.access import (
    AccessDecisionOut, AccessRequestOut, ResourceCreate, ResourceOut,
    ResourceReachability, ResourceUpdate,
)
from app.services.access_service import AccessService
from app.services.audit_service import AuditService
from app.services.policy_engine import PolicyEngine
from app.services.trust_service import TrustService

router = APIRouter(prefix="/api/resources", tags=["resources"])


@router.get(
    "",
    response_model=list[ResourceReachability],
    summary="The catalogue, annotated with what this session can currently reach",
)
def catalogue(
    principal: Principal = Depends(get_principal),
    bundle: ContextBundle = Depends(get_context_bundle),
    db: Session = Depends(get_db),
    sensitivity: Sensitivity | None = Query(default=None),
    include_disabled: bool = Query(
        default=False,
        description="Administrators only: also list disabled resources",
    ),
) -> list[ResourceReachability]:
    """Evaluate every resource against the caller's live trust score.

    Reachability is computed, not stored: the same catalogue returns different
    answers for the same user from a different device, network or hour.
    """
    assessment, _ = TrustService.evaluate(
        db,
        user=principal.user,
        session=principal.session,
        bundle=bundle,
        trigger=ScoreTrigger.PERIODIC,
        device=principal.device,
    )
    signals = profiling.build_signals(
        db, user=principal.user, session=principal.session, bundle=bundle,
        device=principal.device,
    )
    device_known = signals.is_known_device and signals.device_approved

    # A caller without resources:write must never see disabled resources,
    # whatever they pass — the flag alone is never trusted.
    show_disabled = include_disabled and principal.has_permission("resources:write")

    rows: list[ResourceReachability] = []
    for resource, decision in PolicyEngine.reachable(
        db,
        user=principal.user,
        session=principal.session,
        score=assessment.score,
        risk=assessment.risk_level,
        bundle=bundle,
        device_known=device_known,
    ):
        if sensitivity is not None and resource.sensitivity is not sensitivity:
            continue
        if not resource.enabled and not show_disabled:
            continue
        rows.append(
            ResourceReachability(
                id=resource.id,
                slug=resource.slug,
                name=resource.name,
                description=resource.description,
                category=resource.category,
                sensitivity=resource.sensitivity.value,
                min_trust_score=resource.min_trust_score,
                owner=resource.owner,
                enabled=resource.enabled,
                reachable=decision.granted,
                action=decision.action.value,
                reason=decision.reason,
                gate=decision.gate,
                required_score=decision.required_score,
                matched_policy=decision.matched_policy,
            )
        )
    return rows


@router.get("/{slug}", response_model=ResourceOut, summary="One resource")
def get_resource(
    slug: str,
    _: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> Resource:
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")
    return resource


def _to_out(resource: Resource) -> ResourceOut:
    return ResourceOut(
        id=resource.id,
        slug=resource.slug,
        name=resource.name,
        description=resource.description,
        category=resource.category,
        sensitivity=resource.sensitivity.value,
        min_trust_score=resource.min_trust_score,
        owner=resource.owner,
        enabled=resource.enabled,
        has_file=resource.has_file,
        file_name=resource.file_name,
        content_type=resource.content_type,
        file_size=resource.file_size,
    )


@router.post(
    "",
    response_model=ResourceOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a resource (administrators only)",
)
def create_resource(
    payload: ResourceCreate,
    principal: Principal = Depends(require_permission("resources:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> ResourceOut:
    clash = db.scalar(select(Resource).where(Resource.slug == payload.slug))
    if clash is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Slug '{payload.slug}' is already in use."
        )

    sensitivity = Sensitivity(payload.sensitivity)
    resource = Resource(
        slug=payload.slug,
        name=payload.name,
        description=payload.description,
        category=payload.category,
        sensitivity=sensitivity,
        min_trust_score=(
            payload.min_trust_score
            if payload.min_trust_score is not None
            else Resource.default_min_trust(sensitivity)
        ),
        owner=payload.owner,
    )
    db.add(resource)
    db.flush()

    AuditService.record(
        db, action="RESOURCE_CREATED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="resource",
        resource_id=str(resource.id), ip_address=bundle.ip_address,
        payload={"slug": resource.slug, "sensitivity": sensitivity.value,
                 "min_trust_score": resource.min_trust_score},
    )
    return _to_out(resource)


@router.patch(
    "/{slug}", response_model=ResourceOut, summary="Edit a resource"
)
def update_resource(
    slug: str,
    payload: ResourceUpdate,
    principal: Principal = Depends(require_permission("resources:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> ResourceOut:
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")

    changes: dict[str, object] = {}
    for field in ("name", "description", "category", "owner",
                  "min_trust_score", "enabled"):
        value = getattr(payload, field)
        if value is not None and value != getattr(resource, field):
            changes[field] = {"from": getattr(resource, field), "to": value}
            setattr(resource, field, value)

    if payload.sensitivity is not None:
        sensitivity = Sensitivity(payload.sensitivity)
        if sensitivity is not resource.sensitivity:
            changes["sensitivity"] = {
                "from": resource.sensitivity.value, "to": sensitivity.value
            }
            resource.sensitivity = sensitivity

    if not changes:
        raise HTTPException(422, "No changes supplied.")

    db.flush()
    AuditService.record(
        db, action="RESOURCE_UPDATED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="resource",
        resource_id=str(resource.id), ip_address=bundle.ip_address,
        payload={"slug": resource.slug, "changes": changes},
    )
    return _to_out(resource)


@router.delete(
    "/{slug}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable a resource",
)
def disable_resource(
    slug: str,
    principal: Principal = Depends(require_permission("resources:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> Response:
    """Disables rather than deletes: access history references this row, and
    the audit trail has to stay whole."""
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")

    resource.enabled = False
    AuditService.record(
        db, action="RESOURCE_DISABLED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="resource",
        resource_id=str(resource.id), ip_address=bundle.ip_address,
        payload={"slug": resource.slug},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{slug}/access",
    response_model=AccessDecisionOut,
    summary="Request access — the policy enforcement point",
    responses={
        403: {"description": "Refused by clearance, policy or trust"},
        404: {"description": "No such resource"},
    },
)
def request_access(
    slug: str,
    principal: Principal = Depends(get_principal),
    bundle: ContextBundle = Depends(get_context_bundle),
    db: Session = Depends(get_db),
) -> AccessDecisionOut:
    """Re-score the session, apply policy, record the attempt and enforce.

    Returns 200 with ``granted: true`` when access is allowed and 403 with the
    full reasoning when it is not — a refusal always says which of the three
    gates stopped it and what would have to change.
    """
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")

    decision, row = AccessService.request_access(
        db,
        user=principal.user,
        session=principal.session,
        resource=resource,
        bundle=bundle,
        device=principal.device,
    )

    payload = AccessDecisionOut(
        resource=resource.slug,
        sensitivity=resource.sensitivity.value,
        granted=decision.granted,
        action=decision.action.value,
        reason=decision.reason,
        gate=decision.gate,
        matched_policy=decision.matched_policy,
        required_score=decision.required_score,
        trust_score=row.score_at_request,
        risk_level=row.risk_level.value,
        latency_ms=row.latency_ms,
        policies_evaluated=[e.to_dict() for e in decision.evaluations],
    )

    if not decision.granted:
        # Commit first: the denial, the score behind it and the audit record
        # must survive the 403, or the evidence disappears with the refusal.
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
            headers={"X-Access-Gate": decision.gate or "trust"},
        )
    return payload


@router.get(
    "/access/history",
    response_model=list[AccessRequestOut],
    summary="The caller's recent access attempts",
)
def my_access_history(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[AccessRequestOut]:
    rows = db.scalars(
        select(AccessRequest)
        .where(AccessRequest.user_id == principal.user.id)
        .order_by(AccessRequest.requested_at.desc())
        .limit(limit)
    ).all()
    return [
        AccessRequestOut(
            id=r.id,
            requested_at=r.requested_at,
            resource=r.resource.slug if r.resource else None,
            path=r.path,
            score_at_request=r.score_at_request,
            risk_level=r.risk_level.value,
            decision=r.decision.value,
            granted=r.granted,
            reason=r.reason,
            matched_policy=r.matched_policy,
            latency_ms=r.latency_ms,
        )
        for r in rows
    ]
