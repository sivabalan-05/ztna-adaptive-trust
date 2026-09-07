"""Protected resource catalogue and the access enforcement endpoint."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import (
    APIRouter, Depends, File, HTTPException, Query, Response, UploadFile,
    status,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import profiling
from app.core import storage
from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_context_bundle, get_principal, require_permission,
)
from app.models.access_request import AccessRequest
from app.models.base import utcnow
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
logger = logging.getLogger(__name__)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _safe_disposition_filename(name: str | None) -> str:
    """Escape a stored display name for use in a ``Content-Disposition`` header.

    ``file_name`` is user-supplied at upload time. Naive interpolation would
    let a crafted name (an embedded quote or a control character) inject
    extra disposition parameters or split the header. Strip control
    characters and backslash-escape backslashes and quotes.
    """
    cleaned = _CONTROL_CHARS.sub("", name or "").replace("\\", "\\\\").replace(
        '"', '\\"'
    )
    return cleaned or "download"


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
                # Built from _to_out so every ResourceOut field (including
                # the file metadata) rides along automatically — a field
                # added to ResourceOut later cannot silently go missing here.
                **_to_out(resource).model_dump(),
                reachable=decision.granted,
                action=decision.action.value,
                reason=decision.reason,
                gate=decision.gate,
                required_score=decision.required_score,
                matched_policy=decision.matched_policy,
            )
        )
    return rows


@router.get(
    "/{slug}/content",
    summary="View or download — enforced on every single request",
    responses={
        403: {"description": "Refused by clearance, policy or trust"},
        404: {"description": "No such resource, or no file attached"},
    },
)
def resource_content(
    slug: str,
    principal: Principal = Depends(get_principal),
    bundle: ContextBundle = Depends(get_context_bundle),
    db: Session = Depends(get_db),
) -> Response:
    """Stream a resource's file, but only as the outcome of a live decision.

    This calls the same enforcement point as ``POST /{slug}/access``, so the
    session is re-scored against the context of *this* request and the
    decision is written to the access log and the audit chain before any byte
    leaves the server. There is no other route to the stored file.
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
        method="GET",
        path=f"/api/resources/{slug}/content",
    )

    if not decision.granted:
        # Commit before raising: the refusal, the score behind it and the
        # audit record must outlive the 403. This runs before the has_file
        # check below, so a caller the policy would refuse never learns
        # whether the resource even has a file attached.
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
            headers={
                "X-Access-Gate": decision.gate or "trust",
                "X-Trust-Score": f"{row.score_at_request:.1f}",
            },
        )

    if not resource.has_file:
        # Commit here too: the decision was granted and already counted
        # toward enumeration and the audit chain — that evidence must not
        # disappear just because this request happens to 404.
        db.commit()
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "This resource has no file attached."
        )

    try:
        data = storage.read(resource.file_path or "")
    except storage.StorageError as exc:
        # Commit first: the grant and its audit entry must outlive this 500.
        db.commit()
        logger.error(
            "Resource %s points at missing file %s", resource.slug, resource.file_path
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, exc.message
        ) from exc

    return Response(
        content=data,
        media_type=resource.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": (
                f'inline; filename="{_safe_disposition_filename(resource.file_name)}"'
            ),
            "X-Access-Gate": "granted",
            "X-Trust-Score": f"{row.score_at_request:.1f}",
        },
    )


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
            headers={
                "X-Access-Gate": decision.gate or "trust",
                "X-Trust-Score": f"{row.score_at_request:.1f}",
            },
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


@router.post(
    "/{slug}/file",
    response_model=ResourceOut,
    summary="Attach or replace this resource's file",
)
async def upload_resource_file(
    slug: str,
    file: UploadFile = File(...),
    principal: Principal = Depends(require_permission("resources:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> ResourceOut:
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")

    data = await file.read()
    try:
        stored_name = storage.save(data, file.content_type or "")
    except storage.StorageError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, exc.message
        ) from exc

    previous = resource.file_path
    resource.file_name = Path(file.filename or "file").name
    resource.file_path = stored_name
    resource.content_type = file.content_type
    resource.file_size = len(data)
    resource.uploaded_at = utcnow()
    resource.uploaded_by_id = principal.user.id
    db.flush()

    # Only once the row points at the new file is the old one removed, so a
    # failure above never leaves the row pointing at nothing.
    if previous and previous != stored_name:
        storage.delete(previous)

    AuditService.record(
        db, action="RESOURCE_FILE_UPLOADED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="resource",
        resource_id=str(resource.id), ip_address=bundle.ip_address,
        payload={"slug": resource.slug, "file_name": resource.file_name,
                 "content_type": resource.content_type, "bytes": resource.file_size},
    )
    return _to_out(resource)
