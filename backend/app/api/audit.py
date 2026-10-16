"""Chain-of-trust audit log: search, verify, export.

The chain is only tamper-*evident* if someone can actually check it. These
endpoints are that check: `/verify` walks every record, recomputes each hash
from the record's own contents, and names the first position where the
recomputation disagrees.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import Principal, require_permission
from app.external import geoip
from app.models.audit_log import GENESIS_HASH, AuditLog
from app.models.base import utcnow
from app.models.session import UserSession
from app.schemas.audit import (
    AuditPage, AuditRecordOut, AuditStats, ChainVerification,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/audit", tags=["audit"])

EXPORT_MAX_ROWS = 50_000

CSV_COLUMNS = [
    "seq", "timestamp", "actor_label", "action", "resource_type",
    "resource_id", "ip_address", "payload", "payload_hash", "prev_hash",
    "record_hash", "note",
]


def _csv_line(values: list[Any]) -> str:
    """One properly quoted CSV line.

    A fresh buffer per line keeps the generator stateless, which matters when
    the response is streamed and the caller may disconnect mid-export.
    """
    buffer = io.StringIO()
    csv.writer(buffer).writerow(values)
    return buffer.getvalue()


def _place(city: object, country: object) -> str:
    return ", ".join(str(part) for part in (city, country) if part)


def _location_from_payload(payload: dict[str, Any]) -> str:
    """City and country recorded inside the event itself, if it has any."""
    place = _place(payload.get("city"), payload.get("country"))
    if place:
        return place
    network = payload.get("network")
    if isinstance(network, dict):
        return _place(network.get("city"), network.get("country"))
    return ""


def _session_id(record: AuditLog) -> uuid.UUID | None:
    payload = record.payload or {}
    raw = payload.get("session_id") or (
        record.resource_id if record.resource_type == "session" else ""
    )
    try:
        return uuid.UUID(str(raw)) if raw else None
    except ValueError:
        return None


def _label_locations(db: Session, rows: list[AuditLog]) -> dict[int, str]:
    """Where each record came from, keyed by chain position.

    A request from the server's own network is labelled as such. Otherwise, in
    order of preference: the event's own payload, the login session it belongs
    to (which stored its city and country when the user signed in), and a
    local-only lookup of the address. Nothing here makes a network call, so the
    page stays fast however many distinct addresses it holds.
    """
    wanted = {sid for r in rows if (sid := _session_id(r)) is not None}
    session_places: dict[uuid.UUID, str] = {}
    if wanted:
        # A session opened from the server's own network stores a placeholder
        # city, so say what it really was instead of repeating the placeholder.
        session_places = {
            s.id: (
                "Local network"
                if s.ip_address and geoip.lookup_local(s.ip_address).is_private
                else _place(s.city, s.country)
            )
            for s in db.scalars(select(UserSession).where(UserSession.id.in_(wanted)))
        }

    labels: dict[int, str] = {}
    for record in rows:
        geo = geoip.lookup_local(record.ip_address) if record.ip_address else None
        if geo is not None and geo.is_private:
            labels[record.seq] = "Local network"
            continue
        sid = _session_id(record)
        label = _location_from_payload(record.payload or {}) or (
            session_places.get(sid, "") if sid else ""
        )
        if not label and geo is not None and geo.resolved:
            label = geo.label
        labels[record.seq] = label
    return labels


def _filtered(
    *,
    action: str | None,
    actor: str | None,
    resource_type: str | None,
    ip: str | None,
    since: datetime | None,
    until: datetime | None,
    q: str | None,
):
    """The WHERE clause shared by search, count and export."""
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor_label.ilike(f"%{actor}%"))
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if ip:
        stmt = stmt.where(AuditLog.ip_address == ip)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since)
    if until:
        stmt = stmt.where(AuditLog.timestamp <= until)
    if q:
        needle = f"%{q}%"
        stmt = stmt.where(
            or_(
                AuditLog.action.ilike(needle),
                AuditLog.actor_label.ilike(needle),
                AuditLog.resource_id.ilike(needle),
                AuditLog.ip_address.ilike(needle),
                AuditLog.note.ilike(needle),
            )
        )
    return stmt


@router.get("", response_model=AuditPage, summary="Search the audit log")
def search(
    _: Principal = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
    action: str | None = Query(default=None, description="Exact action, e.g. LOGIN_SUCCESS"),
    actor: str | None = Query(default=None, description="Substring of the actor label"),
    resource_type: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    q: str | None = Query(default=None, description="Free text across action, actor, resource, note"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AuditPage:
    """Newest first. Chain position (`seq`) is returned so a reader can point at
    an exact record when reporting a break."""
    base = _filtered(
        action=action, actor=actor, resource_type=resource_type, ip=ip,
        since=since, until=until, q=q,
    )
    total = int(db.scalar(select(func.count()).select_from(base.subquery())) or 0)
    rows = db.scalars(
        base.order_by(AuditLog.seq.desc()).limit(limit).offset(offset)
    ).all()
    labels = _label_locations(db, list(rows))
    records: list[AuditRecordOut] = []
    for row in rows:
        record = AuditRecordOut.model_validate(row, from_attributes=True)
        record.location = labels.get(row.seq, "")
        records.append(record)
    return AuditPage(total=total, limit=limit, offset=offset, records=records)


@router.get(
    "/verify",
    response_model=ChainVerification,
    summary="Verify the hash chain end to end",
)
def verify(
    _: Principal = Depends(require_permission("audit:verify")),
    db: Session = Depends(get_db),
    from_seq: int | None = Query(
        default=None, ge=1,
        description="Verify only from this position, anchored on the record before it",
    ),
) -> ChainVerification:
    """Recompute every record's hash from its own contents and re-link the chain.

    A `valid: false` result names the exact position where recomputation first
    disagreed. Altering, inserting or deleting any historical record breaks
    every hash after it, so the first break is where tampering began.
    """
    result = AuditService.verify(db, from_seq=from_seq)
    return ChainVerification(**result, genesis_hash=GENESIS_HASH, checked_at=utcnow())


@router.get("/stats", response_model=AuditStats, summary="Audit log summary")
def stats(
    _: Principal = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> AuditStats:
    total = int(db.scalar(select(func.count()).select_from(AuditLog)) or 0)
    head = db.scalar(select(AuditLog).order_by(AuditLog.seq.desc()).limit(1))
    first = db.scalar(select(AuditLog).order_by(AuditLog.seq).limit(1))

    actions = {
        name: int(count)
        for name, count in db.execute(
            select(AuditLog.action, func.count())
            .group_by(AuditLog.action)
            .order_by(func.count().desc())
        ).all()
    }
    actors = {
        name: int(count)
        for name, count in db.execute(
            select(AuditLog.actor_label, func.count())
            .group_by(AuditLog.actor_label)
            .order_by(func.count().desc())
            .limit(15)
        ).all()
    }
    return AuditStats(
        total_records=total,
        first_record_at=first.timestamp if first else None,
        last_record_at=head.timestamp if head else None,
        head_hash=head.record_hash if head else GENESIS_HASH,
        actions=actions,
        top_actors=actors,
    )


@router.get(
    "/export.csv",
    summary="Export the filtered audit log as CSV",
    response_class=StreamingResponse,
)
def export_csv(
    _: Principal = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
    action: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    q: str | None = Query(default=None),
) -> StreamingResponse:
    """Streamed row by row, so exporting the whole chain never buffers it.

    The hashes are included: an export is only useful as evidence if the
    recipient can re-verify the chain from the file itself.
    """
    base = _filtered(
        action=action, actor=actor, resource_type=resource_type, ip=ip,
        since=since, until=until, q=q,
    ).order_by(AuditLog.seq).limit(EXPORT_MAX_ROWS)

    def rows() -> Iterator[str]:
        yield _csv_line(CSV_COLUMNS)
        for record in db.scalars(base).yield_per(500):
            yield _csv_line(
                [
                    record.seq,
                    record.timestamp.isoformat(),
                    record.actor_label,
                    record.action,
                    record.resource_type,
                    record.resource_id,
                    record.ip_address,
                    json.dumps(record.payload, sort_keys=True, separators=(",", ":")),
                    record.payload_hash,
                    record.prev_hash,
                    record.record_hash,
                    record.note,
                ]
            )

    filename = f"ztna-audit-{utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        rows(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/{seq}", response_model=AuditRecordOut, summary="One record by chain position"
)
def get_record(
    seq: int,
    _: Principal = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> AuditLog:
    record = db.scalar(select(AuditLog).where(AuditLog.seq == seq))
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No record at position {seq}.")
    return record
