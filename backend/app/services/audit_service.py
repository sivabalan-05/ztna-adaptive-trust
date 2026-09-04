"""Chain-of-trust audit writer.

Appends tamper-evident records:

    record_hash = SHA256(prev_hash + timestamp + actor + action + payload_hash)

``seq`` is assigned by this service rather than by a database sequence, under a
row lock on PostgreSQL, so that chain order and hash order can never disagree.
The verification endpoint that walks the chain arrives in Phase 7; the writer
lives here because Phase 2 already produces security events worth recording.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.base import utcnow
from app.services.hash_chain import GENESIS_HASH, compute_record_hash, hash_payload

logger = logging.getLogger(__name__)


class AuditService:
    """Every security-relevant event goes through ``record``."""

    @staticmethod
    def _tail(db: Session) -> AuditLog | None:
        stmt = select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)
        # SQLite serialises writers already; PostgreSQL needs the row lock so
        # two concurrent appends cannot claim the same prev_hash.
        if db.get_bind().dialect.name == "postgresql":
            stmt = stmt.with_for_update()
        return db.execute(stmt).scalar_one_or_none()

    @classmethod
    def record(
        cls,
        db: Session,
        *,
        action: str,
        payload: dict[str, Any],
        actor_id: uuid.UUID | None = None,
        actor_label: str = "system",
        resource_type: str = "",
        resource_id: str = "",
        ip_address: str = "",
        note: str = "",
        timestamp: datetime | None = None,
    ) -> AuditLog:
        """Append one hash-linked record and return it (not yet committed)."""
        tail = cls._tail(db)
        prev_hash = tail.record_hash if tail else GENESIS_HASH
        seq = (tail.seq + 1) if tail else 1
        ts = timestamp or utcnow()

        payload_hash = hash_payload(payload)
        record = AuditLog(
            seq=seq,
            timestamp=ts,
            actor_id=actor_id,
            actor_label=actor_label,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            payload=payload,
            payload_hash=payload_hash,
            prev_hash=prev_hash,
            record_hash=compute_record_hash(
                prev_hash, ts, actor_label, action, payload_hash
            ),
            note=note,
        )
        db.add(record)
        db.flush()
        logger.debug("Audit #%s %s by %s", seq, action, actor_label)
        return record

    @staticmethod
    def verify(
        db: Session, *, from_seq: int | None = None, chunk_size: int = 2000
    ) -> dict[str, Any]:
        """Walk the chain and report the first break, if any.

        Streamed in chunks rather than loaded whole: a chain that outgrows
        memory would become unverifiable, and a chain nobody can afford to
        verify is not tamper-evident in any useful sense.

        ``from_seq`` verifies a suffix, anchored on the preceding record's
        stored hash. That proves nothing about the records before it, and the
        result says so explicitly rather than implying a full check.
        """
        started = time.perf_counter()

        if from_seq is not None and from_seq > 1:
            anchor = db.scalar(
                select(AuditLog).where(AuditLog.seq == from_seq - 1)
            )
            if anchor is None:
                return {
                    "valid": False, "records_checked": 0, "broken_at": from_seq,
                    "reason": f"no record at seq {from_seq - 1} to anchor from",
                    "head_hash": GENESIS_HASH, "partial": True,
                    "verified_from": from_seq, "duration_ms": 0.0,
                }
            prev = anchor.record_hash
        else:
            from_seq = 1
            prev = GENESIS_HASH

        checked = 0
        last_seq = from_seq - 1

        while True:
            batch = list(
                db.scalars(
                    select(AuditLog)
                    .where(AuditLog.seq > last_seq)
                    .order_by(AuditLog.seq)
                    .limit(chunk_size)
                )
            )
            if not batch:
                break

            for record in batch:
                checked += 1
                last_seq = record.seq
                if record.prev_hash != prev:
                    reason = (
                        "prev_hash does not match the previous record; a record "
                        "was altered, inserted or removed"
                    )
                elif hash_payload(record.payload) != record.payload_hash:
                    reason = "payload no longer matches its stored hash"
                elif compute_record_hash(
                    record.prev_hash, record.timestamp, record.actor_label,
                    record.action, record.payload_hash,
                ) != record.record_hash:
                    reason = "record hash does not match the record's own contents"
                else:
                    prev = record.record_hash
                    continue

                return {
                    "valid": False,
                    "records_checked": checked,
                    "broken_at": record.seq,
                    "reason": reason,
                    "head_hash": prev,
                    "partial": from_seq > 1,
                    "verified_from": from_seq,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                }

        return {
            "valid": True,
            "records_checked": checked,
            "broken_at": None,
            "reason": None,
            "head_hash": prev,
            "partial": from_seq > 1,
            "verified_from": from_seq,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }
