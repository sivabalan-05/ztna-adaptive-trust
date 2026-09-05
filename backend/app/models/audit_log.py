"""Chain-of-trust audit log.

Each row commits to its predecessor:

    record_hash = SHA256(prev_hash + timestamp + actor + action + payload_hash)

Altering or deleting any historical row breaks every hash after it, which is
exactly what ``GET /api/audit/verify`` detects.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import JSONColumn, TZDateTime, uuid_pk

#: prev_hash of the very first record.
GENESIS_HASH = "0" * 64


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = uuid_pk()

    #: Monotonic chain position; row N commits to row N-1.  Assigned explicitly
    #: by the audit service under a write lock rather than by a database
    #: sequence, so that seq order and hash order can never disagree.
    seq: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        unique=True,
        nullable=False,
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: Denormalised actor label, preserved even if the user row is deleted.
    actor_label: Mapped[str] = mapped_column(String(96), default="system", nullable=False)

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(48), default="", nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), default="", nullable=False)

    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )

    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    note: Mapped[str] = mapped_column(Text, default="", nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditLog #{self.seq} {self.action} {self.record_hash[:12]}>"
