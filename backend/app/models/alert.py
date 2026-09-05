"""Security alerts raised by the scoring and policy engines."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Enum as SAEnum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import JSONColumn, TZDateTime, TimestampMixin, uuid_pk
from app.models.enums import AlertSeverity, AlertStatus

if TYPE_CHECKING:
    from app.models.user import User


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )

    severity: Mapped[AlertSeverity] = mapped_column(
        SAEnum(AlertSeverity, native_enum=False, length=16, name="alert_severity"),
        nullable=False,
        index=True,
    )
    status: Mapped[AlertStatus] = mapped_column(
        SAEnum(AlertStatus, native_enum=False, length=16, name="alert_status"),
        default=AlertStatus.OPEN,
        nullable=False,
        index=True,
    )

    #: Machine-readable family, e.g. "impossible_travel", "brute_force".
    category: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    trust_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    #: Supporting signals, so an analyst can justify the alert after the fact.
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )

    acknowledged_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolution_note: Mapped[str] = mapped_column(Text, default="", nullable=False)

    user: Mapped["User | None"] = relationship(
        back_populates="alerts", foreign_keys=[user_id]
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Alert {self.severity} {self.category} {self.status}>"
