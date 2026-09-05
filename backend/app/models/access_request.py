"""Every attempt to reach a protected resource, with its decision and features.

This table doubles as the labelled dataset for Isolation Forest training:
``features`` holds the exact feature vector that was scored, and
``is_anomalous`` carries the ground-truth label for the synthetic attack rows.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean, Enum as SAEnum, Float, ForeignKey, Integer, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import JSONColumn, TZDateTime, TimestampMixin, uuid_pk
from app.models.enums import AccessAction, RiskLevel

if TYPE_CHECKING:
    from app.models.resource import Resource
    from app.models.session import UserSession


class AccessRequest(Base, TimestampMixin):
    __tablename__ = "access_requests"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True, index=True
    )
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("resources.id", ondelete="SET NULL"), nullable=True, index=True
    )
    trust_score_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("trust_scores.id", ondelete="SET NULL"), nullable=True
    )

    requested_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(8), default="GET", nullable=False)
    path: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), default="", nullable=False)

    score_at_request: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(
        SAEnum(RiskLevel, native_enum=False, length=16, name="risk_level"),
        nullable=False,
        index=True,
    )
    decision: Mapped[AccessAction] = mapped_column(
        SAEnum(AccessAction, native_enum=False, length=20, name="access_action"),
        nullable=False,
        index=True,
    )
    granted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    matched_policy: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    #: The Isolation Forest feature vector for this event.
    features: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )
    #: Ground-truth label for model evaluation (True on seeded attack events).
    is_anomalous: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )
    #: Which scripted scenario produced this row, when synthetic.
    scenario: Mapped[str] = mapped_column(String(48), default="", nullable=False)

    session: Mapped["UserSession | None"] = relationship(back_populates="access_requests")
    resource: Mapped["Resource | None"] = relationship(back_populates="access_requests")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AccessRequest {self.path} {self.decision}>"
