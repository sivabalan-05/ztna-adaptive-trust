"""Every trust score ever computed, with its full explainable breakdown."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import Enum as SAEnum, Float, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import JSONColumn, TimestampMixin, uuid_pk
from app.models.enums import AccessAction, RiskLevel, ScoreTrigger

if TYPE_CHECKING:
    from app.models.session import UserSession


class TrustScore(Base, TimestampMixin):
    __tablename__ = "trust_scores"

    id: Mapped[uuid.UUID] = uuid_pk()
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    risk_level: Mapped[RiskLevel] = mapped_column(
        SAEnum(RiskLevel, native_enum=False, length=16, name="risk_level"),
        nullable=False,
        index=True,
    )
    action: Mapped[AccessAction] = mapped_column(
        SAEnum(AccessAction, native_enum=False, length=20, name="access_action"),
        nullable=False,
    )
    trigger: Mapped[ScoreTrigger] = mapped_column(
        SAEnum(ScoreTrigger, native_enum=False, length=20, name="score_trigger"),
        nullable=False,
        index=True,
    )

    #: Raw Isolation Forest output, normalised to 0-1 (1 = most anomalous).
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    #: The XAI payload: one entry per factor with raw signal, weight, points
    #: deducted and a plain-English reason.  Never a bare number.
    factors: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )

    #: One-line human summary of the dominant reason for this score.
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)

    session: Mapped["UserSession"] = relationship(back_populates="trust_scores")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<TrustScore {self.score:.1f} {self.risk_level} {self.trigger}>"
