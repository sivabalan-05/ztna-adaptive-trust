"""Zero Trust policies evaluated by the PDP alongside the trust score."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean, Enum as SAEnum, ForeignKey, Integer, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import JSONColumn, TimestampMixin, uuid_pk
from app.models.enums import PolicyEffect, Sensitivity

if TYPE_CHECKING:
    from app.models.resource import Resource
    from app.models.role import Role


class Policy(Base, TimestampMixin):
    """A single rule.  Highest ``priority`` wins; DENY beats ALLOW on a tie."""

    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # --- Match criteria (NULL means "any") ---------------------------------
    role_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), nullable=True, index=True
    )
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("resources.id", ondelete="CASCADE"), nullable=True, index=True
    )
    sensitivity: Mapped[Sensitivity | None] = mapped_column(
        SAEnum(Sensitivity, native_enum=False, length=16, name="sensitivity"),
        nullable=True,
    )

    # --- Conditions --------------------------------------------------------
    min_trust_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    require_known_device: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deny_vpn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    #: ISO-3166 alpha-2 codes; empty list means no country restriction.
    allowed_countries: Mapped[list[str]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )
    #: {"start_hour": 8, "end_hour": 20, "weekdays_only": true} or {}.
    time_window: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )

    effect: Mapped[PolicyEffect] = mapped_column(
        SAEnum(PolicyEffect, native_enum=False, length=8, name="policy_effect"),
        default=PolicyEffect.ALLOW,
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    role: Mapped["Role | None"] = relationship(back_populates="policies")
    resource: Mapped["Resource | None"] = relationship(back_populates="policies")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Policy {self.name} {self.effect} p{self.priority}>"
