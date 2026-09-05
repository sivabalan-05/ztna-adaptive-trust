"""Sessions — the unit that continuous verification re-scores every 30 seconds."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean, Enum as SAEnum, Float, ForeignKey, Integer, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import TZDateTime, TimestampMixin, uuid_pk
from app.models.enums import AccessAction, RiskLevel, SessionStatus

if TYPE_CHECKING:
    from app.models.access_request import AccessRequest
    from app.models.device import Device
    from app.models.trust_score import TrustScore
    from app.models.user import User


class UserSession(Base, TimestampMixin):
    """One authenticated session.  Table name is ``sessions``."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )

    #: JTI of the refresh token bound to this session; revoking the session
    #: adds this to the Redis denylist.
    refresh_jti: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    status: Mapped[SessionStatus] = mapped_column(
        SAEnum(SessionStatus, native_enum=False, length=16, name="session_status"),
        default=SessionStatus.ACTIVE,
        nullable=False,
        index=True,
    )

    # --- Network / location context at session start -----------------------
    ip_address: Mapped[str] = mapped_column(String(45), default="", nullable=False)
    asn: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    isp: Mapped[str] = mapped_column(String(96), default="", nullable=False)
    country: Mapped[str] = mapped_column(String(2), default="IN", nullable=False)
    city: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_datacenter: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ip_reputation: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # --- Lifecycle ---------------------------------------------------------
    started_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    revoked_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    # --- Current enforcement state (denormalised for the live dashboard) ---
    current_trust_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)
    current_risk_level: Mapped[RiskLevel] = mapped_column(
        SAEnum(RiskLevel, native_enum=False, length=16, name="risk_level"),
        default=RiskLevel.LOW,
        nullable=False,
        index=True,
    )
    current_action: Mapped[AccessAction] = mapped_column(
        SAEnum(AccessAction, native_enum=False, length=20, name="access_action"),
        default=AccessAction.ALLOW,
        nullable=False,
    )

    mfa_passed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    step_up_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # --- Activity counters used by the behaviour factor --------------------
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    distinct_resource_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    denied_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    user: Mapped["User"] = relationship(back_populates="sessions")
    device: Mapped["Device | None"] = relationship(back_populates="sessions")
    trust_scores: Mapped[list["TrustScore"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
        order_by="TrustScore.created_at",
    )
    access_requests: Mapped[list["AccessRequest"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )

    @property
    def is_active(self) -> bool:
        return self.status is SessionStatus.ACTIVE

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<UserSession {self.id} {self.status} score={self.current_trust_score:.0f}>"
