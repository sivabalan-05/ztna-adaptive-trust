"""Devices — fingerprint registry with trust-on-first-use plus admin approval."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean, Enum as SAEnum, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import TZDateTime, TimestampMixin, uuid_pk
from app.models.enums import DeviceStatus

if TYPE_CHECKING:
    from app.models.session import UserSession
    from app.models.user import User


class Device(Base, TimestampMixin):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("user_id", "fingerprint", name="uq_device_user_fingerprint"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    #: SHA-256 of user-agent + platform + screen + timezone + language + canvas
    #: hash, computed in the browser and sent as ``X-Device-Fingerprint``.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(96), default="", nullable=False)

    status: Mapped[DeviceStatus] = mapped_column(
        SAEnum(DeviceStatus, native_enum=False, length=16, name="device_status"),
        default=DeviceStatus.PENDING,
        nullable=False,
        index=True,
    )

    # --- Fingerprint components, kept for consistency checking -------------
    os: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    browser: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    platform: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    screen_resolution: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    device_timezone: Mapped[str] = mapped_column(String(48), default="", nullable=False)
    language: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, default="", nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)
    seen_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    approved_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    #: Set once the device has been seen enough times from consistent context.
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship(back_populates="devices", foreign_keys=[user_id])
    sessions: Mapped[list["UserSession"]] = relationship(back_populates="device")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Device {self.label or self.fingerprint[:12]} {self.status}>"
