"""Users — identity, MFA enrolment, lockout state and home location."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Enum as SAEnum, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import TZDateTime, TimestampMixin, as_aware, uuid_pk
from app.models.enums import AccountStatus

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.behavior_profile import BehaviorProfile
    from app.models.device import Device
    from app.models.role import Role
    from app.models.session import UserSession


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    department: Mapped[str] = mapped_column(String(64), default="", nullable=False)

    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    password_changed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    #: Coarse strength estimate (0-100) recorded at set-password time; feeds the
    #: identity trust factor without ever storing the password itself.
    password_strength: Mapped[int] = mapped_column(Integer, default=60, nullable=False)

    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    account_status: Mapped[AccountStatus] = mapped_column(
        SAEnum(AccountStatus, native_enum=False, length=16, name="account_status"),
        default=AccountStatus.ACTIVE,
        nullable=False,
        index=True,
    )

    # --- MFA ---------------------------------------------------------------
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_confirmed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    # --- Lockout / failure tracking ---------------------------------------
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_failed_login_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    # --- Home location (baseline for the location trust factor) ------------
    home_city: Mapped[str] = mapped_column(String(64), default="Coimbatore", nullable=False)
    home_country: Mapped[str] = mapped_column(String(2), default="IN", nullable=False)
    home_latitude: Mapped[float] = mapped_column(Float, default=11.0168, nullable=False)
    home_longitude: Mapped[float] = mapped_column(Float, default=76.9558, nullable=False)
    timezone: Mapped[str] = mapped_column(String(48), default="Asia/Kolkata", nullable=False)

    role: Mapped["Role"] = relationship(back_populates="users", lazy="joined")
    # Device has two FKs to users (owner and approver), so the join is explicit.
    devices: Mapped[list["Device"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="Device.user_id",
    )
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="user", cascade="all, delete-orphan",
        foreign_keys="Alert.user_id",
    )
    behavior_profile: Mapped["BehaviorProfile | None"] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )

    @property
    def is_locked(self) -> bool:
        from app.models.base import utcnow

        if self.account_status is AccountStatus.LOCKED:
            return True
        locked_until = as_aware(self.locked_until)
        return locked_until is not None and locked_until > utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User {self.username}>"
