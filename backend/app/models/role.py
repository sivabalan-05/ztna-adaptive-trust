"""Roles — the least-privilege half of every access decision."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import JSONColumn, TimestampMixin, uuid_pk

if TYPE_CHECKING:
    from app.models.policy import Policy
    from app.models.user import User


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    #: Administrative roles may manage users, devices, policies and sessions.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    #: Highest resource sensitivity this role may ever reach, as an ordinal
    #: 0=PUBLIC .. 3=RESTRICTED.  The policy engine treats this as a hard cap.
    max_sensitivity_ordinal: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    #: Free-form capability strings, e.g. ["users:read", "sessions:revoke"].
    permissions: Mapped[list[str]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )

    users: Mapped[list["User"]] = relationship(back_populates="role")
    policies: Mapped[list["Policy"]] = relationship(back_populates="role")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Role {self.name}>"
