"""Operational (non-security) logging, surfaced on the admin diagnostics page."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Enum as SAEnum, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import JSONColumn, TZDateTime, uuid_pk
from app.models.enums import LogLevel


class SystemLog(Base):
    __tablename__ = "system_logs"

    id: Mapped[uuid.UUID] = uuid_pk()
    created_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)
    level: Mapped[LogLevel] = mapped_column(
        SAEnum(LogLevel, native_enum=False, length=16, name="log_level"),
        nullable=False,
        index=True,
    )
    logger: Mapped[str] = mapped_column(String(96), default="app", nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SystemLog {self.level} {self.logger}>"
