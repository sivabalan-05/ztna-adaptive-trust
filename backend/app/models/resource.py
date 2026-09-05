"""Protected resources, each carrying a sensitivity and a trust floor."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean, Enum as SAEnum, ForeignKey, Integer, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import TZDateTime, TimestampMixin, uuid_pk
from app.models.enums import SENSITIVITY_MIN_TRUST, Sensitivity

if TYPE_CHECKING:
    from app.models.access_request import AccessRequest
    from app.models.policy import Policy


class Resource(Base, TimestampMixin):
    __tablename__ = "resources"

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="application", nullable=False)

    sensitivity: Mapped[Sensitivity] = mapped_column(
        SAEnum(Sensitivity, native_enum=False, length=16, name="sensitivity"),
        default=Sensitivity.INTERNAL,
        nullable=False,
        index=True,
    )

    #: Defaults to the sensitivity floor (0 / 60 / 75 / 90) but may be raised
    #: per resource by an administrator.
    min_trust_score: Mapped[int] = mapped_column(Integer, nullable=False)

    owner: Mapped[str] = mapped_column(String(96), default="", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # --- Attached content --------------------------------------------------
    # Nullable throughout: a resource may legitimately carry no file, and the
    # twelve seeded rows predate this feature.
    #: The uploader's filename, kept only as a display label.
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Server-generated name under the storage root. Never client-supplied.
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uploaded_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    access_requests: Mapped[list["AccessRequest"]] = relationship(back_populates="resource")
    policies: Mapped[list["Policy"]] = relationship(back_populates="resource")

    @staticmethod
    def default_min_trust(sensitivity: Sensitivity) -> int:
        return SENSITIVITY_MIN_TRUST[sensitivity]

    @property
    def has_file(self) -> bool:
        """Whether there is content to serve, as opposed to metadata only."""
        return bool(self.file_path)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Resource {self.slug} {self.sensitivity}>"
