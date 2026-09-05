"""Shared column types and mixins for the ORM layer."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, JSON, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

#: JSONB on PostgreSQL (indexable, typed) and plain JSON on SQLite.
JSONColumn = JSON().with_variant(JSONB, "postgresql")

#: TIMESTAMPTZ on PostgreSQL; SQLite stores an ISO string and returns naive
#: datetimes, which ``utcnow`` below keeps consistent by always using UTC.
TZDateTime = DateTime(timezone=True)


def utcnow() -> datetime:
    """Timezone-aware current UTC time (never ``datetime.utcnow``)."""
    return datetime.now(timezone.utc)


def as_aware(value: datetime | None) -> datetime | None:
    """Attach UTC to a naive datetime.

    PostgreSQL round-trips TIMESTAMPTZ as timezone-aware, SQLite returns naive
    values.  Everything the app writes is UTC, so tagging naive reads as UTC
    keeps comparisons and arithmetic correct on both dialects.
    """
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid(as_uuid=True), primary_key=True, default=new_uuid)


class TimestampMixin:
    """``created_at`` / ``updated_at`` maintained by the ORM."""

    created_at: Mapped[datetime] = mapped_column(
        TZDateTime, default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        TZDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


def as_dict(obj: Any) -> dict[str, Any]:
    """Plain-dict view of a model, used by the audit logger and the API."""
    return {
        column.name: getattr(obj, column.name)
        for column in obj.__table__.columns
    }
