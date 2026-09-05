"""Rolling per-user behaviour baseline.

Login hours are stored as the circular mean (sin/cos components) so that a
user who habitually signs in at 23:00 and 01:00 gets a baseline near midnight
rather than near noon.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import JSONColumn, TZDateTime, TimestampMixin, uuid_pk

if TYPE_CHECKING:
    from app.models.user import User


class BehaviorProfile(Base, TimestampMixin):
    __tablename__ = "behavior_profiles"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    # --- Temporal baseline -------------------------------------------------
    login_hour_sin: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    login_hour_cos: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    #: Concentration of the circular distribution, 0 (uniform) .. 1 (fixed hour).
    login_hour_concentration: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )
    #: Counts per hour-of-day, index 0-23.
    hour_histogram: Mapped[list[int]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )
    weekend_login_ratio: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # --- Geographic baseline ----------------------------------------------
    usual_countries: Mapped[list[str]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )
    usual_cities: Mapped[list[str]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )
    centroid_latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    centroid_longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    #: 95th-percentile distance from the centroid, in km.
    radius_km_p95: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)

    # --- Device baseline ---------------------------------------------------
    usual_device_fingerprints: Mapped[list[str]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )

    # --- Session / activity baseline --------------------------------------
    avg_session_minutes: Mapped[float] = mapped_column(Float, default=45.0, nullable=False)
    stddev_session_minutes: Mapped[float] = mapped_column(Float, default=20.0, nullable=False)
    avg_requests_per_minute: Mapped[float] = mapped_column(Float, default=2.0, nullable=False)
    stddev_requests_per_minute: Mapped[float] = mapped_column(
        Float, default=1.0, nullable=False
    )
    avg_distinct_resources: Mapped[float] = mapped_column(Float, default=3.0, nullable=False)
    typical_resources: Mapped[list[str]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )

    # --- Model bookkeeping -------------------------------------------------
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Path to the per-user Isolation Forest, once enough events exist.
    model_path: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    last_trained_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="behavior_profile")

    @property
    def typical_login_hour(self) -> float:
        """Circular mean of the login hour, in [0, 24)."""
        angle = math.atan2(self.login_hour_sin, self.login_hour_cos)
        return (angle % (2 * math.pi)) / (2 * math.pi) * 24.0

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<BehaviorProfile user={self.user_id} events={self.event_count}>"
