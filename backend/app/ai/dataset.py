"""Training dataset assembly.

Reads the feature vectors already stored on ``access_requests`` — written by
the seeder for historical events and by the enforcement point for live ones —
into a DataFrame the Isolation Forest can consume.

Features are stored at write time rather than recomputed at training time on
purpose: a model must be trained on the same numbers the engine actually saw,
not on a reconstruction that later code changes could quietly alter.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.anomaly import FEATURE_ORDER
from app.models.access_request import AccessRequest

logger = logging.getLogger(__name__)


@dataclass
class Dataset:
    """Feature matrix, labels and the ids each row came from."""

    X: pd.DataFrame
    y: np.ndarray              # 1 = labelled anomalous, 0 = normal
    user_ids: list[uuid.UUID]
    request_ids: list[uuid.UUID]

    def __len__(self) -> int:
        return len(self.X)

    @property
    def anomaly_rate(self) -> float:
        return float(self.y.mean()) if len(self.y) else 0.0

    def for_user(self, user_id: uuid.UUID) -> "Dataset":
        mask = [uid == user_id for uid in self.user_ids]
        indices = [i for i, keep in enumerate(mask) if keep]
        return Dataset(
            X=self.X.iloc[indices].reset_index(drop=True),
            y=self.y[indices],
            user_ids=[self.user_ids[i] for i in indices],
            request_ids=[self.request_ids[i] for i in indices],
        )


def load(
    db: Session,
    *,
    user_id: uuid.UUID | None = None,
    limit: int | None = None,
) -> Dataset:
    """Build a dataset from every access event that carries a feature vector."""
    stmt = select(AccessRequest).order_by(AccessRequest.requested_at)
    if user_id is not None:
        stmt = stmt.where(AccessRequest.user_id == user_id)
    if limit is not None:
        stmt = stmt.limit(limit)

    rows, labels, user_ids, request_ids = [], [], [], []
    skipped = 0

    for record in db.scalars(stmt):
        features = record.features or {}
        if not features:
            skipped += 1
            continue
        rows.append([_finite(features.get(name, 0.0)) for name in FEATURE_ORDER])
        labels.append(1 if record.is_anomalous else 0)
        user_ids.append(record.user_id)
        request_ids.append(record.id)

    if skipped:
        logger.warning("Skipped %d access events with no feature vector.", skipped)

    return Dataset(
        X=pd.DataFrame(rows, columns=list(FEATURE_ORDER)),
        y=np.asarray(labels, dtype=int),
        user_ids=user_ids,
        request_ids=request_ids,
    )


def _finite(value: object) -> float:
    """Coerce to a finite float.

    ``travel_velocity_kmh`` is genuinely infinite for a same-second login from
    another city. Infinity is meaningless to a tree split and poisons any
    scaler, so it is capped at the sentinel the writers already use.
    """
    try:
        number = float(value)   # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    if not np.isfinite(number):
        return 99999.0
    return number


def event_counts_by_user(db: Session) -> dict[uuid.UUID, int]:
    """How many events each user has, for the per-user model threshold."""
    rows = db.execute(
        select(AccessRequest.user_id, func.count())
        .group_by(AccessRequest.user_id)
    ).all()
    return {user_id: int(count) for user_id, count in rows}
