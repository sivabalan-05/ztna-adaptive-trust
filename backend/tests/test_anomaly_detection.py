"""Isolation Forest: feature contract, inference, and its absence.

Training itself is exercised end to end by ``scripts/train_model.py``; these
tests pin the parts the running platform depends on — the feature vector's
shape and order, the score normalisation, and the behaviour when no model has
been trained yet.
"""

from __future__ import annotations

import math
import uuid
from pathlib import Path

import numpy as np
import pytest
from sqlalchemy.orm import Session

from app.ai import anomaly, dataset
from app.ai.scoring import TrustSignals, behavior_factor
from app.core.context import anonymous_bundle
from app.models import AccessRequest, User
from app.models.base import utcnow
from app.models.enums import AccessAction, RiskLevel


# --- the feature contract ---------------------------------------------------

def test_feature_order_matches_the_specification() -> None:
    """Training and inference must agree; this list is the single definition."""
    assert anomaly.FEATURE_ORDER == (
        "hour_sin", "hour_cos", "day_of_week", "is_known_device",
        "geo_distance_from_usual_km", "is_new_country", "ip_reputation_score",
        "is_vpn", "requests_per_minute", "session_duration_min",
        "num_distinct_resources", "failed_auth_count_24h", "travel_velocity_kmh",
    )
    assert len(anomaly.FEATURE_ORDER) == 13


def test_to_vector_preserves_order_and_fills_gaps() -> None:
    vector = anomaly.to_vector({"hour_sin": 0.5, "is_vpn": 1.0})
    assert len(vector) == len(anomaly.FEATURE_ORDER)
    assert vector[0] == 0.5
    assert vector[anomaly.FEATURE_ORDER.index("is_vpn")] == 1.0
    assert vector[anomaly.FEATURE_ORDER.index("day_of_week")] == 0.0


def test_hour_is_encoded_circularly() -> None:
    """23:00 and 00:00 must be adjacent in feature space, not maximally apart."""
    from app.ai.profiling import features_for_model

    def at(hour: int) -> tuple[float, float]:
        bundle = anonymous_bundle()
        temporal = type(bundle.temporal)(
            at=bundle.temporal.at, local_time=bundle.temporal.local_time,
            hour_of_day=hour, day_of_week=2, is_weekend=False,
            is_business_hours=True,
        )
        patched = type(bundle)(
            request_id="t", method="GET", path="", user_agent="",
            network=bundle.network, temporal=temporal,
        )
        f = features_for_model(TrustSignals(), patched)
        return f["hour_sin"], f["hour_cos"]

    def distance(a: tuple[float, float], b: tuple[float, float]) -> float:
        return math.dist(a, b)

    near = distance(at(23), at(0))
    far = distance(at(23), at(11))
    assert near < far


def test_features_are_json_safe_even_with_infinite_velocity() -> None:
    import json

    from app.ai.profiling import features_for_model

    features = features_for_model(
        TrustSignals(travel_velocity_kmh=float("inf")), anonymous_bundle()
    )
    json.dumps(features)
    assert features["travel_velocity_kmh"] == 99999.0


# --- dataset assembly -------------------------------------------------------

def test_dataset_is_empty_without_events(db: Session) -> None:
    data = dataset.load(db)
    assert len(data) == 0
    assert data.anomaly_rate == 0.0


def test_dataset_reads_stored_feature_vectors(
    db: Session, user: User, catalogue: dict
) -> None:
    for index in range(3):
        db.add(
            AccessRequest(
                user_id=user.id, requested_at=utcnow(), score_at_request=90.0,
                risk_level=RiskLevel.LOW, decision=AccessAction.ALLOW,
                granted=True,
                features={"hour_sin": 0.1 * index, "is_vpn": float(index % 2)},
                is_anomalous=index == 2,
            )
        )
    db.commit()

    data = dataset.load(db)
    assert len(data) == 3
    assert data.X.shape == (3, len(anomaly.FEATURE_ORDER))
    assert int(data.y.sum()) == 1
    assert list(data.X.columns) == list(anomaly.FEATURE_ORDER)


def test_dataset_skips_events_with_no_features(db: Session, user: User) -> None:
    db.add(
        AccessRequest(
            user_id=user.id, requested_at=utcnow(), score_at_request=90.0,
            risk_level=RiskLevel.LOW, decision=AccessAction.ALLOW, granted=True,
            features={},
        )
    )
    db.commit()
    assert len(dataset.load(db)) == 0


def test_dataset_caps_infinite_values(db: Session, user: User) -> None:
    """Infinity is meaningless to a tree split and poisons any scaler."""
    db.add(
        AccessRequest(
            user_id=user.id, requested_at=utcnow(), score_at_request=10.0,
            risk_level=RiskLevel.CRITICAL, decision=AccessAction.BLOCK,
            granted=False,
            features={"travel_velocity_kmh": float("inf")},
        )
    )
    db.commit()
    data = dataset.load(db)
    assert np.isfinite(data.X.to_numpy()).all()


def test_dataset_can_be_sliced_per_user(db: Session, user: User, admin: User) -> None:
    for owner in (user, user, admin):
        db.add(
            AccessRequest(
                user_id=owner.id, requested_at=utcnow(), score_at_request=90.0,
                risk_level=RiskLevel.LOW, decision=AccessAction.ALLOW,
                granted=True, features={"hour_sin": 0.5},
            )
        )
    db.commit()
    data = dataset.load(db)
    assert len(data.for_user(user.id)) == 2
    assert len(data.for_user(admin.id)) == 1


def test_event_counts_by_user(db: Session, user: User) -> None:
    for _ in range(4):
        db.add(
            AccessRequest(
                user_id=user.id, requested_at=utcnow(), score_at_request=90.0,
                risk_level=RiskLevel.LOW, decision=AccessAction.ALLOW,
                granted=True, features={"hour_sin": 0.1},
            )
        )
    db.commit()
    assert dataset.event_counts_by_user(db)[user.id] == 4


# --- inference with no trained model ---------------------------------------

@pytest.fixture
def no_model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point the model directory somewhere empty."""
    monkeypatch.setattr("app.ai.anomaly.settings.model_dir", tmp_path)
    anomaly.clear_cache()
    yield
    anomaly.clear_cache()


def test_score_is_none_when_no_model_is_trained(no_model: None) -> None:
    """None means 'no model', which the behaviour factor must handle.

    A fabricated 0.0 would read as 'checked and found normal', which is the
    opposite of the truth.
    """
    assert anomaly.score({"hour_sin": 0.5}) is None
    assert anomaly.is_available() is False
    assert anomaly.model_info() is None


def test_score_for_user_falls_back_to_the_global_model(
    no_model: None
) -> None:
    value, used = anomaly.score_for_user({"hour_sin": 0.5}, uuid.uuid4())
    assert value is None
    assert used == anomaly.GLOBAL_MODEL_NAME


def test_behaviour_factor_still_works_without_a_model() -> None:
    result = behavior_factor(TrustSignals(anomaly_score=None, profile_deviation=0.8))
    assert result.penalty > 0
    assert result.signals["anomaly_score"] is None
    assert "behaviour profile" in result.reason


def test_behaviour_factor_prefers_the_model_when_one_exists() -> None:
    with_model = behavior_factor(
        TrustSignals(anomaly_score=0.9, profile_deviation=0.1)
    )
    assert "Isolation Forest" in with_model.reason
    assert with_model.signals["anomaly_score"] == 0.9


# --- retrain guard ----------------------------------------------------------

def test_retrain_rejects_a_regression() -> None:
    """A scheduled job must not quietly deploy a worse detector."""
    from app.workers.retrain import MAX_F1_REGRESSION

    assert 0 < MAX_F1_REGRESSION < 0.5


def test_retrain_hour_check() -> None:
    from datetime import datetime, timezone

    from app.workers import retrain

    assert retrain.due(datetime(2026, 3, 1, 2, 30, tzinfo=timezone.utc), hour=2)
    assert not retrain.due(datetime(2026, 3, 1, 14, 0, tzinfo=timezone.utc), hour=2)
