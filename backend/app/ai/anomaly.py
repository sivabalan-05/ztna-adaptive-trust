"""Isolation Forest anomaly detection.

The model itself is trained in Phase 6 by ``scripts/train_model.py``. This
module is the loading and inference side: it looks for a persisted model, uses
it when one exists, and returns ``None`` when none does.

``None`` is deliberate and load-bearing. The behaviour factor treats it as
"no model available" and falls back to measurable profile deviation, rather
than being handed a fabricated 0.0 that would read as "verified normal".
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

#: The feature vector, in a fixed order. Training and inference must agree, so
#: this list is the single definition of it.
FEATURE_ORDER: tuple[str, ...] = (
    "hour_sin",
    "hour_cos",
    "day_of_week",
    "is_known_device",
    "geo_distance_from_usual_km",
    "is_new_country",
    "ip_reputation_score",
    "is_vpn",
    "requests_per_minute",
    "session_duration_min",
    "num_distinct_resources",
    "failed_auth_count_24h",
    "travel_velocity_kmh",
)

GLOBAL_MODEL_NAME = "isolation_forest_global.joblib"


def user_model_name(user_id: uuid.UUID) -> str:
    return f"isolation_forest_user_{user_id.hex}.joblib"


@dataclass
class LoadedModel:
    estimator: Any
    scaler: Any | None
    version: str
    path: Path


_lock = threading.Lock()
_cache: dict[str, LoadedModel | None] = {}


def model_path(name: str = GLOBAL_MODEL_NAME) -> Path:
    return Path(settings.model_dir) / name


def load_model(name: str = GLOBAL_MODEL_NAME) -> LoadedModel | None:
    """Load a persisted model, or return None when none has been trained."""
    with _lock:
        if name in _cache:
            return _cache[name]

        path = model_path(name)
        if not path.exists():
            logger.info(
                "No Isolation Forest at %s; the behaviour factor will use profile "
                "deviation only until scripts/train_model.py has run.", path,
            )
            _cache[name] = None
            return None

        try:
            import joblib

            bundle = joblib.load(path)
            model = LoadedModel(
                estimator=bundle["estimator"],
                scaler=bundle.get("scaler"),
                version=bundle.get("version", "unknown"),
                path=path,
            )
            logger.info("Loaded Isolation Forest %s from %s", model.version, path)
        except Exception:
            logger.exception("Could not load the Isolation Forest at %s", path)
            _cache[name] = None
            return None

        _cache[name] = model
        return model


def clear_cache() -> None:
    """Drop the loaded model, so a retrain is picked up without a restart."""
    with _lock:
        _cache.clear()


def to_vector(features: dict[str, float]) -> list[float]:
    """Order a feature dict into the fixed vector, defaulting missing keys to 0."""
    return [float(features.get(name, 0.0)) for name in FEATURE_ORDER]


def score(features: dict[str, float], model_name: str = GLOBAL_MODEL_NAME) -> float | None:
    """Anomaly score in 0-1 (1 = most anomalous), or None if no model exists.

    ``IsolationForest.decision_function`` returns roughly -0.5 (anomalous) to
    +0.5 (normal); this maps that onto 0-1 with the sign flipped so that larger
    always means worse, which is how every other signal in the engine reads.
    """
    model = load_model(model_name)
    if model is None:
        return None

    try:
        vector = [to_vector(features)]
        if model.scaler is not None:
            vector = model.scaler.transform(vector)
        raw = float(model.estimator.decision_function(vector)[0])
    except Exception:
        logger.exception("Isolation Forest inference failed; returning no score.")
        return None

    normalised = 0.5 - raw
    return max(0.0, min(1.0, normalised))


def score_for_user(
    features: dict[str, float], user_id: uuid.UUID | None
) -> tuple[float | None, str]:
    """Score with the per-user model when enabled, else the global one.

    Returns ``(score, model_used)``. Per-user models are trained and measured
    by ``scripts/train_model.py`` but are **off by default**, because on this
    dataset they are measurably worse than the global model: each account
    carries only a handful of labelled attacks, so a per-account contamination
    of 5% is a poor fit and recall drops sharply. The setting exists so the
    trade-off can be re-tested as real traffic accumulates.
    """
    if settings.use_per_user_models and user_id is not None:
        name = user_model_name(user_id)
        if load_model(name) is not None:
            value = score(features, name)
            if value is not None:
                return value, name
    return score(features), GLOBAL_MODEL_NAME


def is_available(model_name: str = GLOBAL_MODEL_NAME) -> bool:
    return load_model(model_name) is not None


def model_info(model_name: str = GLOBAL_MODEL_NAME) -> dict[str, object] | None:
    """Version and metrics of a loaded model, for /health and the dashboard."""
    model = load_model(model_name)
    if model is None:
        return None
    try:
        import joblib

        bundle = joblib.load(model.path)
    except Exception:
        return {"version": model.version, "path": str(model.path)}
    return {
        "version": bundle.get("version"),
        "trained_at": bundle.get("trained_at"),
        "params": bundle.get("params"),
        "metrics": bundle.get("metrics"),
        "path": str(model.path),
    }
