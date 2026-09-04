"""Nightly model retraining.

Runs the same code path as ``scripts/train_model.py`` so that a scheduled
retrain and a manual one cannot diverge. Each run is versioned, its metrics are
written to ``system_logs``, and the in-process model cache is cleared so the API
picks up the new model without a restart.

A retrain that produces a *worse* model is rejected rather than deployed: a
scheduled job must not be able to quietly degrade enforcement while nobody is
watching.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.ai import anomaly
from app.core.config import ROOT_DIR, settings
from app.core.database import SessionLocal
from app.models.base import utcnow
from app.models.enums import LogLevel
from app.models.system_log import SystemLog

logger = logging.getLogger(__name__)

TRAIN_SCRIPT = ROOT_DIR / "scripts" / "train_model.py"

#: A new model may lose at most this much F1 against the previous one before it
#: is treated as a regression and left undeployed.
MAX_F1_REGRESSION = 0.05


@dataclass
class RetrainResult:
    ok: bool
    message: str
    previous_f1: float | None = None
    new_f1: float | None = None


def _current_f1() -> float | None:
    info = anomaly.model_info()
    if not info:
        return None
    metrics = info.get("metrics") or {}
    value = metrics.get("f1") if isinstance(metrics, dict) else None
    return float(value) if value is not None else None


def _backup_path() -> Path:
    return Path(settings.model_dir) / f"{anomaly.GLOBAL_MODEL_NAME}.previous"


def run_retrain(*, per_user: bool = False) -> RetrainResult:
    """Retrain, compare against the model in service, and keep the better one."""
    if not TRAIN_SCRIPT.exists():
        return RetrainResult(False, f"Training script not found at {TRAIN_SCRIPT}")

    previous_f1 = _current_f1()
    live_model = Path(settings.model_dir) / anomaly.GLOBAL_MODEL_NAME
    backup = _backup_path()
    if live_model.exists():
        backup.write_bytes(live_model.read_bytes())

    command = [sys.executable, str(TRAIN_SCRIPT), "--no-backfill"]
    if not per_user:
        command.append("--no-per-user")

    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=1800, check=False
        )
    except subprocess.TimeoutExpired:
        return RetrainResult(False, "Retraining timed out after 30 minutes.")

    if completed.returncode != 0:
        logger.error("Retraining failed:\n%s", completed.stderr[-2000:])
        return RetrainResult(False, f"Training exited {completed.returncode}.")

    anomaly.clear_cache()
    new_f1 = _current_f1()

    if previous_f1 is not None and new_f1 is not None:
        if new_f1 < previous_f1 - MAX_F1_REGRESSION:
            # Roll back rather than deploy a worse detector unattended.
            if backup.exists():
                live_model.write_bytes(backup.read_bytes())
                anomaly.clear_cache()
            return RetrainResult(
                False,
                f"Rejected: F1 fell from {previous_f1:.3f} to {new_f1:.3f}; "
                f"the previous model was restored.",
                previous_f1, new_f1,
            )

    return RetrainResult(
        True,
        f"Retrained successfully (F1 {new_f1:.3f})" if new_f1 is not None
        else "Retrained successfully.",
        previous_f1, new_f1,
    )


def retrain_and_log(*, per_user: bool = False) -> RetrainResult:
    result = run_retrain(per_user=per_user)
    with SessionLocal() as db:
        db.add(
            SystemLog(
                created_at=utcnow(),
                level=LogLevel.INFO if result.ok else LogLevel.ERROR,
                logger="workers.retrain",
                message=result.message,
                context={
                    "ok": result.ok,
                    "previous_f1": result.previous_f1,
                    "new_f1": result.new_f1,
                    "per_user": per_user,
                },
            )
        )
        db.commit()
    logger.info("Retrain: %s", result.message)
    return result


def due(now: datetime | None = None, hour: int = 2) -> bool:
    """True during the retrain hour (02:00 UTC by default)."""
    now = now or datetime.now(timezone.utc)
    return now.hour == hour
