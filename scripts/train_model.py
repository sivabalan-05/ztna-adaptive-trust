#!/usr/bin/env python3
"""Train the Isolation Forest and report its accuracy.

    python scripts/train_model.py                 # train, evaluate, persist
    python scripts/train_model.py --no-per-user   # global model only
    python scripts/train_model.py --dry-run       # evaluate without persisting

Trains a global model over every recorded access event, plus a per-user model
for each account with at least ``PER_USER_MODEL_MIN_EVENTS`` events, and scores
both against the labelled synthetic attacks in the seed.

A word on what the numbers mean. Isolation Forest is *unsupervised*: it is never
shown the labels. They exist only to measure it afterwards. So precision and
recall here answer "how well does an algorithm that was told nothing about
attacks happen to isolate the ones we planted?" — not "how well did it learn
them". That is the honest framing for the report, and it is also why recall
matters more than precision in this system: a missed attack is a breach, a false
positive is one extra MFA prompt.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score, confusion_matrix, precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.ai import anomaly, dataset  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.models import BehaviorProfile, TrustScore, User  # noqa: E402
from app.models.base import utcnow  # noqa: E402


@dataclass
class Metrics:
    n_events: int
    n_anomalies: int
    precision: float
    recall: float
    f1: float
    roc_auc: float | None
    average_precision: float | None
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    def line(self) -> str:
        return (
            f"precision {self.precision:.3f}  recall {self.recall:.3f}  "
            f"F1 {self.f1:.3f}"
            + (f"  ROC-AUC {self.roc_auc:.3f}" if self.roc_auc is not None else "")
        )


def evaluate(estimator: Any, scaler: Any, data: dataset.Dataset) -> Metrics:
    """Score the model against the ground-truth labels it never saw."""
    matrix = data.X.to_numpy(dtype=float)
    X = scaler.transform(matrix) if scaler is not None else matrix
    predicted = (estimator.predict(X) == -1).astype(int)
    scores = np.clip(0.5 - estimator.decision_function(X), 0.0, 1.0)

    precision, recall, f1, _ = precision_recall_fscore_support(
        data.y, predicted, average="binary", zero_division=0
    )
    matrix = confusion_matrix(data.y, predicted, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()

    both_classes = len(set(data.y.tolist())) > 1
    return Metrics(
        n_events=len(data),
        n_anomalies=int(data.y.sum()),
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        roc_auc=float(roc_auc_score(data.y, scores)) if both_classes else None,
        average_precision=(
            float(average_precision_score(data.y, scores)) if both_classes else None
        ),
        true_positives=int(tp), false_positives=int(fp),
        true_negatives=int(tn), false_negatives=int(fn),
    )


def fit(data: dataset.Dataset) -> tuple[IsolationForest, StandardScaler]:
    # Fit on a bare array. Fitting on the DataFrame binds the scaler to column
    # names, and every later ndarray inference call then warns about it.
    matrix = data.X.to_numpy(dtype=float)
    scaler = StandardScaler().fit(matrix)
    estimator = IsolationForest(
        n_estimators=settings.isolation_forest_estimators,
        contamination=settings.isolation_forest_contamination,
        random_state=settings.isolation_forest_random_state,
        n_jobs=-1,
    )
    estimator.fit(scaler.transform(matrix))
    return estimator, scaler


def persist(
    estimator: Any, scaler: Any, metrics: Metrics, version: str, name: str
) -> Path:
    model_dir = Path(settings.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    path = model_dir / name
    joblib.dump(
        {
            "estimator": estimator,
            "scaler": scaler,
            "version": version,
            "feature_order": list(anomaly.FEATURE_ORDER),
            "metrics": asdict(metrics),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "params": {
                "n_estimators": settings.isolation_forest_estimators,
                "contamination": settings.isolation_forest_contamination,
                "random_state": settings.isolation_forest_random_state,
            },
        },
        path,
    )
    return path


def backfill_scores(db: Any, estimator: Any, scaler: Any) -> int:
    """Fill ``trust_scores.anomaly_score`` for rows recorded before training.

    Each trust score is matched to the access event closest to it in time in
    the same session; a score recorded for a session with no access events
    stays NULL rather than being given a borrowed number.
    """
    from app.models.access_request import AccessRequest

    events: dict[Any, list[tuple[datetime, dict[str, Any]]]] = {}
    for row in db.scalars(select(AccessRequest)):
        if row.session_id and row.features:
            events.setdefault(row.session_id, []).append(
                (row.requested_at, row.features)
            )

    updated = 0
    pending: list[tuple[TrustScore, list[float]]] = []
    for score_row in db.scalars(select(TrustScore)):
        candidates = events.get(score_row.session_id)
        if not candidates:
            continue
        target = score_row.created_at
        _, features = min(
            candidates,
            key=lambda pair: abs(
                (pair[0].replace(tzinfo=None) - target.replace(tzinfo=None)).total_seconds()
            ),
        )
        pending.append((score_row, anomaly.to_vector(features)))

    if not pending:
        return 0

    matrix = np.asarray([vector for _, vector in pending], dtype=float)
    matrix = np.nan_to_num(matrix, posinf=99999.0, neginf=-99999.0)
    if scaler is not None:
        matrix = scaler.transform(matrix)
    scores = np.clip(0.5 - estimator.decision_function(matrix), 0.0, 1.0)

    for (score_row, _), value in zip(pending, scores):
        score_row.anomaly_score = float(value)
        updated += 1
    db.commit()
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-per-user", action="store_true",
                        help="Train the global model only.")
    parser.add_argument("--no-backfill", action="store_true",
                        help="Leave historical anomaly_score values as NULL.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Evaluate without writing any model to disk.")
    parser.add_argument("--min-events", type=int,
                        default=settings.per_user_model_min_events,
                        help="Events required before a per-user model is trained.")
    args = parser.parse_args()

    version = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    with SessionLocal() as db:
        data = dataset.load(db)
        if len(data) < 100:
            print(
                f"Only {len(data)} events available; seed the database first "
                f"(python scripts/seed.py --reset).",
                file=sys.stderr,
            )
            return 1

        print("=" * 74)
        print("  ISOLATION FOREST — TRAINING")
        print("=" * 74)
        print(f"  events              : {len(data):,}")
        print(f"  labelled anomalous  : {int(data.y.sum()):,} "
              f"({data.anomaly_rate * 100:.1f}%)")
        print(f"  features            : {len(anomaly.FEATURE_ORDER)}")
        print(f"  n_estimators        : {settings.isolation_forest_estimators}")
        print(f"  contamination       : {settings.isolation_forest_contamination}")
        print(f"  random_state        : {settings.isolation_forest_random_state}")
        print()

        estimator, scaler = fit(data)
        metrics = evaluate(estimator, scaler, data)

        print("  GLOBAL MODEL")
        print(f"    {metrics.line()}")
        print(f"    confusion matrix   TP {metrics.true_positives:<5} "
              f"FP {metrics.false_positives:<5} "
              f"FN {metrics.false_negatives:<5} TN {metrics.true_negatives}")
        if metrics.average_precision is not None:
            print(f"    average precision  {metrics.average_precision:.3f}")
        print()

        if not args.dry_run:
            path = persist(
                estimator, scaler, metrics, version, anomaly.GLOBAL_MODEL_NAME
            )
            print(f"    saved to {path}")
            print()

        # --- per-user models ------------------------------------------------
        per_user_report: list[tuple[str, int, Metrics]] = []
        if not args.no_per_user:
            counts = dataset.event_counts_by_user(db)
            eligible = [uid for uid, n in counts.items() if n >= args.min_events]
            print(f"  PER-USER MODELS ({len(eligible)} accounts with "
                  f">= {args.min_events} events)")

            for user_id in eligible:
                subset = data.for_user(user_id)
                if len(subset) < args.min_events:
                    continue
                user = db.get(User, user_id)
                try:
                    user_estimator, user_scaler = fit(subset)
                except ValueError:
                    print(f"    {user.username:<22} skipped (degenerate features)")
                    continue

                user_metrics = evaluate(user_estimator, user_scaler, subset)
                per_user_report.append((user.username, len(subset), user_metrics))

                if not args.dry_run:
                    name = f"isolation_forest_user_{user_id.hex}.joblib"
                    model_path = persist(
                        user_estimator, user_scaler, user_metrics, version, name
                    )
                    profile = db.scalar(
                        select(BehaviorProfile).where(
                            BehaviorProfile.user_id == user_id
                        )
                    )
                    if profile is not None:
                        profile.model_path = str(model_path)
                        profile.model_version = version
                        profile.last_trained_at = utcnow()

            with_anomalies = [r for r in per_user_report if r[2].n_anomalies > 0]
            if with_anomalies:
                mean_recall = sum(m.recall for _, _, m in with_anomalies) / len(with_anomalies)
                mean_f1 = sum(m.f1 for _, _, m in with_anomalies) / len(with_anomalies)
                print(f"    {len(per_user_report)} models trained; "
                      f"{len(with_anomalies)} accounts carry labelled attacks")
                print(f"    mean recall {mean_recall:.3f}   mean F1 {mean_f1:.3f}")
            else:
                print(f"    {len(per_user_report)} models trained")
            print()

        if not args.dry_run:
            db.commit()

        # --- backfill --------------------------------------------------------
        if not args.dry_run and not args.no_backfill:
            filled = backfill_scores(db, estimator, scaler)
            print(f"  BACKFILL")
            print(f"    anomaly_score written to {filled:,} historical trust scores")
            print()

        # --- report file -----------------------------------------------------
        if not args.dry_run:
            report_path = Path(settings.model_dir) / "training_report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "version": version,
                        "trained_at": datetime.now(timezone.utc).isoformat(),
                        "params": {
                            "n_estimators": settings.isolation_forest_estimators,
                            "contamination": settings.isolation_forest_contamination,
                            "random_state": settings.isolation_forest_random_state,
                        },
                        "features": list(anomaly.FEATURE_ORDER),
                        "global": asdict(metrics),
                        "per_user": [
                            {"username": name, "events": n, **asdict(m)}
                            for name, n, m in per_user_report
                        ],
                    },
                    indent=2,
                )
            )
            print(f"  report written to {report_path}")

        print("=" * 74)

    anomaly.clear_cache()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
