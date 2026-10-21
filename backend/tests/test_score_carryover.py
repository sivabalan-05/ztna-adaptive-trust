"""A trust score lost in one session must not reset when the user signs in again."""

from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import User
from app.models.base import utcnow
from app.models.enums import AccessAction, RiskLevel, ScoreTrigger
from app.models.trust_score import TrustScore
from tests.conftest import sign_in


def _record_drop(
    db: Session, user: User, tokens: dict, score: float, age_hours: float = 0
) -> None:
    """Pretend the session behind ``tokens`` was scored down to ``score``."""
    db.add(
        TrustScore(
            session_id=uuid.UUID(str(tokens["session_id"])),
            user_id=user.id,
            score=score,
            risk_level=RiskLevel.HIGH,
            action=AccessAction.STEP_UP_MFA,
            trigger=ScoreTrigger.PERIODIC,
            factors=[],
            reason="Lateral movement",
            created_at=utcnow() - timedelta(hours=age_hours),
        )
    )
    db.commit()


def test_relogin_keeps_a_recent_drop(
    client: TestClient, db: Session, user: User
) -> None:
    fresh = sign_in(client, user)["trust_score"]
    assert fresh > 60

    _record_drop(db, user, sign_in(client, user), score=45.0)
    again = sign_in(client, user)

    assert again["trust_score"] <= 46, again["trust_score"]
    assert "Carried over" in again["trust_reason"]


def test_carried_score_recovers_over_the_window(
    client: TestClient, db: Session, user: User
) -> None:
    fresh = sign_in(client, user)["trust_score"]
    _record_drop(
        db, user, sign_in(client, user), score=45.0,
        age_hours=settings.trust_carryover_hours / 2,
    )

    halfway = sign_in(client, user)["trust_score"]
    assert 45 < halfway < fresh, (halfway, fresh)


def test_drop_older_than_the_window_is_forgotten(
    client: TestClient, db: Session, user: User
) -> None:
    fresh = sign_in(client, user)["trust_score"]
    _record_drop(
        db, user, sign_in(client, user), score=45.0,
        age_hours=settings.trust_carryover_hours + 1,
    )

    assert sign_in(client, user)["trust_score"] == fresh


def test_repeated_logins_do_not_restart_recovery(
    client: TestClient, db: Session, user: User
) -> None:
    """A score held down by the carry-over is not itself carried again."""
    _record_drop(db, user, sign_in(client, user), score=45.0)

    second = sign_in(client, user)["trust_score"]
    third = sign_in(client, user)["trust_score"]

    assert abs(third - second) < 1.0, (second, third)


def test_carry_over_never_forces_critical(
    client: TestClient, db: Session, user: User
) -> None:
    """A revoked session's score drags the next sign-in down to HIGH, not out."""
    _record_drop(db, user, sign_in(client, user), score=10.0)

    again = sign_in(client, user)

    assert again["trust_score"] >= settings.risk_high_min
    assert again["risk_level"] == RiskLevel.HIGH.value
