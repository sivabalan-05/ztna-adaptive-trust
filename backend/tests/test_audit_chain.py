"""Chain-of-trust audit log: linkage, verification and tamper detection."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, User
from app.services.audit_service import AuditService
from app.services.hash_chain import (
    GENESIS_HASH, canonical_timestamp, compute_record_hash, hash_payload,
)
from tests.conftest import sign_in


def test_first_record_links_to_genesis(db: Session) -> None:
    record = AuditService.record(
        db, action="TEST_EVENT", payload={"a": 1}, actor_label="tester"
    )
    db.commit()
    assert record.seq == 1
    assert record.prev_hash == GENESIS_HASH
    assert len(record.record_hash) == 64


def test_records_chain_in_sequence(db: Session) -> None:
    first = AuditService.record(db, action="ONE", payload={"n": 1})
    second = AuditService.record(db, action="TWO", payload={"n": 2})
    third = AuditService.record(db, action="THREE", payload={"n": 3})
    db.commit()

    assert [first.seq, second.seq, third.seq] == [1, 2, 3]
    assert second.prev_hash == first.record_hash
    assert third.prev_hash == second.record_hash


def test_verify_reports_a_healthy_chain(db: Session) -> None:
    for i in range(5):
        AuditService.record(db, action=f"EVENT_{i}", payload={"i": i})
    db.commit()

    result = AuditService.verify(db)
    assert result["valid"] is True
    assert result["records_checked"] == 5
    assert result["broken_at"] is None


def test_verify_on_an_empty_log_is_valid(db: Session) -> None:
    result = AuditService.verify(db)
    assert result["valid"] is True
    assert result["records_checked"] == 0
    assert result["head_hash"] == GENESIS_HASH


def test_altering_a_payload_breaks_the_chain(db: Session) -> None:
    for i in range(5):
        AuditService.record(db, action=f"EVENT_{i}", payload={"i": i})
    db.commit()

    victim = db.scalar(select(AuditLog).where(AuditLog.seq == 3))
    victim.payload = {"i": 999}
    db.commit()

    result = AuditService.verify(db)
    assert result["valid"] is False
    assert result["broken_at"] == 3
    assert "payload" in result["reason"]


def test_altering_an_action_breaks_the_chain(db: Session) -> None:
    for i in range(4):
        AuditService.record(db, action=f"EVENT_{i}", payload={"i": i})
    db.commit()

    victim = db.scalar(select(AuditLog).where(AuditLog.seq == 2))
    victim.action = "SOMETHING_ELSE"
    db.commit()

    result = AuditService.verify(db)
    assert result["valid"] is False
    assert result["broken_at"] == 2


def test_deleting_a_record_breaks_the_chain(db: Session) -> None:
    for i in range(5):
        AuditService.record(db, action=f"EVENT_{i}", payload={"i": i})
    db.commit()

    db.delete(db.scalar(select(AuditLog).where(AuditLog.seq == 3)))
    db.commit()

    result = AuditService.verify(db)
    assert result["valid"] is False
    assert result["broken_at"] == 4, "the record after the gap is where it shows"


def test_hash_is_stable_across_key_ordering() -> None:
    """Re-serialising an identical payload must not change its hash."""
    assert hash_payload({"a": 1, "b": 2}) == hash_payload({"b": 2, "a": 1})


def test_timestamp_canonicalisation_is_dialect_independent() -> None:
    """A naive UTC datetime and its aware twin must hash identically.

    PostgreSQL returns aware datetimes and SQLite returns naive ones for the
    same stored instant; without this, verification would fail on the dialect
    rather than on tampering.
    """
    from datetime import datetime, timezone

    naive = datetime(2026, 3, 1, 12, 30, 15, 123456)
    aware = naive.replace(tzinfo=timezone.utc)
    assert canonical_timestamp(naive) == canonical_timestamp(aware)
    assert compute_record_hash(
        GENESIS_HASH, naive, "a", "B", "c"
    ) == compute_record_hash(GENESIS_HASH, aware, "a", "B", "c")


# --- the chain is fed by real authentication traffic ------------------------

def test_login_writes_a_verifiable_chain(
    client: TestClient, user: User, db: Session
) -> None:
    sign_in(client, user)

    actions = [
        row.action for row in db.scalars(select(AuditLog).order_by(AuditLog.seq))
    ]
    assert "PASSWORD_ACCEPTED" in actions
    assert "LOGIN_SUCCESS" in actions
    assert AuditService.verify(db)["valid"] is True


def test_failed_login_is_recorded_and_still_verifies(
    client: TestClient, user: User, db: Session
) -> None:
    client.post(
        "/api/auth/login", json={"username": user.username, "password": "wrong-one"}
    )
    record = db.scalar(select(AuditLog).where(AuditLog.action == "LOGIN_FAILED"))
    assert record is not None
    assert record.payload["reason"] == "bad_password"
    assert AuditService.verify(db)["valid"] is True
