"""The audit API: search, verification, export and access control."""

from __future__ import annotations

import csv
import io

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, User
from app.models.audit_log import GENESIS_HASH
from app.services.audit_service import AuditService
from app.services.hash_chain import compute_record_hash, hash_payload
from tests.conftest import PASSWORD, auth_headers, sign_in


def seed_chain(db: Session, n: int = 12) -> None:
    for i in range(n):
        AuditService.record(
            db,
            action="LOGIN_SUCCESS" if i % 2 else "ACCESS_DENIED",
            actor_label=f"user{i % 3}",
            resource_type="session",
            resource_id=f"res-{i}",
            ip_address="117.192.1.1",
            payload={"index": i},
        )
    db.commit()


# --- access control ---------------------------------------------------------

def test_audit_requires_a_permission(client: TestClient, user: User) -> None:
    """An ordinary employee cannot read the audit log."""
    tokens = sign_in(client, user)
    assert client.get("/api/audit", headers=auth_headers(tokens)).status_code == 403
    assert client.get(
        "/api/audit/verify", headers=auth_headers(tokens)
    ).status_code == 403


def test_audit_is_not_public(client: TestClient) -> None:
    assert client.get("/api/audit").status_code == 401


# --- search -----------------------------------------------------------------

def test_search_returns_newest_first_with_chain_positions(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)

    body = client.get("/api/audit?limit=5", headers=auth_headers(tokens)).json()
    assert body["limit"] == 5
    assert len(body["records"]) == 5
    positions = [r["seq"] for r in body["records"]]
    assert positions == sorted(positions, reverse=True)
    assert body["total"] >= 12


def test_search_filters_by_action(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)
    body = client.get(
        "/api/audit?action=ACCESS_DENIED&limit=100", headers=auth_headers(tokens)
    ).json()
    assert body["records"]
    assert {r["action"] for r in body["records"]} == {"ACCESS_DENIED"}


def test_search_filters_by_actor_substring(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)
    body = client.get(
        "/api/audit?actor=user1&limit=100", headers=auth_headers(tokens)
    ).json()
    assert body["records"]
    assert all("user1" in r["actor_label"] for r in body["records"])


def test_free_text_search(client: TestClient, admin: User, db: Session) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)
    body = client.get(
        "/api/audit?q=res-7&limit=100", headers=auth_headers(tokens)
    ).json()
    assert body["total"] == 1
    assert body["records"][0]["resource_id"] == "res-7"


def test_pagination_does_not_repeat_records(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db, 20)
    first = client.get("/api/audit?limit=5&offset=0", headers=auth_headers(tokens)).json()
    second = client.get("/api/audit?limit=5&offset=5", headers=auth_headers(tokens)).json()
    assert not (
        {r["seq"] for r in first["records"]} & {r["seq"] for r in second["records"]}
    )


def test_fetch_one_record_by_chain_position(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)
    record = client.get("/api/audit/3", headers=auth_headers(tokens))
    assert record.status_code == 200
    assert record.json()["seq"] == 3
    assert len(record.json()["record_hash"]) == 64


def test_missing_position_is_404(client: TestClient, admin: User) -> None:
    tokens = sign_in(client, admin)
    assert client.get("/api/audit/999999", headers=auth_headers(tokens)).status_code == 404


# --- verification -----------------------------------------------------------

def test_verify_reports_a_healthy_chain(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)

    body = client.get("/api/audit/verify", headers=auth_headers(tokens)).json()
    assert body["valid"] is True
    assert body["broken_at"] is None
    assert body["records_checked"] > 0
    assert body["genesis_hash"] == GENESIS_HASH
    assert body["partial"] is False
    assert body["duration_ms"] >= 0


def test_verify_names_the_exact_tampered_position(
    client: TestClient, admin: User, db: Session
) -> None:
    """The headline demo: alter one record, the chain says which one."""
    tokens = sign_in(client, admin)
    seed_chain(db)

    victim = db.scalar(select(AuditLog).where(AuditLog.seq == 6))
    victim.payload = {"index": "tampered"}
    db.commit()

    body = client.get("/api/audit/verify", headers=auth_headers(tokens)).json()
    assert body["valid"] is False
    assert body["broken_at"] == 6
    assert "payload" in body["reason"]


def test_verify_detects_a_rewritten_action(
    client: TestClient, admin: User, db: Session
) -> None:
    """Rewriting history to hide a denial is exactly what this must catch."""
    tokens = sign_in(client, admin)
    seed_chain(db)

    victim = db.scalar(select(AuditLog).where(AuditLog.seq == 4))
    victim.action = "ACCESS_GRANTED"
    db.commit()

    body = client.get("/api/audit/verify", headers=auth_headers(tokens)).json()
    assert body["valid"] is False
    assert body["broken_at"] == 4


def test_verify_detects_a_deleted_record(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)

    db.delete(db.scalar(select(AuditLog).where(AuditLog.seq == 5)))
    db.commit()

    body = client.get("/api/audit/verify", headers=auth_headers(tokens)).json()
    assert body["valid"] is False
    assert body["broken_at"] == 6, "the record after the gap is where it shows"


def test_partial_verification_is_labelled_as_partial(
    client: TestClient, admin: User, db: Session
) -> None:
    """A suffix check proves nothing about earlier records, and says so."""
    tokens = sign_in(client, admin)
    seed_chain(db)

    victim = db.scalar(select(AuditLog).where(AuditLog.seq == 3))
    victim.payload = {"index": "tampered"}
    db.commit()

    full = client.get("/api/audit/verify", headers=auth_headers(tokens)).json()
    assert full["valid"] is False

    suffix = client.get(
        "/api/audit/verify?from_seq=5", headers=auth_headers(tokens)
    ).json()
    assert suffix["valid"] is True, "the tampering is before the anchor"
    assert suffix["partial"] is True
    assert suffix["verified_from"] == 5


def test_a_forged_record_with_a_recomputed_hash_still_breaks_the_chain(
    client: TestClient, admin: User, db: Session
) -> None:
    """An attacker who recomputes one record's own hash still fails.

    The next record's prev_hash no longer matches, because they would have to
    rewrite every record after it too — which is the whole point of the chain.
    """
    tokens = sign_in(client, admin)
    seed_chain(db)

    victim = db.scalar(select(AuditLog).where(AuditLog.seq == 7))
    victim.payload = {"index": "forged"}
    victim.payload_hash = hash_payload(victim.payload)
    victim.record_hash = compute_record_hash(
        victim.prev_hash, victim.timestamp, victim.actor_label,
        victim.action, victim.payload_hash,
    )
    db.commit()

    body = client.get("/api/audit/verify", headers=auth_headers(tokens)).json()
    assert body["valid"] is False
    assert body["broken_at"] == 8
    assert "prev_hash" in body["reason"]


# --- statistics -------------------------------------------------------------

def test_stats_summarise_the_chain(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)
    body = client.get("/api/audit/stats", headers=auth_headers(tokens)).json()

    assert body["total_records"] >= 12
    assert body["actions"]["ACCESS_DENIED"] >= 6
    assert len(body["head_hash"]) == 64
    assert body["first_record_at"] is not None
    assert body["top_actors"]


# --- export -----------------------------------------------------------------

def test_csv_export_is_reverifiable_from_the_file(
    client: TestClient, admin: User, db: Session
) -> None:
    """An export is only evidence if the recipient can re-check it offline."""
    tokens = sign_in(client, admin)
    seed_chain(db)

    response = client.get("/api/audit/export.csv", headers=auth_headers(tokens))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]

    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) >= 12
    assert {"seq", "record_hash", "prev_hash", "payload_hash"} <= set(rows[0])

    # Re-link the chain from the exported columns alone.
    prev = GENESIS_HASH
    for row in rows:
        assert row["prev_hash"] == prev, f"chain breaks at exported row {row['seq']}"
        prev = row["record_hash"]


def test_csv_export_honours_filters(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    seed_chain(db)
    response = client.get(
        "/api/audit/export.csv?action=ACCESS_DENIED", headers=auth_headers(tokens)
    )
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert rows
    assert {r["action"] for r in rows} == {"ACCESS_DENIED"}


def test_export_quotes_payloads_containing_commas(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    AuditService.record(
        db, action="TEST", actor_label="tester",
        payload={"note": "one, two, three", "quote": 'he said "hi"'},
    )
    db.commit()

    response = client.get("/api/audit/export.csv", headers=auth_headers(tokens))
    rows = list(csv.DictReader(io.StringIO(response.text)))
    match = next(r for r in rows if r["action"] == "TEST")
    assert "one, two, three" in match["payload"]
