"""The audit page shows where each event came from."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import User, UserSession
from app.services.audit_service import AuditService
from tests.conftest import auth_headers, sign_in


def _records(client: TestClient, tokens: dict, **params: str) -> list[dict]:
    response = client.get("/api/audit", params=params, headers=auth_headers(tokens))
    assert response.status_code == 200, response.text
    return response.json()["records"]


def test_a_login_is_labelled_with_the_place_its_session_recorded(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)
    session = db.get(UserSession, uuid.UUID(tokens["session_id"]))
    session.city, session.country = "Coimbatore", "IN"
    db.commit()

    login = _records(client, tokens, action="LOGIN_SUCCESS")[0]
    assert login["location"] == "Coimbatore, IN"


def test_new_login_events_record_the_place_in_their_own_payload(
    client: TestClient, admin: User
) -> None:
    tokens = sign_in(client, admin)
    login = _records(client, tokens, action="LOGIN_SUCCESS")[0]
    assert {"ip", "city", "country"} <= set(login["payload"])


def test_a_request_from_a_private_address_is_labelled_local(
    client: TestClient, admin: User
) -> None:
    client.headers["X-Forwarded-For"] = "10.1.2.3"
    tokens = sign_in(client, admin)

    login = _records(client, tokens, action="LOGIN_SUCCESS")[0]
    assert login["ip_address"] == "10.1.2.3"
    assert login["location"] == "Local network"


def test_an_older_record_with_only_an_address_is_placed_from_the_local_table(
    client: TestClient, admin: User, db: Session
) -> None:
    AuditService.record(
        db, action="LOGIN_SUCCESS", actor_label="aswin.pillai",
        ip_address="49.207.248.8", payload={},
    )
    db.commit()
    tokens = sign_in(client, admin)

    match = [
        r for r in _records(client, tokens, actor="aswin.pillai")
        if r["ip_address"] == "49.207.248.8"
    ]
    assert match and match[0]["location"] == "Bangalore, IN"


def test_the_search_box_matches_an_ip_address(
    client: TestClient, admin: User, db: Session
) -> None:
    AuditService.record(
        db, action="LOGIN_FAILED", actor_label="someone",
        ip_address="185.234.9.9", payload={},
    )
    db.commit()
    tokens = sign_in(client, admin)

    found = _records(client, tokens, q="185.234")
    assert [r["ip_address"] for r in found] == ["185.234.9.9"]


def test_a_system_event_on_a_local_session_does_not_repeat_the_placeholder_city(
    client: TestClient, admin: User, db: Session
) -> None:
    """Sessions opened from the server's own network store a placeholder city. An
    event with no address of its own (such as a revocation by the trust engine)
    must still say "Local network", not that placeholder."""
    client.headers["X-Forwarded-For"] = "10.1.2.3"
    tokens = sign_in(client, admin)
    session_id = tokens["session_id"]
    session = db.get(UserSession, uuid.UUID(session_id))
    session.city, session.country = "Coimbatore", "IN"
    AuditService.record(
        db, action="SESSION_REVOKED", actor_label="system",
        resource_type="session", resource_id=session_id,
        payload={"session_id": session_id},
    )
    db.commit()

    revoked = _records(client, tokens, action="SESSION_REVOKED")[0]
    assert revoked["ip_address"] == ""
    assert revoked["location"] == "Local network"
