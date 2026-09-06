"""Serving resource content — every delivery is a policy decision."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.access_request import AccessRequest
from app.models.audit_log import AuditLog
from app.models.resource import Resource
from app.models.user import User
from tests.conftest import auth_headers, sign_in


@pytest.fixture(autouse=True)
def storage_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "app.core.config.settings.resource_storage_dir", tmp_path / "resources"
    )
    yield


def attach(
    client: TestClient, admin: User, slug: str, body: bytes = b"file contents"
) -> None:
    """Upload a small text file to ``slug`` as the administrator."""
    tokens = sign_in(client, admin)
    response = client.post(
        f"/api/resources/{slug}/file",
        headers=auth_headers(tokens),
        files={"file": ("notes.txt", body, "text/plain")},
    )
    assert response.status_code == 200, response.text


def test_a_permitted_user_receives_the_bytes(
    client: TestClient, admin: User, user: User, catalogue: dict[str, Resource]
) -> None:
    attach(client, admin, "public-docs", b"published documentation")
    tokens = sign_in(client, user)

    response = client.get(
        "/api/resources/public-docs/content", headers=auth_headers(tokens)
    )

    assert response.status_code == 200, response.text
    assert response.content == b"published documentation"
    assert response.headers["content-type"].startswith("text/plain")


def test_delivery_is_refused_when_clearance_is_too_low(
    client: TestClient, admin: User, contractor: User,
    catalogue: dict[str, Resource],
) -> None:
    attach(client, admin, "source-repo", b"secret source")
    tokens = sign_in(client, contractor)

    response = client.get(
        "/api/resources/source-repo/content", headers=auth_headers(tokens)
    )

    assert response.status_code == 403
    assert response.headers["X-Access-Gate"] in {"clearance", "policy"}
    assert b"secret source" not in response.content


def test_every_delivery_records_an_access_request_and_an_audit_entry(
    client: TestClient, admin: User, user: User,
    catalogue: dict[str, Resource], db: Session,
) -> None:
    attach(client, admin, "public-docs")
    tokens = sign_in(client, user)
    before = db.scalar(select(func.count(AuditLog.id))) or 0

    client.get("/api/resources/public-docs/content", headers=auth_headers(tokens))

    requests = db.scalars(
        select(AccessRequest).where(AccessRequest.user_id == user.id)
    ).all()
    assert len(requests) == 1
    assert requests[0].granted is True
    after = db.scalar(select(func.count(AuditLog.id))) or 0
    assert after > before, "the decision must be appended to the audit chain"


def test_a_refusal_is_recorded_as_evidence(
    client: TestClient, admin: User, contractor: User,
    catalogue: dict[str, Resource], db: Session,
) -> None:
    attach(client, admin, "source-repo")
    tokens = sign_in(client, contractor)

    client.get("/api/resources/source-repo/content", headers=auth_headers(tokens))

    denied = db.scalars(
        select(AccessRequest).where(
            AccessRequest.user_id == contractor.id,
            AccessRequest.granted.is_(False),
        )
    ).all()
    assert len(denied) == 1, "a refusal must survive the 403"


def test_a_resource_with_no_file_is_a_404_not_a_denial(
    client: TestClient, user: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, user)

    response = client.get(
        "/api/resources/public-docs/content", headers=auth_headers(tokens)
    )

    assert response.status_code == 404
    assert "no file" in response.json()["detail"].lower()


def test_access_granted_once_is_re_decided_on_the_next_request(
    client: TestClient, admin: User, user: User,
    catalogue: dict[str, Resource], db: Session,
) -> None:
    """The continuous-verification claim, asserted directly: raising the
    resource's trust floor above the session's score turns the next delivery
    into a refusal, with no re-login in between."""
    attach(client, admin, "public-docs", b"still public")
    tokens = sign_in(client, user)

    first = client.get(
        "/api/resources/public-docs/content", headers=auth_headers(tokens)
    )
    assert first.status_code == 200

    resource = db.scalar(select(Resource).where(Resource.slug == "public-docs"))
    assert resource is not None
    resource.min_trust_score = 100
    db.commit()

    second = client.get(
        "/api/resources/public-docs/content", headers=auth_headers(tokens)
    )

    assert second.status_code == 403
    assert second.headers["X-Access-Gate"] == "trust"


def test_a_disabled_resource_refuses_delivery(
    client: TestClient, admin: User, user: User, catalogue: dict[str, Resource]
) -> None:
    attach(client, admin, "public-docs")
    admin_tokens = sign_in(client, admin)
    client.delete("/api/resources/public-docs", headers=auth_headers(admin_tokens))
    tokens = sign_in(client, user)

    response = client.get(
        "/api/resources/public-docs/content", headers=auth_headers(tokens)
    )

    assert response.status_code in {403, 404}
    assert response.content != b"file contents"
