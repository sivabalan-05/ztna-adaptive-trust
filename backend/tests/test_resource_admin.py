"""Administering the resource catalogue through the API."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.resource import Resource
from app.models.user import User
from tests.conftest import auth_headers, sign_in


def test_an_admin_creates_a_resource(
    client: TestClient, admin: User, db: Session
) -> None:
    tokens = sign_in(client, admin)

    response = client.post(
        "/api/resources",
        headers=auth_headers(tokens),
        json={
            "slug": "security-handbook",
            "name": "Security Handbook",
            "description": "How we handle incidents.",
            "category": "document",
            "sensitivity": "INTERNAL",
            "owner": "Information Security",
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["slug"] == "security-handbook"
    assert body["has_file"] is False
    assert body["min_trust_score"] == 60, "must default to the INTERNAL floor"

    stored = db.scalar(select(Resource).where(Resource.slug == "security-handbook"))
    assert stored is not None


def test_an_analyst_cannot_create_a_resource(
    client: TestClient, analyst: User
) -> None:
    tokens = sign_in(client, analyst)

    response = client.post(
        "/api/resources",
        headers=auth_headers(tokens),
        json={"slug": "sneaky", "name": "Sneaky", "sensitivity": "PUBLIC"},
    )

    assert response.status_code == 403


def test_an_employee_cannot_create_a_resource(
    client: TestClient, user: User
) -> None:
    tokens = sign_in(client, user)

    response = client.post(
        "/api/resources",
        headers=auth_headers(tokens),
        json={"slug": "sneaky", "name": "Sneaky", "sensitivity": "PUBLIC"},
    )

    assert response.status_code == 403


def test_a_malformed_slug_is_refused(client: TestClient, admin: User) -> None:
    tokens = sign_in(client, admin)

    response = client.post(
        "/api/resources",
        headers=auth_headers(tokens),
        json={"slug": "Not A Slug!", "name": "Bad", "sensitivity": "PUBLIC"},
    )

    assert response.status_code == 422


def test_a_duplicate_slug_is_refused(
    client: TestClient, admin: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, admin)

    response = client.post(
        "/api/resources",
        headers=auth_headers(tokens),
        json={"slug": "hr-portal", "name": "Clash", "sensitivity": "PUBLIC"},
    )

    assert response.status_code == 409


def test_an_admin_edits_a_resource(
    client: TestClient, admin: User, catalogue: dict[str, Resource], db: Session
) -> None:
    tokens = sign_in(client, admin)

    response = client.patch(
        "/api/resources/hr-portal",
        headers=auth_headers(tokens),
        json={"description": "Leave, timesheets and appraisals.", "min_trust_score": 70},
    )

    assert response.status_code == 200, response.text
    assert response.json()["min_trust_score"] == 70


def test_deleting_a_resource_disables_it_rather_than_destroying_it(
    client: TestClient, admin: User, catalogue: dict[str, Resource], db: Session
) -> None:
    tokens = sign_in(client, admin)

    response = client.delete("/api/resources/hr-portal", headers=auth_headers(tokens))

    assert response.status_code == 204
    stored = db.scalar(select(Resource).where(Resource.slug == "hr-portal"))
    assert stored is not None, "the row must survive so audit history stays intact"
    assert stored.enabled is False


def test_a_disabled_resource_leaves_the_catalogue(
    client: TestClient, admin: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, admin)
    client.delete("/api/resources/hr-portal", headers=auth_headers(tokens))

    listing = client.get("/api/resources", headers=auth_headers(tokens))

    assert listing.status_code == 200
    assert all(row["slug"] != "hr-portal" for row in listing.json())


def test_an_employee_with_include_disabled_still_does_not_see_it(
    client: TestClient, admin: User, user: User, catalogue: dict[str, Resource]
) -> None:
    admin_tokens = sign_in(client, admin)
    client.delete("/api/resources/hr-portal", headers=auth_headers(admin_tokens))

    tokens = sign_in(client, user)
    listing = client.get(
        "/api/resources?include_disabled=true", headers=auth_headers(tokens)
    )

    assert listing.status_code == 200
    assert all(row["slug"] != "hr-portal" for row in listing.json())


def test_an_admin_with_include_disabled_sees_it(
    client: TestClient, admin: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, admin)
    client.delete("/api/resources/hr-portal", headers=auth_headers(tokens))

    listing = client.get(
        "/api/resources?include_disabled=true", headers=auth_headers(tokens)
    )

    assert listing.status_code == 200
    assert any(row["slug"] == "hr-portal" for row in listing.json())
