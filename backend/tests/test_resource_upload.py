"""Attaching files to resources."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import storage
from app.models.resource import Resource
from app.models.user import User
from tests.conftest import auth_headers, sign_in


@pytest.fixture(autouse=True)
def storage_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "app.core.config.settings.resource_storage_dir", tmp_path / "resources"
    )
    yield


def test_an_admin_attaches_a_file(
    client: TestClient, admin: User, catalogue: dict[str, Resource], db: Session
) -> None:
    tokens = sign_in(client, admin)

    response = client.post(
        "/api/resources/hr-portal/file",
        headers=auth_headers(tokens),
        files={"file": ("leave-policy.md", b"# Leave policy\n", "text/markdown")},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["has_file"] is True
    assert body["file_name"] == "leave-policy.md"
    assert body["content_type"] == "text/markdown"
    assert body["file_size"] == len(b"# Leave policy\n")

    stored = db.scalar(select(Resource).where(Resource.slug == "hr-portal"))
    assert stored is not None
    assert storage.read(stored.file_path) == b"# Leave policy\n"


def test_the_stored_name_does_not_use_the_uploaded_filename(
    client: TestClient, admin: User, catalogue: dict[str, Resource], db: Session
) -> None:
    tokens = sign_in(client, admin)

    client.post(
        "/api/resources/hr-portal/file",
        headers=auth_headers(tokens),
        files={"file": ("../../escape.md", b"payload", "text/markdown")},
    )

    stored = db.scalar(select(Resource).where(Resource.slug == "hr-portal"))
    assert stored is not None
    assert ".." not in stored.file_path
    assert "escape" not in stored.file_path


def test_a_disallowed_type_is_refused(
    client: TestClient, admin: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, admin)

    response = client.post(
        "/api/resources/hr-portal/file",
        headers=auth_headers(tokens),
        files={"file": ("run.sh", b"rm -rf /", "application/x-sh")},
    )

    assert response.status_code == 422
    assert "not accepted" in response.json()["detail"]


def test_an_analyst_cannot_upload(
    client: TestClient, analyst: User, catalogue: dict[str, Resource]
) -> None:
    tokens = sign_in(client, analyst)

    response = client.post(
        "/api/resources/hr-portal/file",
        headers=auth_headers(tokens),
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 403


def test_replacing_a_file_removes_the_previous_one(
    client: TestClient, admin: User, catalogue: dict[str, Resource], db: Session
) -> None:
    tokens = sign_in(client, admin)
    client.post(
        "/api/resources/hr-portal/file",
        headers=auth_headers(tokens),
        files={"file": ("first.txt", b"first", "text/plain")},
    )
    first_path = db.scalar(
        select(Resource.file_path).where(Resource.slug == "hr-portal")
    )

    client.post(
        "/api/resources/hr-portal/file",
        headers=auth_headers(tokens),
        files={"file": ("second.txt", b"second", "text/plain")},
    )

    second_path = db.scalar(
        select(Resource.file_path).where(Resource.slug == "hr-portal")
    )
    assert second_path != first_path
    with pytest.raises(storage.StorageError):
        storage.read(first_path)
