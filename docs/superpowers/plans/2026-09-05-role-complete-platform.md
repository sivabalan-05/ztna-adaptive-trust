# Role-Complete Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every role a complete working interface, and make resources carry real files whose delivery is itself a live policy decision.

**Architecture:** Resource bytes live on disk under a configured storage root, with metadata in the `resources` table. The only route to those bytes is `GET /api/resources/{slug}/content`, which calls the same `AccessService.request_access()` the enforcement point uses — so every view or download re-scores the session, writes an `access_requests` row and appends to the audit chain. On the frontend, `employee` and `contractor` get a real router-based portal in place of today's single placeholder screen, and every operator write control is gated on the permission it actually needs.

**Tech Stack:** FastAPI, SQLAlchemy 2.0, Alembic, pytest, React 18 + TypeScript, Vite, TailwindCSS, axios, react-router-dom.

**Spec:** `docs/superpowers/specs/2026-09-05-role-complete-platform-design.md`

## Global Constraints

- No new runtime dependencies. No server-side PDF renderer, no Markdown-to-HTML renderer, no object-storage client. Preview uses native browser rendering only.
- No frontend test harness is added. Frontend tasks are verified by type-check plus in-browser checks as the specific role.
- Upload ceiling is exactly **25 MB** (`25 * 1024 * 1024` bytes).
- Content-type allowlist, exactly: `application/pdf`, `text/plain`, `text/markdown`, `text/csv`, `application/json`, `image/png`, `image/jpeg`, `image/webp`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, `application/vnd.openxmlformats-officedocument.presentationml.presentation`.
- Resource slug pattern is exactly `^[a-z0-9-]+$`, max 64 characters, unique.
- `resources:write` is held only by `admin`. `DELETE` on a resource sets `enabled = false`; it never deletes the row.
- Stored filenames are always server-generated UUIDs. A client-supplied filename is kept only as a display label.
- Files are never statically served. No `StaticFiles` mount over the storage root, ever.
- All schema changes go through Alembic. SQLite cannot ALTER constraints, so use `op.batch_alter_table`.
- Keep files under 500 lines. Validate input at system boundaries. Read a file before editing it.
- Never add a `Co-Authored-By` trailer or any attribution line to commit messages.
- Backend tests run from `backend/`: `../.venv/bin/python -m pytest`. Frontend type-check runs from `frontend/`: `npm run lint`.

---

# Phase A — Backend: resource content

### Task 1: Storage layer

**Files:**
- Create: `backend/app/core/storage.py`
- Modify: `backend/app/core/config.py` (add `resource_storage_dir` in the Persistence block)
- Create: `backend/tests/test_storage.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `settings` from `app.core.config`
- Produces: `storage.save(data: bytes, content_type: str) -> str`, `storage.read(relative_path: str) -> bytes`, `storage.delete(relative_path: str) -> None`, `storage.clear() -> None`, `storage.storage_root() -> Path`, `storage.StorageError(message, code)`, `storage.MAX_UPLOAD_BYTES`, `storage.ALLOWED_CONTENT_TYPES`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_storage.py`:

```python
"""Resource file storage: what it accepts, and what it refuses."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core import storage


@pytest.fixture(autouse=True)
def storage_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point the storage root at a temporary directory for every test."""
    monkeypatch.setattr(
        "app.core.config.settings.resource_storage_dir", tmp_path / "resources"
    )
    yield tmp_path / "resources"


def test_saving_returns_a_uuid_name_and_keeps_the_bytes() -> None:
    name = storage.save(b"hello world", "text/plain")

    assert name.endswith(".txt")
    assert "hello" not in name, "the stored name must not echo the content"
    assert storage.read(name) == b"hello world"


def test_a_disallowed_content_type_is_refused() -> None:
    with pytest.raises(storage.StorageError) as excinfo:
        storage.save(b"#!/bin/sh\nrm -rf /", "application/x-sh")

    assert excinfo.value.code == "unsupported_type"


def test_a_file_over_the_ceiling_is_refused() -> None:
    oversized = b"a" * (storage.MAX_UPLOAD_BYTES + 1)

    with pytest.raises(storage.StorageError) as excinfo:
        storage.save(oversized, "text/plain")

    assert excinfo.value.code == "file_too_large"


def test_an_empty_file_is_refused() -> None:
    with pytest.raises(storage.StorageError) as excinfo:
        storage.save(b"", "text/plain")

    assert excinfo.value.code == "empty_file"


def test_reading_a_missing_file_raises_rather_than_returning_empty() -> None:
    with pytest.raises(storage.StorageError) as excinfo:
        storage.read("never-written.txt")

    assert excinfo.value.code == "file_missing"


def test_a_traversal_path_cannot_escape_the_storage_root() -> None:
    with pytest.raises(storage.StorageError) as excinfo:
        storage.read("../../ztna.db")

    assert excinfo.value.code == "path_escape"


def test_clear_removes_every_stored_file() -> None:
    storage.save(b"one", "text/plain")
    storage.save(b"two", "text/plain")

    storage.clear()

    assert list(storage.storage_root().iterdir()) == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_storage.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core.storage'`

- [ ] **Step 3: Add the storage setting**

In `backend/app/core/config.py`, inside the `# --- Persistence ---` block, immediately after the `redis_url` line, add:

```python
    #: Where uploaded resource files are written. Kept out of the database so
    #: ztna.db stays small and portable; never served statically.
    resource_storage_dir: Path = ROOT_DIR / "storage" / "resources"
```

- [ ] **Step 4: Write the storage module**

Create `backend/app/core/storage.py`:

```python
"""Resource file storage.

Bytes live on disk rather than in the database: SQLite reads a ``LargeBinary``
fully into memory, and the project's single-file ``ztna.db`` is meant to stay
small enough to copy around.

Two rules hold everywhere in this module:

* the stored filename is always a server-generated UUID, so a hostile upload
  name can never influence a path;
* every read resolves the final path and refuses anything that lands outside
  the storage root.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from app.core.config import settings

#: Hard ceiling on a single upload.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

#: Accepted content types, mapped to the extension the file is stored under.
ALLOWED_CONTENT_TYPES: dict[str, str] = {
    "application/pdf": ".pdf",
    "text/plain": ".txt",
    "text/markdown": ".md",
    "text/csv": ".csv",
    "application/json": ".json",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
}


class StorageError(Exception):
    """Raised when an upload is refused or a stored file cannot be read."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def storage_root() -> Path:
    """The storage directory, created on first use."""
    root = Path(settings.resource_storage_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _resolve(relative_path: str) -> Path:
    """Resolve a stored name against the root, refusing any escape."""
    root = storage_root().resolve()
    candidate = (root / relative_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise StorageError(
            "Refusing to read outside the storage root.", "path_escape"
        )
    return candidate


def save(data: bytes, content_type: str) -> str:
    """Write ``data`` under a generated name and return that name."""
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise StorageError(
            f"Files of type '{content_type}' are not accepted.", "unsupported_type"
        )
    if not data:
        raise StorageError("The uploaded file is empty.", "empty_file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise StorageError(
            f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
            "file_too_large",
        )

    name = f"{uuid.uuid4().hex}{ALLOWED_CONTENT_TYPES[content_type]}"
    (storage_root() / name).write_bytes(data)
    return name


def read(relative_path: str) -> bytes:
    path = _resolve(relative_path)
    if not path.is_file():
        raise StorageError("The stored file is missing.", "file_missing")
    return path.read_bytes()


def delete(relative_path: str) -> None:
    """Remove a stored file. Missing files are not an error."""
    _resolve(relative_path).unlink(missing_ok=True)


def clear() -> None:
    """Remove every stored file. Used by the seeder's ``--reset``."""
    for child in storage_root().iterdir():
        if child.is_file():
            child.unlink()
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_storage.py -v`
Expected: PASS, 7 tests

- [ ] **Step 6: Ignore the storage directory**

Append to `.gitignore`:

```
# Uploaded resource files — content is per-installation, never committed
storage/
```

- [ ] **Step 7: Run the whole suite and commit**

```bash
cd backend && ../.venv/bin/python -m pytest
cd .. && git add backend/app/core/storage.py backend/app/core/config.py backend/tests/test_storage.py .gitignore
git commit -m "Add resource file storage with type, size and path-escape guards"
```

---

### Task 2: Resource content columns and migration 0002

**Files:**
- Modify: `backend/app/models/resource.py`
- Create: `backend/alembic/versions/0002_resource_content.py`
- Create: `backend/tests/test_resource_model.py`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces: `Resource.file_name`, `Resource.file_path`, `Resource.content_type`, `Resource.file_size`, `Resource.uploaded_at`, `Resource.uploaded_by_id`, and the property `Resource.has_file -> bool`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_resource_model.py`:

```python
"""The resource row's file-content fields."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.base import utcnow
from app.models.enums import Sensitivity
from app.models.resource import Resource


def test_a_resource_without_a_file_reports_no_file(db: Session) -> None:
    resource = Resource(
        slug="empty-shelf", name="Empty Shelf", sensitivity=Sensitivity.PUBLIC,
        min_trust_score=Resource.default_min_trust(Sensitivity.PUBLIC),
    )
    db.add(resource)
    db.commit()

    assert resource.has_file is False


def test_a_resource_records_its_attached_file(db: Session) -> None:
    resource = Resource(
        slug="handbook", name="Handbook", sensitivity=Sensitivity.INTERNAL,
        min_trust_score=Resource.default_min_trust(Sensitivity.INTERNAL),
        file_name="handbook.md", file_path="abc123.md",
        content_type="text/markdown", file_size=42, uploaded_at=utcnow(),
    )
    db.add(resource)
    db.commit()

    stored = db.get(Resource, resource.id)
    assert stored is not None
    assert stored.has_file is True
    assert stored.file_name == "handbook.md"
    assert stored.content_type == "text/markdown"
    assert stored.file_size == 42
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_resource_model.py -v`
Expected: FAIL — `TypeError: 'file_name' is an invalid keyword argument for Resource` (and no `has_file` attribute)

- [ ] **Step 3: Add the columns to the model**

In `backend/app/models/resource.py`, extend the imports to:

```python
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean, Enum as SAEnum, ForeignKey, Integer, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import TZDateTime, TimestampMixin, uuid_pk
from app.models.enums import SENSITIVITY_MIN_TRUST, Sensitivity
```

Then, immediately after the `enabled` column, add:

```python
    # --- Attached content --------------------------------------------------
    # Nullable throughout: a resource may legitimately carry no file, and the
    # twelve seeded rows predate this feature.
    #: The uploader's filename, kept only as a display label.
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Server-generated name under the storage root. Never client-supplied.
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uploaded_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
```

And add this property next to `default_min_trust`:

```python
    @property
    def has_file(self) -> bool:
        """Whether there is content to serve, as opposed to metadata only."""
        return bool(self.file_path)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_resource_model.py -v`
Expected: PASS, 2 tests

- [ ] **Step 5: Write the migration**

Create `backend/alembic/versions/0002_resource_content.py`:

```python
"""resource content

Revision ID: 0002_resource_content
Revises: 0001_initial
Create Date: 2026-09-05

Adds the file-content columns to ``resources``. Every column is nullable so
existing rows migrate untouched; a resource with no file is still valid.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_resource_content"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SQLite cannot ALTER a table to add a constraint, so the foreign key has
    # to be created inside a batch operation that rebuilds the table.
    with op.batch_alter_table("resources") as batch:
        batch.add_column(sa.Column("file_name", sa.String(length=255), nullable=True))
        batch.add_column(sa.Column("file_path", sa.String(length=512), nullable=True))
        batch.add_column(sa.Column("content_type", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("file_size", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("uploaded_by_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            "fk_resources_uploaded_by_id_users",
            "users",
            ["uploaded_by_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("resources") as batch:
        batch.drop_constraint("fk_resources_uploaded_by_id_users", type_="foreignkey")
        batch.drop_column("uploaded_by_id")
        batch.drop_column("uploaded_at")
        batch.drop_column("file_size")
        batch.drop_column("content_type")
        batch.drop_column("file_path")
        batch.drop_column("file_name")
```

- [ ] **Step 6: Verify the migration upgrades and downgrades against the real database**

```bash
cd backend
../.venv/bin/alembic upgrade head
../.venv/bin/alembic downgrade -1
../.venv/bin/alembic upgrade head
```
Expected: all three succeed with no error; the final state is at `0002_resource_content`.

- [ ] **Step 7: Run the whole suite and commit**

```bash
cd backend && ../.venv/bin/python -m pytest
cd .. && git add backend/app/models/resource.py backend/alembic/versions/0002_resource_content.py backend/tests/test_resource_model.py
git commit -m "Add file content columns to resources with migration 0002"
```

---

### Task 3: Test fixtures for roles that lack write permission

**Files:**
- Modify: `backend/tests/conftest.py`

**Interfaces:**
- Consumes: the existing `roles`, `db` fixtures
- Produces: a `security_analyst` entry in the `roles` fixture, and an `analyst` user fixture. Later tasks use `analyst` to prove permission gating.

Every later permission test needs a role that is neither admin nor plain employee. The `roles` fixture currently has no `security_analyst`, and its `admin` role carries only device permissions (it passes everything by virtue of `is_admin`).

- [ ] **Step 1: Extend the roles fixture**

In `backend/tests/conftest.py`, inside the `roles` fixture's `rows` dict, after the `"admin"` entry, add:

```python
        "security_analyst": Role(
            name="security_analyst", description="Security analyst", is_admin=False,
            max_sensitivity_ordinal=2,
            permissions=[
                "users:read", "devices:read", "policies:read", "sessions:read",
                "sessions:revoke", "alerts:read", "audit:read", "resources:read",
            ],
        ),
```

- [ ] **Step 2: Add the analyst user fixture**

In `backend/tests/conftest.py`, immediately after the `admin` fixture, add:

```python
@pytest.fixture
def analyst(db: Session, roles: dict[str, Role]) -> User:
    """A read-and-revoke operator: no users:write, no resources:write."""
    row = User(
        username="meera.nair",
        email="meera.nair@ztna-demo.in",
        full_name="Meera Nair",
        department="Information Security",
        hashed_password=hash_password(PASSWORD),
        password_strength=88,
        role_id=roles["security_analyst"].id,
        mfa_enabled=True,
        mfa_secret=mfa.generate_secret(),
    )
    db.add(row)
    db.commit()
    return row
```

- [ ] **Step 3: Verify the fixture resolves**

Run: `cd backend && ../.venv/bin/python -m pytest tests/ -q -k "auth_flow"`
Expected: PASS — existing tests unaffected by the new role.

- [ ] **Step 4: Run the whole suite and commit**

```bash
cd backend && ../.venv/bin/python -m pytest
cd .. && git add backend/tests/conftest.py
git commit -m "Add security_analyst role and analyst fixture for permission tests"
```

---

### Task 4: Resource administration endpoints

**Files:**
- Modify: `backend/app/schemas/access.py`
- Modify: `backend/app/api/resources.py`
- Create: `backend/tests/test_resource_admin.py`

**Interfaces:**
- Consumes: `storage` from Task 1, `Resource.has_file` from Task 2, the `analyst` fixture from Task 3
- Produces: `POST /api/resources`, `PATCH /api/resources/{slug}`, `DELETE /api/resources/{slug}`, and schemas `ResourceCreate`, `ResourceUpdate`. `ResourceOut` gains `has_file`, `file_name`, `content_type`, `file_size`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_resource_admin.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_resource_admin.py -v`
Expected: FAIL — `POST /api/resources` returns 405 Method Not Allowed (no such route).

- [ ] **Step 3: Add the schemas**

In `backend/app/schemas/access.py`, extend `ResourceOut` with the content fields:

```python
class ResourceOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str
    category: str
    sensitivity: str
    min_trust_score: int
    owner: str
    enabled: bool
    has_file: bool = False
    file_name: str | None = None
    content_type: str | None = None
    file_size: int | None = None
```

And add these two models directly after `ResourceReachability`:

```python
class ResourceCreate(BaseModel):
    """A new catalogue entry. The file, if any, is attached separately."""

    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=2, max_length=128)
    description: str = ""
    category: str = Field(default="application", max_length=64)
    sensitivity: str = Field(default="INTERNAL",
                             pattern="^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    owner: str = Field(default="", max_length=96)
    #: Left unset, the sensitivity's own floor is applied.
    min_trust_score: int | None = Field(default=None, ge=0, le=100)


class ResourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=128)
    description: str | None = None
    category: str | None = Field(default=None, max_length=64)
    sensitivity: str | None = Field(
        default=None, pattern="^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$"
    )
    owner: str | None = Field(default=None, max_length=96)
    min_trust_score: int | None = Field(default=None, ge=0, le=100)
    enabled: bool | None = None
```

- [ ] **Step 4: Add the endpoints**

In `backend/app/api/resources.py`, extend the imports:

```python
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from app.core.dependencies import (
    Principal, get_context_bundle, get_principal, require_permission,
)
from app.schemas.access import (
    AccessDecisionOut, AccessRequestOut, ResourceCreate, ResourceOut,
    ResourceReachability, ResourceUpdate,
)
from app.services.audit_service import AuditService
```

Add a serialiser next to the existing helpers:

```python
def _to_out(resource: Resource) -> ResourceOut:
    return ResourceOut(
        id=resource.id,
        slug=resource.slug,
        name=resource.name,
        description=resource.description,
        category=resource.category,
        sensitivity=resource.sensitivity.value,
        min_trust_score=resource.min_trust_score,
        owner=resource.owner,
        enabled=resource.enabled,
        has_file=resource.has_file,
        file_name=resource.file_name,
        content_type=resource.content_type,
        file_size=resource.file_size,
    )
```

Then append the three routes:

```python
@router.post(
    "",
    response_model=ResourceOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a resource (administrators only)",
)
def create_resource(
    payload: ResourceCreate,
    principal: Principal = Depends(require_permission("resources:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> ResourceOut:
    clash = db.scalar(select(Resource).where(Resource.slug == payload.slug))
    if clash is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Slug '{payload.slug}' is already in use."
        )

    sensitivity = Sensitivity(payload.sensitivity)
    resource = Resource(
        slug=payload.slug,
        name=payload.name,
        description=payload.description,
        category=payload.category,
        sensitivity=sensitivity,
        min_trust_score=(
            payload.min_trust_score
            if payload.min_trust_score is not None
            else Resource.default_min_trust(sensitivity)
        ),
        owner=payload.owner,
    )
    db.add(resource)
    db.flush()

    AuditService.record(
        db, action="RESOURCE_CREATED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="resource",
        resource_id=str(resource.id), ip_address=bundle.ip_address,
        payload={"slug": resource.slug, "sensitivity": sensitivity.value,
                 "min_trust_score": resource.min_trust_score},
    )
    return _to_out(resource)


@router.patch(
    "/{slug}", response_model=ResourceOut, summary="Edit a resource"
)
def update_resource(
    slug: str,
    payload: ResourceUpdate,
    principal: Principal = Depends(require_permission("resources:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> ResourceOut:
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")

    changes: dict[str, object] = {}
    for field in ("name", "description", "category", "owner",
                  "min_trust_score", "enabled"):
        value = getattr(payload, field)
        if value is not None and value != getattr(resource, field):
            changes[field] = {"from": getattr(resource, field), "to": value}
            setattr(resource, field, value)

    if payload.sensitivity is not None:
        sensitivity = Sensitivity(payload.sensitivity)
        if sensitivity is not resource.sensitivity:
            changes["sensitivity"] = {
                "from": resource.sensitivity.value, "to": sensitivity.value
            }
            resource.sensitivity = sensitivity

    if not changes:
        raise HTTPException(422, "No changes supplied.")

    db.flush()
    AuditService.record(
        db, action="RESOURCE_UPDATED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="resource",
        resource_id=str(resource.id), ip_address=bundle.ip_address,
        payload={"slug": resource.slug, "changes": changes},
    )
    return _to_out(resource)


@router.delete(
    "/{slug}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable a resource",
)
def disable_resource(
    slug: str,
    principal: Principal = Depends(require_permission("resources:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> Response:
    """Disables rather than deletes: access history references this row, and
    the audit trail has to stay whole."""
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")

    resource.enabled = False
    AuditService.record(
        db, action="RESOURCE_DISABLED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="resource",
        resource_id=str(resource.id), ip_address=bundle.ip_address,
        payload={"slug": resource.slug},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
```

- [ ] **Step 5: Exclude disabled resources from the catalogue**

In the existing `catalogue` endpoint in the same file, inside the `for resource, decision in PolicyEngine.reachable(...)` loop, add this immediately after the existing `sensitivity` filter:

```python
        if not resource.enabled:
            continue
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_resource_admin.py -v`
Expected: PASS, 8 tests

- [ ] **Step 7: Run the whole suite and commit**

```bash
cd backend && ../.venv/bin/python -m pytest
cd .. && git add backend/app/api/resources.py backend/app/schemas/access.py backend/tests/test_resource_admin.py
git commit -m "Add resource create, edit and disable endpoints for administrators"
```

---

### Task 5: File upload

**Files:**
- Modify: `backend/app/api/resources.py`
- Create: `backend/tests/test_resource_upload.py`

**Interfaces:**
- Consumes: `storage.save`, `storage.delete` from Task 1; `_to_out` from Task 4
- Produces: `POST /api/resources/{slug}/file` accepting `multipart/form-data` with a single field named `file`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_resource_upload.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_resource_upload.py -v`
Expected: FAIL — 405 Method Not Allowed on `/api/resources/hr-portal/file`

- [ ] **Step 3: Add the upload endpoint**

In `backend/app/api/resources.py`, add `File` and `UploadFile` to the FastAPI import, add `from pathlib import Path`, `from app.core import storage` and `from app.models.base import utcnow`, then append:

```python
@router.post(
    "/{slug}/file",
    response_model=ResourceOut,
    summary="Attach or replace this resource's file",
)
async def upload_resource_file(
    slug: str,
    file: UploadFile = File(...),
    principal: Principal = Depends(require_permission("resources:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> ResourceOut:
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")

    data = await file.read()
    try:
        stored_name = storage.save(data, file.content_type or "")
    except storage.StorageError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, exc.message
        ) from exc

    previous = resource.file_path
    resource.file_name = Path(file.filename or "file").name
    resource.file_path = stored_name
    resource.content_type = file.content_type
    resource.file_size = len(data)
    resource.uploaded_at = utcnow()
    resource.uploaded_by_id = principal.user.id
    db.flush()

    # Only once the row points at the new file is the old one removed, so a
    # failure above never leaves the row pointing at nothing.
    if previous and previous != stored_name:
        storage.delete(previous)

    AuditService.record(
        db, action="RESOURCE_FILE_UPLOADED", actor_id=principal.user.id,
        actor_label=principal.user.username, resource_type="resource",
        resource_id=str(resource.id), ip_address=bundle.ip_address,
        payload={"slug": resource.slug, "file_name": resource.file_name,
                 "content_type": resource.content_type, "bytes": resource.file_size},
    )
    return _to_out(resource)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_resource_upload.py -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Run the whole suite and commit**

```bash
cd backend && ../.venv/bin/python -m pytest
cd .. && git add backend/app/api/resources.py backend/tests/test_resource_upload.py
git commit -m "Add resource file upload with type, size and filename guards"
```

---

### Task 6: Content delivery through the enforcement point

This is the task the whole plan exists for. The file is never served except as the outcome of a live policy decision.

**Files:**
- Modify: `backend/app/api/resources.py`
- Modify: `backend/app/main.py` (CORS `expose_headers`)
- Create: `backend/tests/test_resource_content.py`

**Interfaces:**
- Consumes: `storage.read` from Task 1, `AccessService.request_access`, `_to_out` from Task 4
- Produces: `GET /api/resources/{slug}/content` returning the bytes with `X-Access-Gate` and `X-Trust-Score` response headers

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_resource_content.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_resource_content.py -v`
Expected: FAIL — 404 on `/api/resources/public-docs/content`, because the route resolves to the existing `GET /{slug}` handler and no content route exists.

- [ ] **Step 3: Add the content endpoint**

In `backend/app/api/resources.py`, add `import logging` and `logger = logging.getLogger(__name__)` near the top if not already present, then add this route **directly above** the existing `get_resource` handler. Order matters: declared after `GET /{slug}`, FastAPI would match `content` as a slug.

```python
@router.get(
    "/{slug}/content",
    summary="View or download — enforced on every single request",
    responses={
        403: {"description": "Refused by clearance, policy or trust"},
        404: {"description": "No such resource, or no file attached"},
    },
)
def resource_content(
    slug: str,
    principal: Principal = Depends(get_principal),
    bundle: ContextBundle = Depends(get_context_bundle),
    db: Session = Depends(get_db),
) -> Response:
    """Stream a resource's file, but only as the outcome of a live decision.

    This calls the same enforcement point as ``POST /{slug}/access``, so the
    session is re-scored against the context of *this* request and the
    decision is written to the access log and the audit chain before any byte
    leaves the server. There is no other route to the stored file.
    """
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")
    if not resource.has_file:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "This resource has no file attached."
        )

    decision, row = AccessService.request_access(
        db,
        user=principal.user,
        session=principal.session,
        resource=resource,
        bundle=bundle,
        device=principal.device,
        method="GET",
    )

    if not decision.granted:
        # Commit before raising: the refusal, the score behind it and the
        # audit record must outlive the 403.
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
            headers={
                "X-Access-Gate": decision.gate or "trust",
                "X-Trust-Score": f"{row.score_at_request:.1f}",
            },
        )

    try:
        data = storage.read(resource.file_path or "")
    except storage.StorageError as exc:
        logger.error(
            "Resource %s points at missing file %s", resource.slug, resource.file_path
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, exc.message
        ) from exc

    return Response(
        content=data,
        media_type=resource.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'inline; filename="{resource.file_name}"',
            "X-Access-Gate": "granted",
            "X-Trust-Score": f"{row.score_at_request:.1f}",
        },
    )
```

- [ ] **Step 4: Expose the decision headers to the browser**

In `backend/app/main.py`, change the CORS `expose_headers` line to:

```python
        expose_headers=["X-Request-ID", "X-Access-Gate", "X-Trust-Score"],
```

Without this the frontend cannot read why a download was refused — the browser hides unlisted response headers from cross-origin JavaScript.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd backend && ../.venv/bin/python -m pytest tests/test_resource_content.py -v`
Expected: PASS, 7 tests

- [ ] **Step 6: Run the whole suite and commit**

```bash
cd backend && ../.venv/bin/python -m pytest
cd .. && git add backend/app/api/resources.py backend/app/main.py backend/tests/test_resource_content.py
git commit -m "Serve resource content only through the policy enforcement point"
```

---

### Task 7: Seeded resources carry real files

**Files:**
- Modify: `scripts/seed_data.py`
- Modify: `scripts/seed.py`

**Interfaces:**
- Consumes: `storage.save`, `storage.clear` from Task 1; the content columns from Task 2
- Produces: every seeded resource has a file; `--reset` clears storage

- [ ] **Step 1: Add sample content to the resource specs**

In `scripts/seed_data.py`, add `file_name`, `content_type` and `body` keys to each of the twelve entries in `RESOURCES`. Use text-family content only — the project carries no PDF renderer and this must not introduce one. The first two entries become:

```python
    {
        "slug": "public-docs", "name": "Public Documentation Portal",
        "description": "Externally published product documentation and policies.",
        "category": "website", "sensitivity": "PUBLIC", "owner": "Marketing",
        "file_name": "product-documentation.md",
        "content_type": "text/markdown",
        "body": (
            "# Product Documentation\n\n"
            "Publicly published guides, release notes and policy summaries.\n\n"
            "## Contents\n\n"
            "- Getting started\n- Release notes\n- Acceptable use policy\n"
        ),
    },
    {
        "slug": "company-intranet", "name": "Company Intranet",
        "description": "Announcements, holiday calendar and internal directory.",
        "category": "website", "sensitivity": "PUBLIC", "owner": "Human Resources",
        "file_name": "announcements.md",
        "content_type": "text/markdown",
        "body": (
            "# Company Intranet\n\n"
            "## This week\n\n"
            "- Quarterly all-hands on Friday\n"
            "- Holiday calendar published for the next quarter\n"
        ),
    },
```

Apply the same shape to the remaining ten, matching each resource's nature: `hr-portal` a Markdown leave policy, `ticketing-system` a CSV of open tickets, `wiki-engineering` a Markdown runbook index, `source-repo` a Markdown repository layout, `build-pipeline` a JSON pipeline definition (`"content_type": "application/json"`), `crm-database` a CSV of accounts, `finance-reports` a CSV ledger extract, `payroll-db` a CSV salary register, `customer-pii-store` a CSV of synthetic KYC records, `prod-secrets-vault` a Markdown index naming secrets without values. Use `"text/csv"` for CSV bodies and `"text/markdown"` for Markdown.

- [ ] **Step 2: Write the files during seeding**

In `scripts/seed.py`, add near the other `app.` imports:

```python
from app.core import storage  # noqa: E402
```

Then in the resource-creation block around line 216, attach the file to each row. Keep every key the existing dict already sets and add the six new ones:

```python
                stored_name = storage.save(
                    spec["body"].encode("utf-8"), spec["content_type"]
                )
                rows.append({
                    "id": uuid.uuid4(), "slug": spec["slug"], "name": spec["name"],
                    # ... keep every existing key exactly as it is ...
                    "file_name": spec["file_name"],
                    "file_path": stored_name,
                    "content_type": spec["content_type"],
                    "file_size": len(spec["body"].encode("utf-8")),
                    "uploaded_at": utcnow(),
                    "uploaded_by_id": None,
                })
```

If `utcnow` is not already imported in the seeder, add `from app.models.base import utcnow`.

- [ ] **Step 3: Clear storage on reset**

In `scripts/seed.py`, in the truncation function that iterates `TABLES_IN_DELETE_ORDER` (around line 190), add after its `db.commit()`:

```python
    # Files and rows must not drift apart: a reset that left orphaned files
    # behind would grow the storage directory on every run.
    storage.clear()
```

- [ ] **Step 4: Reseed and verify the files land**

```bash
cd /Users/sivabalan/Documents/ztna-project
.venv/bin/python scripts/seed.py --reset
ls storage/resources | head
.venv/bin/python -c "
import sys; sys.path.insert(0, 'backend')
from sqlalchemy import select
from app.core.database import SessionLocal
from app.models.resource import Resource
with SessionLocal() as db:
    for r in db.scalars(select(Resource).order_by(Resource.slug)):
        print(f'{r.slug:22} {str(r.has_file):5} {r.file_size} bytes  {r.content_type}')
"
```
Expected: twelve rows, all `True`, each with a non-zero size.

- [ ] **Step 5: Run the whole suite and commit**

```bash
cd backend && ../.venv/bin/python -m pytest
cd .. && git add scripts/seed.py scripts/seed_data.py
git commit -m "Seed every resource with real file content and clear storage on reset"
```

---

# Phase B — Frontend: shared plumbing

### Task 8: API client additions

**Files:**
- Modify: `frontend/src/api/client.ts`

**Interfaces:**
- Consumes: the endpoints from Tasks 4–6
- Produces: types `ResourceSummary`, `ResourceReachability`, `PolicyEvaluation`, `AccessDecision`, `AccessHistoryRow`, `PolicyRow`, `ResourceContent`; functions `getResources`, `requestAccess`, `getResourceContent`, `getAccessHistory`, `getMySessions`, `createResource`, `updateResource`, `disableResource`, `uploadResourceFile`, `getPolicies`, `createPolicy`, `updatePolicy`, `deletePolicy`, `blobErrorMessage`

- [ ] **Step 1: Add the types**

In `frontend/src/api/client.ts`, in the types section after `TrustConfig`, add:

```typescript
export interface ResourceSummary {
  id: string;
  slug: string;
  name: string;
  description: string;
  category: string;
  sensitivity: string;
  min_trust_score: number;
  owner: string;
  enabled: boolean;
  has_file: boolean;
  file_name: string | null;
  content_type: string | null;
  file_size: number | null;
}

export interface ResourceReachability extends ResourceSummary {
  reachable: boolean;
  action: string;
  reason: string;
  gate: string;
  required_score: number;
  matched_policy: string;
}

export interface PolicyEvaluation {
  name: string;
  effect: string;
  priority: number;
  matched: boolean;
  decisive: boolean;
  unmet_conditions: string[];
}

export interface AccessDecision {
  resource: string;
  sensitivity: string;
  granted: boolean;
  action: string;
  reason: string;
  gate: string;
  matched_policy: string;
  required_score: number;
  trust_score: number;
  risk_level: string;
  latency_ms: number;
  policies_evaluated: PolicyEvaluation[];
}

export interface AccessHistoryRow {
  id: string;
  requested_at: string;
  resource: string | null;
  path: string;
  score_at_request: number;
  risk_level: string;
  decision: string;
  granted: boolean;
  reason: string;
  matched_policy: string;
  latency_ms: number;
}

export interface PolicyRow {
  id: string;
  name: string;
  description: string;
  role: string | null;
  resource: string | null;
  sensitivity: string | null;
  min_trust_score: number;
  require_mfa: boolean;
  require_known_device: boolean;
  deny_vpn: boolean;
  allowed_countries: string[];
  time_window: Record<string, unknown>;
  effect: string;
  priority: number;
  enabled: boolean;
}

/** A fetched file plus the decision headers that allowed it through. */
export interface ResourceContent {
  blob: Blob;
  contentType: string;
  trustScore: number | null;
}
```

- [ ] **Step 2: Add the calls**

Append to the calls section of the same file:

```typescript
// --- resources --------------------------------------------------------------

export const getResources = () =>
  api.get<ResourceReachability[]>("/api/resources").then((r) => r.data);

export const requestAccess = (slug: string) =>
  api.post<AccessDecision>(`/api/resources/${slug}/access`).then((r) => r.data);

/**
 * Fetches a resource's file. The Authorization header rules out a plain
 * anchor download, so the bytes come back as a blob and the caller decides
 * whether to preview or save them.
 */
export const getResourceContent = (slug: string): Promise<ResourceContent> =>
  api
    .get(`/api/resources/${slug}/content`, { responseType: "blob" })
    .then((r) => ({
      blob: r.data as Blob,
      contentType: String(r.headers["content-type"] ?? "application/octet-stream"),
      trustScore: r.headers["x-trust-score"]
        ? Number(r.headers["x-trust-score"])
        : null,
    }));

export const getAccessHistory = (limit = 50) =>
  api
    .get<AccessHistoryRow[]>(`/api/resources/access/history?limit=${limit}`)
    .then((r) => r.data);

export const getMySessions = () =>
  api.get<LiveSession[]>("/api/sessions/me").then((r) => r.data);

export const createResource = (body: Record<string, unknown>) =>
  api.post<ResourceSummary>("/api/resources", body).then((r) => r.data);

export const updateResource = (slug: string, body: Record<string, unknown>) =>
  api.patch<ResourceSummary>(`/api/resources/${slug}`, body).then((r) => r.data);

export const disableResource = (slug: string) =>
  api.delete(`/api/resources/${slug}`);

export const uploadResourceFile = (slug: string, file: File) => {
  const form = new FormData();
  form.append("file", file);
  return api
    .post<ResourceSummary>(`/api/resources/${slug}/file`, form)
    .then((r) => r.data);
};

// --- policies ---------------------------------------------------------------

export const getPolicies = () =>
  api.get<PolicyRow[]>("/api/policies").then((r) => r.data);

export const createPolicy = (body: Record<string, unknown>) =>
  api.post<PolicyRow>("/api/policies", body).then((r) => r.data);

export const updatePolicy = (id: string, body: Record<string, unknown>) =>
  api.patch<PolicyRow>(`/api/policies/${id}`, body).then((r) => r.data);

export const deletePolicy = (id: string) => api.delete(`/api/policies/${id}`);
```

`LiveSession` is already exported from this file by the operator console; reuse it rather than declaring a second session type.

- [ ] **Step 3: Decode blob error bodies**

An axios error for a `responseType: "blob"` request carries its `detail` inside a Blob, so `apiErrorMessage` cannot read it. Add below `apiErrorMessage` in the same file:

```typescript
/**
 * Reads the `detail` out of a failed blob request. A denial's reason arrives
 * as a Blob rather than parsed JSON, so it needs decoding before display.
 */
export async function blobErrorMessage(
  error: unknown,
  fallback: string,
): Promise<string> {
  if (axios.isAxiosError(error) && error.response?.data instanceof Blob) {
    try {
      const parsed = JSON.parse(await error.response.data.text());
      if (parsed?.detail) return String(parsed.detail);
    } catch {
      /* not JSON; fall through to the generic message */
    }
  }
  return apiErrorMessage(error, fallback);
}
```

- [ ] **Step 4: Type-check and commit**

```bash
cd frontend && npm run lint
cd .. && git add frontend/src/api/client.ts
git commit -m "Add resource, access and policy calls to the API client"
```

---

### Task 9: Permission hook

**Files:**
- Create: `frontend/src/auth/usePermissions.ts`

**Interfaces:**
- Consumes: `useAuth()` from `frontend/src/auth/AuthContext.tsx`
- Produces: `usePermissions(): { can: (permission: string) => boolean; isAdmin: boolean; isOperator: boolean }`

- [ ] **Step 1: Write the hook**

Create `frontend/src/auth/usePermissions.ts`:

```typescript
import { useMemo } from "react";
import { useAuth } from "./AuthContext";

/**
 * What the signed-in role may actually do.
 *
 * The server is the authority — every route re-checks the permission — but the
 * console must not offer a control the caller's role will be refused for. A
 * security_analyst seeing an "Approve device" button that always fails is a
 * worse experience than not seeing it at all.
 */
export function usePermissions() {
  const { me } = useAuth();

  return useMemo(() => {
    const granted = new Set(me?.permissions ?? []);
    const isAdmin = Boolean(me?.is_admin);
    return {
      isAdmin,
      isOperator: isAdmin || me?.role === "security_analyst",
      can: (permission: string) => isAdmin || granted.has(permission),
    };
  }, [me]);
}
```

- [ ] **Step 2: Type-check and commit**

```bash
cd frontend && npm run lint
cd .. && git add frontend/src/auth/usePermissions.ts
git commit -m "Add a permission hook so controls match what the role may do"
```

---

# Phase C — Frontend: the non-operator portal

Tasks 10–14 are written and committed together, because `App.tsx` references every portal page. Implement them in order, then type-check once at the end of Task 14.

### Task 10: Portal shell and routing

**Files:**
- Create: `frontend/src/components/layout/PortalShell.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/pages/SessionPage.tsx`

**Interfaces:**
- Consumes: `useAuth`, `useLive`
- Produces: `PortalShell`, and routes `/`, `/session`, `/devices`, `/activity`, `/trust` for non-operator roles

- [ ] **Step 1: Write the portal shell**

Create `frontend/src/components/layout/PortalShell.tsx`:

```tsx
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import { useLive } from "../../live/LiveContext";

const NAV = [
  { to: "/", label: "My Access", end: true },
  { to: "/session", label: "My Session" },
  { to: "/devices", label: "My Devices" },
  { to: "/activity", label: "My Activity" },
  { to: "/trust", label: "Trust & Policy" },
];

/** The shell for employees and contractors. Every entry is a real screen. */
export default function PortalShell() {
  const { me, signOut } = useAuth();
  const { status } = useLive();

  return (
    <div className="flex min-h-full">
      <aside className="flex w-60 shrink-0 flex-col bg-shell p-5 text-slate-300">
        <div>
          <div className="text-lg font-semibold text-white">ZTNA</div>
          <div className="mt-0.5 text-xs text-slate-400">Adaptive Trust Scoring</div>
        </div>

        <div className="mt-6 rounded-lg bg-shell-soft p-3">
          <div className="truncate text-sm font-medium text-white">
            {me?.full_name}
          </div>
          <div className="truncate text-xs text-slate-400">
            {me?.username} · {me?.role}
          </div>
        </div>

        <nav className="mt-5 flex-1 space-y-0.5 text-sm">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `block rounded px-3 py-2 transition ${
                  isActive
                    ? "bg-shell-soft text-white"
                    : "text-slate-400 hover:bg-shell-soft/60 hover:text-slate-200"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="mt-4 flex items-center gap-2 px-3 text-xs text-slate-400">
          <span
            className={`inline-block h-2 w-2 rounded-full ${
              status === "open"
                ? "bg-risk-low"
                : status === "connecting"
                  ? "bg-risk-medium"
                  : "bg-risk-critical"
            }`}
            aria-hidden
          />
          {status === "open" ? "live stream connected" : `stream ${status}`}
        </div>

        <button
          onClick={signOut}
          className="mt-3 w-full rounded-lg border border-slate-600 px-3 py-2 text-sm text-slate-300 hover:bg-shell-soft"
        >
          Sign out
        </button>
      </aside>

      <main className="flex-1 overflow-auto bg-slate-50">
        <Outlet />
      </main>
    </div>
  );
}
```

- [ ] **Step 2: Strip the private sidebar out of SessionPage**

In `frontend/src/pages/SessionPage.tsx`, delete the entire `<aside>` element (the sidebar holding the "Available in Phase 9" placeholders) and the `<div className="flex min-h-full">` that wraps it. Delete the `devices` state, its `useEffect`, the `getMyDevices` and `DeviceInfo` imports, and the whole "Registered devices" table — that content moves to `MyDevicesPage` in Task 12. Remove `signOut` from the `useAuth()` destructure. The return becomes:

```tsx
  return (
    <div className="p-8">
      <div className="flex items-start justify-between gap-6">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">
            Authenticated session
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Password and TOTP both verified. This session is re-checked on
            every request.
          </p>
        </div>
        <div
          className={`rounded-full px-4 py-2 text-sm font-medium ring-1 ring-inset ${
            RISK_STYLES[session.current_risk_level] ?? RISK_STYLES.LOW
          }`}
        >
          Session {session.current_risk_level}
        </div>
      </div>

      <div className="mt-8">
        <TrustPanel />
      </div>

      <h2 className="mt-8 text-sm font-semibold text-slate-900">Session</h2>
      {/* keep the existing <dl> of Field components exactly as it is */}

      <button
        onClick={refreshMe}
        className="mt-6 rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
      >
        Re-verify this session
      </button>
    </div>
  );
```

- [ ] **Step 3: Route non-operators into the portal**

In `frontend/src/App.tsx`, add these imports:

```tsx
import PortalShell from "./components/layout/PortalShell";
import MyAccessPage from "./pages/portal/MyAccessPage";
import MyActivityPage from "./pages/portal/MyActivityPage";
import MyDevicesPage from "./pages/portal/MyDevicesPage";
import MyTrustPage from "./pages/portal/MyTrustPage";
import PoliciesPage from "./pages/PoliciesPage";
import ResourcesAdminPage from "./pages/ResourcesAdminPage";
```

and replace the `return` inside `Gate()` with:

```tsx
  return (
    <LiveProvider>
      {isOperator ? (
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<OverviewPage />} />
            <Route path="users" element={<UsersPage />} />
            <Route path="resources" element={<ResourcesAdminPage />} />
            <Route path="policies" element={<PoliciesPage />} />
            <Route path="live" element={<LiveMonitoringPage />} />
            <Route path="risk" element={<RiskScoresPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="trust" element={<TrustScorePage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="revocation" element={<RevocationPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      ) : (
        <Routes>
          <Route element={<PortalShell />}>
            <Route index element={<MyAccessPage />} />
            <Route path="session" element={<SessionPage />} />
            <Route path="devices" element={<MyDevicesPage />} />
            <Route path="activity" element={<MyActivityPage />} />
            <Route path="trust" element={<MyTrustPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      )}
    </LiveProvider>
  );
```

The six imported page modules are created in Tasks 11–14 and 16–17. The tree will not compile until then; that is expected. Do not run the type-check or commit until Task 14.

---

### Task 11: My Access page

**Files:**
- Create: `frontend/src/pages/portal/MyAccessPage.tsx`

**Interfaces:**
- Consumes: `getResources`, `requestAccess`, `getResourceContent`, `blobErrorMessage`, types `AccessDecision`, `ResourceContent`, `ResourceReachability` from Task 8
- Produces: default-exported `MyAccessPage`

- [ ] **Step 1: Write the page**

Create `frontend/src/pages/portal/MyAccessPage.tsx`:

```tsx
import { useCallback, useEffect, useState } from "react";
import {
  blobErrorMessage, getResourceContent, getResources, requestAccess,
  type AccessDecision, type ResourceContent, type ResourceReachability,
} from "../../api/client";
import Page, { Card, Empty } from "../../components/layout/Page";

const TIERS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];

const TIER_STYLES: Record<string, string> = {
  PUBLIC: "bg-slate-100 text-slate-700",
  INTERNAL: "bg-sky-50 text-sky-800",
  CONFIDENTIAL: "bg-amber-50 text-amber-800",
  RESTRICTED: "bg-red-50 text-red-800",
};

function humanSize(bytes: number | null): string {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Renders a fetched file: text inline, PDFs and images natively, else save. */
function ContentView({
  content, fileName,
}: {
  content: ResourceContent;
  fileName: string;
}) {
  const [text, setText] = useState<string | null>(null);
  const [url, setUrl] = useState<string>("");

  useEffect(() => {
    const objectUrl = URL.createObjectURL(content.blob);
    setUrl(objectUrl);
    const isText =
      content.contentType.startsWith("text/") ||
      content.contentType === "application/json";
    if (isText) content.blob.text().then(setText);
    else setText(null);
    return () => URL.revokeObjectURL(objectUrl);
  }, [content]);

  return (
    <div className="mt-4">
      {text !== null ? (
        <pre className="max-h-96 overflow-auto rounded-lg border border-slate-200 bg-slate-50 p-4 text-xs text-slate-800">
          {text}
        </pre>
      ) : content.contentType.startsWith("image/") ? (
        <img
          src={url}
          alt={fileName}
          className="max-h-96 rounded-lg border border-slate-200"
        />
      ) : content.contentType === "application/pdf" ? (
        <object
          data={url}
          type="application/pdf"
          className="h-96 w-full rounded-lg border border-slate-200"
        >
          <p className="p-4 text-sm text-slate-600">
            This browser will not display the PDF inline. Use Download instead.
          </p>
        </object>
      ) : (
        <p className="text-sm text-slate-600">
          This file type cannot be previewed. Use Download to save it.
        </p>
      )}

      <a
        href={url}
        download={fileName}
        className="mt-3 inline-block rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
      >
        Download {fileName}
      </a>
    </div>
  );
}

/** The decision the enforcement point returned, shown in full. */
function DecisionPanel({ decision }: { decision: AccessDecision }) {
  return (
    <div
      className={`mt-4 rounded-lg p-4 text-sm ring-1 ring-inset ${
        decision.granted
          ? "bg-emerald-50 text-emerald-900 ring-emerald-600/20"
          : "bg-red-50 text-red-900 ring-red-600/20"
      }`}
    >
      <div className="font-medium">
        {decision.granted ? "Access granted" : "Access denied"}
      </div>
      <p className="mt-1">{decision.reason}</p>
      <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
        <div>
          <dt className="text-slate-500">Deciding gate</dt>
          <dd className="font-medium">{decision.gate || "—"}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Your score</dt>
          <dd className="font-mono font-medium">{decision.trust_score.toFixed(1)}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Required</dt>
          <dd className="font-mono font-medium">{decision.required_score}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Decided in</dt>
          <dd className="font-mono font-medium">
            {decision.latency_ms.toFixed(1)} ms
          </dd>
        </div>
      </dl>
      {decision.policies_evaluated.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-slate-600">
            {decision.policies_evaluated.length} policies evaluated
          </summary>
          <ul className="mt-2 space-y-1 text-xs">
            {decision.policies_evaluated.map((policy) => (
              <li key={policy.name} className="flex justify-between gap-4">
                <span className={policy.decisive ? "font-semibold" : ""}>
                  {policy.name} · {policy.effect}
                </span>
                <span className="text-slate-500">
                  {policy.matched ? "matched" : "not matched"}
                  {policy.unmet_conditions.length > 0 &&
                    ` — ${policy.unmet_conditions.join(", ")}`}
                </span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

/**
 * What this account can reach right now.
 *
 * Reachability is not a stored property: the server re-scores the session for
 * every entry in this list, so the same catalogue answers differently from a
 * different device, network or hour.
 */
export default function MyAccessPage() {
  const [resources, setResources] = useState<ResourceReachability[]>([]);
  const [openSlug, setOpenSlug] = useState<string>("");
  const [decision, setDecision] = useState<AccessDecision | null>(null);
  const [content, setContent] = useState<ResourceContent | null>(null);
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getResources().then(setResources).catch(() => setResources([]));
  }, []);

  useEffect(load, [load]);

  async function open(resource: ResourceReachability) {
    setOpenSlug(resource.slug);
    setDecision(null);
    setContent(null);
    setError("");
    setBusy(true);
    try {
      setDecision(await requestAccess(resource.slug));
      if (resource.has_file) {
        setContent(await getResourceContent(resource.slug));
      }
    } catch (err) {
      setError(await blobErrorMessage(err, "Access was refused."));
    } finally {
      setBusy(false);
      load();
    }
  }

  return (
    <Page
      title="My access"
      description="Every resource is re-evaluated against your live trust score. Opening one is a policy decision, recorded in the audit log."
      actions={
        <button
          onClick={load}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
        >
          Refresh
        </button>
      }
    >
      {resources.length === 0 ? (
        <Empty>No resources are published yet.</Empty>
      ) : (
        TIERS.filter((tier) => resources.some((r) => r.sensitivity === tier)).map(
          (tier) => (
            <div key={tier} className="mb-4">
              <Card title={`${tier.charAt(0)}${tier.slice(1).toLowerCase()}`}>
                <ul className="divide-y divide-slate-100">
                  {resources
                    .filter((resource) => resource.sensitivity === tier)
                    .map((resource) => (
                      <li key={resource.id} className="py-3">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-slate-900">
                                {resource.name}
                              </span>
                              <span
                                className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                                  TIER_STYLES[resource.sensitivity] ?? ""
                                }`}
                              >
                                {resource.sensitivity}
                              </span>
                              <span
                                className={`text-xs ${
                                  resource.reachable
                                    ? "text-emerald-700"
                                    : "text-risk-critical"
                                }`}
                              >
                                {resource.reachable ? "reachable" : "blocked"}
                              </span>
                            </div>
                            <p className="mt-0.5 text-xs text-slate-600">
                              {resource.description}
                            </p>
                            <p className="mt-0.5 text-xs text-slate-400">
                              {resource.owner} · needs {resource.required_score}
                              {resource.has_file
                                ? ` · ${resource.file_name} ${humanSize(resource.file_size)}`
                                : " · no file attached"}
                            </p>
                            {!resource.reachable && (
                              <p className="mt-1 text-xs text-slate-600">
                                {resource.reason}
                              </p>
                            )}
                          </div>
                          <button
                            onClick={() => open(resource)}
                            disabled={busy && openSlug === resource.slug}
                            className="shrink-0 rounded-lg bg-shell px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
                          >
                            {busy && openSlug === resource.slug
                              ? "Checking…"
                              : "Open"}
                          </button>
                        </div>

                        {openSlug === resource.slug && (
                          <>
                            {decision && <DecisionPanel decision={decision} />}
                            {error && (
                              <div className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-risk-critical">
                                {error}
                              </div>
                            )}
                            {content && (
                              <ContentView
                                content={content}
                                fileName={resource.file_name ?? resource.slug}
                              />
                            )}
                          </>
                        )}
                      </li>
                    ))}
                </ul>
              </Card>
            </div>
          ),
        )
      )}
    </Page>
  );
}
```

---

### Task 12: My Devices page

**Files:**
- Create: `frontend/src/pages/portal/MyDevicesPage.tsx`

**Interfaces:**
- Consumes: `getMyDevices`, type `DeviceInfo` from the API client
- Produces: default-exported `MyDevicesPage`

- [ ] **Step 1: Write the page**

Create `frontend/src/pages/portal/MyDevicesPage.tsx`:

```tsx
import { useEffect, useState } from "react";
import { getMyDevices, type DeviceInfo } from "../../api/client";
import Page, { Card, Empty } from "../../components/layout/Page";

const STATUS_STYLES: Record<string, string> = {
  APPROVED: "text-emerald-700",
  PENDING: "text-amber-700",
  REVOKED: "text-risk-critical",
  BLOCKED: "text-risk-critical",
};

/**
 * The devices this account has signed in from.
 *
 * Device standing is not cosmetic: an unrecognised fingerprint costs trust
 * score, which is often what puts a higher-sensitivity resource out of reach.
 */
export default function MyDevicesPage() {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);

  useEffect(() => {
    getMyDevices().then(setDevices).catch(() => setDevices([]));
  }, []);

  const pending = devices.filter((device) => device.status === "PENDING").length;

  return (
    <Page
      title="My devices"
      description="Every device you have signed in from. An unapproved device lowers your trust score until an administrator approves it."
    >
      {pending > 0 && (
        <div className="mb-4 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900">
          {pending === 1
            ? "One of your devices is awaiting administrator approval."
            : `${pending} of your devices are awaiting administrator approval.`}{" "}
          Until then your trust score carries a device penalty.
        </div>
      )}

      <Card title={`Registered devices (${devices.length})`}>
        {devices.length === 0 ? (
          <Empty>No devices registered.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Device</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Times seen</th>
                  <th className="px-3 py-2 font-medium">First seen</th>
                  <th className="px-3 py-2 font-medium">Last used</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {devices.map((device) => (
                  <tr key={device.id}>
                    <td className="px-3 py-2">
                      <div className="font-medium text-slate-900">{device.label}</div>
                      <div className="font-mono text-[11px] text-slate-400">
                        {device.fingerprint.slice(0, 24)}…
                      </div>
                    </td>
                    <td className={`px-3 py-2 ${STATUS_STYLES[device.status] ?? ""}`}>
                      {device.status}
                    </td>
                    <td className="px-3 py-2 text-slate-600">{device.seen_count}×</td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {new Date(device.first_seen_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {new Date(device.last_seen_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </Page>
  );
}
```

---

### Task 13: My Activity page

**Files:**
- Create: `frontend/src/pages/portal/MyActivityPage.tsx`

**Interfaces:**
- Consumes: `getAccessHistory`, `getMySessions`, types `AccessHistoryRow`, `LiveSession` from Task 8
- Produces: default-exported `MyActivityPage`

- [ ] **Step 1: Write the page**

Create `frontend/src/pages/portal/MyActivityPage.tsx`:

```tsx
import { useEffect, useState } from "react";
import {
  getAccessHistory, getMySessions,
  type AccessHistoryRow, type LiveSession,
} from "../../api/client";
import Page, { Card, Empty, RiskChip } from "../../components/layout/Page";

/**
 * This account's own record: what it asked for, what was decided, and where
 * it is signed in. The same evidence an analyst sees, scoped to one user.
 */
export default function MyActivityPage() {
  const [history, setHistory] = useState<AccessHistoryRow[]>([]);
  const [sessions, setSessions] = useState<LiveSession[]>([]);

  useEffect(() => {
    getAccessHistory(100).then(setHistory).catch(() => setHistory([]));
    getMySessions().then(setSessions).catch(() => setSessions([]));
  }, []);

  const denied = history.filter((row) => !row.granted).length;

  return (
    <Page
      title="My activity"
      description="Every access decision made about this account, and every session it currently holds."
    >
      <Card title={`Access decisions (${history.length}, ${denied} refused)`}>
        {history.length === 0 ? (
          <Empty>No access attempts recorded yet.</Empty>
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="sticky top-0 bg-white text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">When</th>
                  <th className="px-3 py-2 font-medium">Resource</th>
                  <th className="px-3 py-2 font-medium">Score</th>
                  <th className="px-3 py-2 font-medium">Outcome</th>
                  <th className="px-3 py-2 font-medium">Why</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {history.map((row) => (
                  <tr key={row.id}>
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-600">
                      {new Date(row.requested_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-slate-900">{row.resource ?? "—"}</td>
                    <td className="px-3 py-2">
                      <RiskChip level={row.risk_level} score={row.score_at_request} />
                    </td>
                    <td
                      className={`px-3 py-2 text-xs font-medium ${
                        row.granted ? "text-emerald-700" : "text-risk-critical"
                      }`}
                    >
                      {row.granted ? "allowed" : "denied"}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-700">{row.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="mt-4">
        <Card title={`My sessions (${sessions.length})`}>
          {sessions.length === 0 ? (
            <Empty>No sessions found.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">Started</th>
                    <th className="px-3 py-2 font-medium">Device</th>
                    <th className="px-3 py-2 font-medium">Where</th>
                    <th className="px-3 py-2 font-medium">Score</th>
                    <th className="px-3 py-2 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {sessions.map((session) => (
                    <tr key={session.id}>
                      <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-600">
                        {new Date(session.started_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-700">
                        {session.device_label ?? "—"}
                        {session.device_status && (
                          <span className="ml-1 text-slate-400">
                            ({session.device_status})
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-600">
                        {session.ip_address}
                        {session.city && ` · ${session.city}`}
                      </td>
                      <td className="px-3 py-2">
                        <RiskChip
                          level={session.current_risk_level}
                          score={session.current_trust_score}
                        />
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-600">
                        {session.status}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </Page>
  );
}
```

---

### Task 14: Trust & Policy page, and portal verification

**Files:**
- Create: `frontend/src/pages/portal/MyTrustPage.tsx`

**Interfaces:**
- Consumes: `getTrustConfig`, `getMyTrust`, `evaluateMyTrust`, types `TrustConfig`, `TrustAssessment` from the API client
- Produces: default-exported `MyTrustPage`. Completes the portal, so Tasks 10–14 are type-checked and committed here.

- [ ] **Step 1: Write the page**

Create `frontend/src/pages/portal/MyTrustPage.tsx`:

```tsx
import { useEffect, useState } from "react";
import {
  evaluateMyTrust, getMyTrust, getTrustConfig,
  type TrustAssessment, type TrustConfig,
} from "../../api/client";
import Page, { Card, Empty } from "../../components/layout/Page";

/**
 * Why this account's score is what it is, and what would change it.
 *
 * The weights and bands are read from the server rather than restated here,
 * so the explanation cannot drift from the engine that produced the score.
 */
export default function MyTrustPage() {
  const [config, setConfig] = useState<TrustConfig | null>(null);
  const [assessment, setAssessment] = useState<TrustAssessment | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getTrustConfig().then(setConfig).catch(() => setConfig(null));
    getMyTrust().then(setAssessment).catch(() => setAssessment(null));
  }, []);

  async function recheck() {
    setBusy(true);
    try {
      setAssessment(await evaluateMyTrust());
    } finally {
      setBusy(false);
    }
  }

  const band = config?.bands.find(
    (b) => assessment && assessment.score >= b.min && assessment.score <= b.max,
  );
  const nextBand = config?.bands
    .filter((b) => assessment && b.min > assessment.score)
    .sort((a, b) => a.min - b.min)[0];

  return (
    <Page
      title="Trust & policy"
      description="How your score is calculated, what it currently is, and what would move it."
      actions={
        <button
          onClick={recheck}
          disabled={busy}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm disabled:opacity-50"
        >
          {busy ? "Re-checking…" : "Re-check now"}
        </button>
      }
    >
      <Card title="Your score right now">
        {assessment === null ? (
          <Empty>No score available yet.</Empty>
        ) : (
          <>
            <div className="flex flex-wrap items-baseline gap-3">
              <span className="font-mono text-3xl font-semibold text-slate-900">
                {assessment.score.toFixed(1)}
              </span>
              <span className="text-sm font-medium text-slate-700">
                {assessment.risk_level}
              </span>
              <span className="text-sm text-slate-500">{assessment.headline}</span>
            </div>
            {band && <p className="mt-2 text-sm text-slate-600">{band.description}</p>}
            {nextBand && (
              <p className="mt-1 text-sm text-slate-600">
                Reaching <span className="font-medium">{nextBand.level}</span> needs{" "}
                {(nextBand.min - assessment.score).toFixed(1)} more points — most
                often earned by having this device approved and signing in from a
                familiar network at a usual hour.
              </p>
            )}
          </>
        )}
      </Card>

      <div className="mt-4">
        <Card title="What each factor is worth">
          {config === null ? (
            <Empty>Configuration unavailable.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {Object.entries(config.weights).map(([factor, weight]) => {
                const scored = assessment?.factors.find((f) => f.factor === factor);
                return (
                  <li
                    key={factor}
                    className="flex items-baseline justify-between gap-4 py-2"
                  >
                    <span className="capitalize text-slate-900">{factor}</span>
                    <span className="text-xs text-slate-500">
                      worth {weight} points
                      {scored && scored.points_deducted > 0.05 && (
                        <span className="ml-2 text-risk-critical">
                          −{scored.points_deducted.toFixed(1)} now: {scored.reason}
                        </span>
                      )}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4">
        <Card title="What each band allows">
          {config === null ? (
            <Empty>Configuration unavailable.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {config.bands.map((b) => (
                <li
                  key={b.level}
                  className="flex items-baseline justify-between gap-4 py-2"
                >
                  <span className="font-medium text-slate-900">{b.level}</span>
                  <span className="text-xs text-slate-600">
                    {b.min}–{b.max} · {b.description}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4">
        <Card title="Trust required per sensitivity">
          {config === null ? (
            <Empty>Configuration unavailable.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {Object.entries(config.sensitivity_floors).map(([tier, floor]) => (
                <li
                  key={tier}
                  className="flex items-baseline justify-between gap-4 py-2"
                >
                  <span className="text-slate-900">{tier}</span>
                  <span className="font-mono text-xs text-slate-600">
                    needs {floor}
                    {assessment && assessment.score < floor && " — out of reach now"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </Page>
  );
}
```

- [ ] **Step 2: Type-check the portal**

Run: `cd frontend && npm run lint`
Expected: errors only for the two not-yet-created operator pages (`ResourcesAdminPage`, `PoliciesPage`). Temporarily comment out those two imports and their two `<Route>` lines in `App.tsx`, re-run, and confirm zero errors. Restore them before Task 16.

- [ ] **Step 3: Verify in the browser as an employee**

Start both servers:

```bash
cd backend && ../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```
In a second terminal: `cd frontend && npm run dev`. Sign in at http://localhost:5173 as `arjun.krishnan` / `Ztna@Demo2026`, code from `.venv/bin/python scripts/totp.py arjun.krishnan`.

Confirm: all five nav entries load real screens; My Access lists twelve resources grouped by sensitivity; opening a PUBLIC resource shows a granted decision and previews its Markdown; opening a RESTRICTED resource shows a denial naming the gate; My Activity lists both attempts.

- [ ] **Step 4: Commit Tasks 10–14 together**

```bash
git add frontend/src/components/layout/PortalShell.tsx frontend/src/pages/portal/ frontend/src/App.tsx frontend/src/pages/SessionPage.tsx
git commit -m "Replace the placeholder screen with a five-page portal for employees and contractors"
```

---

# Phase D — Frontend: operator console

### Task 15: Gate operator controls on permissions

**Files:**
- Modify: `frontend/src/pages/UsersPage.tsx`
- Modify: `frontend/src/pages/LiveMonitoringPage.tsx`
- Modify: `frontend/src/pages/RevocationPage.tsx`
- Modify: `frontend/src/components/layout/AppShell.tsx`

**Interfaces:**
- Consumes: `usePermissions` from Task 9
- Produces: an operator console that renders only the controls the signed-in role holds

- [ ] **Step 1: Gate the user and device controls**

In `frontend/src/pages/UsersPage.tsx`, add:

```tsx
import { usePermissions } from "../auth/usePermissions";
```

Inside the component add `const { can } = usePermissions();`, then wrap each write control. The role `<select>` gets a read-only fallback so the column still reads correctly:

```tsx
{can("users:write") ? (
  /* the existing role <select> element, unchanged */
) : (
  <span className="text-sm text-slate-700">{user.role}</span>
)}
```

and the remaining three are wrapped without a fallback:

```tsx
{can("users:write") && (
  /* the existing unlock button, unchanged */
)}

{can("devices:approve") && (
  /* the existing Approve button, unchanged */
)}

{can("devices:revoke") && (
  /* the existing Revoke button, unchanged */
)}
```

- [ ] **Step 2: Gate session revocation**

In both `frontend/src/pages/LiveMonitoringPage.tsx` and `frontend/src/pages/RevocationPage.tsx`, add the same import and `const { can } = usePermissions();`, then wrap every revoke control in `{can("sessions:revoke") && ( … )}`. `security_analyst` holds this permission, so those controls stay visible for that role — the point is that the gating is explicit rather than assumed.

- [ ] **Step 3: Add the two new nav entries**

In `frontend/src/components/layout/AppShell.tsx`, replace the `NAV` array with:

```tsx
const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/users", label: "Users & Devices" },
  { to: "/resources", label: "Resources" },
  { to: "/policies", label: "Policies" },
  { to: "/live", label: "Live Monitoring" },
  { to: "/risk", label: "Risk Scores" },
  { to: "/alerts", label: "Alerts" },
  { to: "/trust", label: "Trust Score" },
  { to: "/audit", label: "Audit Logs" },
  { to: "/revocation", label: "Session Revocation" },
];
```

- [ ] **Step 4: Type-check and verify as an analyst**

Run: `cd frontend && npm run lint`

Find a seeded analyst:

```bash
cd /Users/sivabalan/Documents/ztna-project && .venv/bin/python -c "
import sys; sys.path.insert(0, 'backend')
from sqlalchemy import select
from app.core.database import SessionLocal
from app.models.user import User
from app.models.role import Role
with SessionLocal() as db:
    for u in db.scalars(select(User).join(Role).where(Role.name=='security_analyst')):
        print(u.username)
"
```

Sign in as that account (`Ztna@Demo2026`) and confirm on Users & Devices that no role dropdown, unlock, approve or revoke-device control renders, and that session revocation still does.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/UsersPage.tsx frontend/src/pages/LiveMonitoringPage.tsx frontend/src/pages/RevocationPage.tsx frontend/src/components/layout/AppShell.tsx
git commit -m "Render operator write controls only for roles that hold the permission"
```

---

### Task 16: Resources administration page

**Files:**
- Create: `frontend/src/pages/ResourcesAdminPage.tsx`

**Interfaces:**
- Consumes: `getResources`, `createResource`, `updateResource`, `disableResource`, `uploadResourceFile`, `apiErrorMessage` from Task 8; `usePermissions` from Task 9
- Produces: default-exported `ResourcesAdminPage`

- [ ] **Step 1: Write the page**

Create `frontend/src/pages/ResourcesAdminPage.tsx`:

```tsx
import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  apiErrorMessage, createResource, disableResource, getResources,
  updateResource, uploadResourceFile, type ResourceReachability,
} from "../api/client";
import { usePermissions } from "../auth/usePermissions";
import Page, { Card, Empty } from "../components/layout/Page";

const SENSITIVITIES = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];

const EMPTY_FORM = {
  slug: "", name: "", description: "", category: "application",
  sensitivity: "INTERNAL", owner: "",
};

/**
 * The catalogue, as an administrator sees it: what exists, what it protects,
 * and what file sits behind it. Analysts get the same view without controls.
 */
export default function ResourcesAdminPage() {
  const { can } = usePermissions();
  const writable = can("resources:write");
  const [resources, setResources] = useState<ResourceReachability[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);

  const load = useCallback(() => {
    getResources().then(setResources).catch(() => setResources([]));
  }, []);

  useEffect(load, [load]);

  async function onCreate(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await createResource(form);
      setForm(EMPTY_FORM);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not create the resource."));
    } finally {
      setBusy(false);
    }
  }

  async function onUpload(slug: string, file: File) {
    setError("");
    try {
      await uploadResourceFile(slug, file);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Upload failed."));
    }
  }

  async function onDisable(slug: string) {
    setError("");
    try {
      await disableResource(slug);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not disable the resource."));
    }
  }

  async function onSetFloor(slug: string, value: number) {
    setError("");
    try {
      await updateResource(slug, { min_trust_score: value });
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not update the resource."));
    }
  }

  return (
    <Page
      title="Resources"
      description="The protected catalogue. A resource's sensitivity and trust floor decide who reaches it; the attached file is what they receive."
    >
      {error && (
        <div className="mb-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-risk-critical">
          {error}
        </div>
      )}

      {writable && (
        <div className="mb-4">
          <Card title="Publish a resource">
            <form onSubmit={onCreate} className="grid gap-3 sm:grid-cols-2">
              <input
                required
                placeholder="slug (lowercase, hyphens)"
                pattern="[a-z0-9-]+"
                value={form.slug}
                onChange={(e) => setForm({ ...form, slug: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <input
                required
                placeholder="Display name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <input
                placeholder="Description"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm sm:col-span-2"
              />
              <input
                placeholder="Owner (team)"
                value={form.owner}
                onChange={(e) => setForm({ ...form, owner: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <select
                value={form.sensitivity}
                onChange={(e) => setForm({ ...form, sensitivity: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
                aria-label="Sensitivity"
              >
                {SENSITIVITIES.map((level) => (
                  <option key={level} value={level}>{level}</option>
                ))}
              </select>
              <button
                type="submit"
                disabled={busy}
                className="rounded-lg bg-shell px-4 py-2 text-sm font-medium text-white disabled:opacity-50 sm:col-span-2"
              >
                {busy ? "Publishing…" : "Publish resource"}
              </button>
            </form>
            <p className="mt-2 text-xs text-slate-500">
              The trust floor defaults to the sensitivity's own minimum. Attach a
              file below once the resource exists.
            </p>
          </Card>
        </div>
      )}

      <Card title={`Catalogue (${resources.length})`}>
        {resources.length === 0 ? (
          <Empty>No resources published yet.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Resource</th>
                  <th className="px-3 py-2 font-medium">Sensitivity</th>
                  <th className="px-3 py-2 font-medium">Floor</th>
                  <th className="px-3 py-2 font-medium">File</th>
                  {writable && <th className="px-3 py-2 font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {resources.map((resource) => (
                  <tr key={resource.id}>
                    <td className="px-3 py-2">
                      <div className="font-medium text-slate-900">{resource.name}</div>
                      <div className="font-mono text-[11px] text-slate-400">
                        {resource.slug} · {resource.owner}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-700">
                      {resource.sensitivity}
                    </td>
                    <td className="px-3 py-2">
                      {writable ? (
                        <input
                          type="number"
                          min={0}
                          max={100}
                          defaultValue={resource.min_trust_score}
                          onBlur={(e) => {
                            const value = Number(e.target.value);
                            if (value !== resource.min_trust_score) {
                              onSetFloor(resource.slug, value);
                            }
                          }}
                          className="w-20 rounded border border-slate-300 px-2 py-1 font-mono text-xs"
                          aria-label={`Trust floor for ${resource.name}`}
                        />
                      ) : (
                        <span className="font-mono text-xs">
                          {resource.min_trust_score}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {resource.has_file ? (
                        <>
                          {resource.file_name}
                          <span className="ml-1 text-slate-400">
                            ({resource.content_type})
                          </span>
                        </>
                      ) : (
                        <span className="text-amber-700">no file</span>
                      )}
                    </td>
                    {writable && (
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <label className="cursor-pointer rounded border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50">
                            {resource.has_file ? "Replace" : "Upload"}
                            <input
                              type="file"
                              className="hidden"
                              onChange={(e) => {
                                const file = e.target.files?.[0];
                                if (file) onUpload(resource.slug, file);
                                e.target.value = "";
                              }}
                            />
                          </label>
                          <button
                            onClick={() => onDisable(resource.slug)}
                            className="rounded border border-slate-300 px-2 py-1 text-xs text-risk-critical hover:bg-red-50"
                          >
                            Disable
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </Page>
  );
}
```

- [ ] **Step 2: Type-check and verify as an admin**

Run: `cd frontend && npm run lint`

In the browser as `admin` / `Admin@Ztna2026!`: publish a resource, upload a small `.md` file to it, and confirm it appears with its filename. Then sign in as `arjun.krishnan` and confirm the new resource appears in My Access.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/ResourcesAdminPage.tsx
git commit -m "Add the Resources administration page with browser upload"
```

---

### Task 17: Policies page

**Files:**
- Create: `frontend/src/pages/PoliciesPage.tsx`

**Interfaces:**
- Consumes: `getPolicies`, `createPolicy`, `updatePolicy`, `deletePolicy`, `apiErrorMessage`, type `PolicyRow` from Task 8; `usePermissions` from Task 9
- Produces: default-exported `PoliciesPage`

- [ ] **Step 1: Write the page**

Create `frontend/src/pages/PoliciesPage.tsx`:

```tsx
import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  apiErrorMessage, createPolicy, deletePolicy, getPolicies, updatePolicy,
  type PolicyRow,
} from "../api/client";
import { usePermissions } from "../auth/usePermissions";
import Page, { Card, Empty } from "../components/layout/Page";

const SENSITIVITIES = ["", "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];

const EMPTY_FORM = {
  name: "", description: "", sensitivity: "", min_trust_score: 0,
  effect: "ALLOW", priority: 100, require_mfa: false,
  require_known_device: false, deny_vpn: false,
};

/**
 * The rules the enforcement point evaluates.
 *
 * Highest priority wins and DENY beats ALLOW on a tie, so the list is shown in
 * the order the engine considers it rather than alphabetically.
 */
export default function PoliciesPage() {
  const { can } = usePermissions();
  const writable = can("policies:write");
  const [policies, setPolicies] = useState<PolicyRow[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);

  const load = useCallback(() => {
    getPolicies().then(setPolicies).catch(() => setPolicies([]));
  }, []);

  useEffect(load, [load]);

  async function onCreate(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await createPolicy({
        ...form,
        sensitivity: form.sensitivity || null,
        min_trust_score: Number(form.min_trust_score),
        priority: Number(form.priority),
      });
      setForm(EMPTY_FORM);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not create the policy."));
    } finally {
      setBusy(false);
    }
  }

  async function onToggle(policy: PolicyRow) {
    setError("");
    try {
      await updatePolicy(policy.id, { enabled: !policy.enabled });
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not update the policy."));
    }
  }

  async function onDelete(policy: PolicyRow) {
    setError("");
    try {
      await deletePolicy(policy.id);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not delete the policy."));
    }
  }

  return (
    <Page
      title="Policies"
      description="Evaluated on every access decision, highest priority first. A DENY beats an ALLOW at the same priority."
    >
      {error && (
        <div className="mb-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-risk-critical">
          {error}
        </div>
      )}

      {writable && (
        <div className="mb-4">
          <Card title="Add a policy">
            <form onSubmit={onCreate} className="grid gap-3 sm:grid-cols-2">
              <input
                required
                minLength={3}
                placeholder="Policy name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <input
                placeholder="Description"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <select
                value={form.sensitivity}
                onChange={(e) => setForm({ ...form, sensitivity: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
                aria-label="Applies to sensitivity"
              >
                {SENSITIVITIES.map((level) => (
                  <option key={level || "any"} value={level}>
                    {level || "Any sensitivity"}
                  </option>
                ))}
              </select>
              <select
                value={form.effect}
                onChange={(e) => setForm({ ...form, effect: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
                aria-label="Effect"
              >
                <option value="ALLOW">ALLOW</option>
                <option value="DENY">DENY</option>
              </select>
              <label className="text-sm text-slate-700">
                Minimum trust score
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={form.min_trust_score}
                  onChange={(e) =>
                    setForm({ ...form, min_trust_score: Number(e.target.value) })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="text-sm text-slate-700">
                Priority
                <input
                  type="number"
                  min={0}
                  max={1000}
                  value={form.priority}
                  onChange={(e) =>
                    setForm({ ...form, priority: Number(e.target.value) })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <div className="flex flex-wrap gap-4 text-sm text-slate-700 sm:col-span-2">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.require_mfa}
                    onChange={(e) =>
                      setForm({ ...form, require_mfa: e.target.checked })
                    }
                  />
                  Require MFA
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.require_known_device}
                    onChange={(e) =>
                      setForm({ ...form, require_known_device: e.target.checked })
                    }
                  />
                  Require a known device
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.deny_vpn}
                    onChange={(e) => setForm({ ...form, deny_vpn: e.target.checked })}
                  />
                  Deny VPN and datacentre traffic
                </label>
              </div>
              <button
                type="submit"
                disabled={busy}
                className="rounded-lg bg-shell px-4 py-2 text-sm font-medium text-white disabled:opacity-50 sm:col-span-2"
              >
                {busy ? "Saving…" : "Add policy"}
              </button>
            </form>
          </Card>
        </div>
      )}

      <Card title={`Policies (${policies.length})`}>
        {policies.length === 0 ? (
          <Empty>No policies defined.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Priority</th>
                  <th className="px-3 py-2 font-medium">Policy</th>
                  <th className="px-3 py-2 font-medium">Applies to</th>
                  <th className="px-3 py-2 font-medium">Conditions</th>
                  <th className="px-3 py-2 font-medium">Effect</th>
                  {writable && <th className="px-3 py-2 font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {policies.map((policy) => (
                  <tr key={policy.id} className={policy.enabled ? "" : "opacity-50"}>
                    <td className="px-3 py-2 font-mono text-xs">{policy.priority}</td>
                    <td className="px-3 py-2">
                      <div className="font-medium text-slate-900">{policy.name}</div>
                      <div className="text-xs text-slate-500">{policy.description}</div>
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {policy.role ?? "any role"} · {policy.sensitivity ?? "any level"}
                      {policy.resource && ` · ${policy.resource}`}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {[
                        policy.min_trust_score > 0 &&
                          `score ≥ ${policy.min_trust_score}`,
                        policy.require_mfa && "MFA",
                        policy.require_known_device && "known device",
                        policy.deny_vpn && "no VPN",
                        policy.allowed_countries.length > 0 &&
                          policy.allowed_countries.join("/"),
                      ]
                        .filter(Boolean)
                        .join(", ") || "none"}
                    </td>
                    <td
                      className={`px-3 py-2 text-xs font-medium ${
                        policy.effect === "DENY"
                          ? "text-risk-critical"
                          : "text-emerald-700"
                      }`}
                    >
                      {policy.effect}
                    </td>
                    {writable && (
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => onToggle(policy)}
                            className="rounded border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50"
                          >
                            {policy.enabled ? "Disable" : "Enable"}
                          </button>
                          <button
                            onClick={() => onDelete(policy)}
                            className="rounded border border-slate-300 px-2 py-1 text-xs text-risk-critical hover:bg-red-50"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </Page>
  );
}
```

- [ ] **Step 2: Type-check and verify**

Run: `cd frontend && npm run lint`
Expected: zero errors across the whole app now that every referenced page exists.

As `admin`, add a policy: name "Contractors denied internal", sensitivity `INTERNAL`, effect `DENY`, priority 500. Sign in as a contractor and confirm My Access shows the denial naming that policy. Delete the policy afterwards.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/PoliciesPage.tsx
git commit -m "Add the Policies administration page"
```

---

# Phase E — Verification and documentation

### Task 18: Per-role verification and documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/API.md`
- Modify: `docs/DEMO_SCRIPT.md`

**Interfaces:**
- Consumes: everything above
- Produces: documentation matching shipped behaviour, and a verified per-role pass

- [ ] **Step 1: Run the full backend suite**

Run: `cd backend && ../.venv/bin/python -m pytest`
Expected: every test passes, including the 312 that existed before this plan.

- [ ] **Step 2: Run the attack demonstrations**

Run: `cd /Users/sivabalan/Documents/ztna-project && .venv/bin/python scripts/demo/run_all.py`
Expected: 7/7 pass. These exercise the enforcement point that content delivery now shares, so a regression here would be significant.

- [ ] **Step 3: Verify the audit chain**

Run: `.venv/bin/python scripts/verify_chain.py`
Expected: the chain verifies. Every content delivery appended to it, so this confirms the new writes chain correctly.

- [ ] **Step 4: Walk each role in the browser**

With both servers running, sign in as each and confirm:

| Role | Expect |
| --- | --- |
| `admin` | ten console pages including Resources and Policies; can publish a resource and upload a file |
| `security_analyst` | same console, but no role dropdown, unlock, or device approve/revoke; session revocation still works; Resources and Policies read-only |
| `employee` (`arjun.krishnan`) | five portal pages, all functional; opens and downloads an INTERNAL resource; refused a RESTRICTED one with a stated reason |
| `contractor` | five portal pages; refused CONFIDENTIAL resources by the seeded policy, which is named in the decision |

- [ ] **Step 5: Demonstrate continuous verification end to end**

As `admin`, raise `hr-portal`'s trust floor to 100 while an employee has it open. Have the employee press Open again: the resource that downloaded a moment ago is now refused, gate `trust`. Restore the floor to 60 afterwards. This is the project's central claim, shown live rather than asserted.

- [ ] **Step 6: Update the documentation**

- `README.md`: add the new endpoints to the API table; describe the portal and the two new operator pages; note that `storage/` holds uploaded content and is not committed.
- `docs/ARCHITECTURE.md`: document that content delivery routes through the enforcement point and that no static mount exists over the storage root.
- `docs/API.md`: regenerate from the live OpenAPI spec so the new routes appear.
- `docs/DEMO_SCRIPT.md`: add the live revocation demonstration from Step 5, and note that a high-sensitivity download needs an approved device — otherwise the device penalty puts it out of reach mid-demo.

- [ ] **Step 7: Commit**

```bash
git add README.md docs/ARCHITECTURE.md docs/API.md docs/DEMO_SCRIPT.md
git commit -m "Document resource content, the portal and per-role console behaviour"
```

---

## Notes for the implementer

- **Route order matters in `resources.py`.** `GET /{slug}/content` must be declared before `GET /{slug}`, or FastAPI matches `content` as a slug and returns 404.
- **`storage.clear()` is destructive.** It is called only from the seeder's reset path. Never call it from a request handler.
- **The frontend never gets a direct file URL.** Content always arrives as a blob through an authenticated request, because a plain `<a href>` cannot carry the bearer token and a token in a query string would land in logs.
- **Do not add `StaticFiles` over `storage/`.** It would create a second route to the bytes that bypasses every gate this plan builds.
