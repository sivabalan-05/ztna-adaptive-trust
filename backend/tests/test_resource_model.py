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
