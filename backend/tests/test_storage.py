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


def test_an_absolute_path_cannot_escape_the_storage_root() -> None:
    """Regression lock: the guard must reject an absolute path outright, not
    just a relative ``..`` traversal. Passes unmodified against the current
    implementation."""
    with pytest.raises(storage.StorageError) as excinfo:
        storage.read("/etc/passwd")

    assert excinfo.value.code == "path_escape"


def test_a_symlink_inside_the_root_cannot_escape_it(tmp_path: Path) -> None:
    """Regression lock: a symlink planted inside the storage root that points
    outside it must not be followed. Passes unmodified against the current
    implementation."""
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("do not serve this")
    link = storage.storage_root() / "escape-link.txt"
    link.symlink_to(outside)

    with pytest.raises(storage.StorageError) as excinfo:
        storage.read("escape-link.txt")

    assert excinfo.value.code == "path_escape"


def test_clear_removes_every_stored_file() -> None:
    storage.save(b"one", "text/plain")
    storage.save(b"two", "text/plain")

    storage.clear()

    assert list(storage.storage_root().iterdir()) == []
