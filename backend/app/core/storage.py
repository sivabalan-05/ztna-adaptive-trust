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
