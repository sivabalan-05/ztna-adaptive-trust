"""Private local-disk or S3-compatible storage for protected resource files.

The API always proxies bytes through its policy checks; this module never
returns a public or presigned object URL. Stored names are generated UUIDs,
never filenames supplied by an uploader.
"""

from __future__ import annotations

import re
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any

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


def _validate_upload(data: bytes, content_type: str) -> None:
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


def _new_name(content_type: str) -> str:
    return f"{uuid.uuid4().hex}{ALLOWED_CONTENT_TYPES[content_type]}"


def _prefix() -> str:
    return settings.s3_key_prefix.strip("/")


def _s3_key(relative_path: str) -> str:
    """Accept only generated keys within this app's configured prefix."""
    prefix = _prefix()
    if not relative_path or "\\" in relative_path or relative_path.startswith("/"):
        raise StorageError("Refusing to read outside the storage root.", "path_escape")
    # Rows created before switching from local disk contain only the generated
    # UUID filename. Map those safely into the bucket prefix so the API reports
    # a missing object and lets an admin replace it.
    if re.fullmatch(r"[0-9a-f]{32}\.[a-z0-9]+", relative_path):
        return f"{prefix}/{relative_path}"
    expected_prefix = f"{prefix}/"
    if not relative_path.startswith(expected_prefix):
        raise StorageError("Refusing to read outside the storage root.", "path_escape")
    name = relative_path[len(expected_prefix):]
    if not re.fullmatch(r"[0-9a-f]{32}\.[a-z0-9]+", name):
        raise StorageError("Refusing to read outside the storage root.", "path_escape")
    return relative_path


@lru_cache(maxsize=1)
def _s3_client() -> Any:
    """Create the S3-compatible client only when remote storage is selected."""
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        region_name=settings.s3_region,
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=settings.s3_secret_access_key,
        config=Config(s3={"addressing_style": settings.s3_addressing_style}),
    )


def _bucket() -> str:
    return settings.s3_bucket_name


def _storage_unavailable() -> StorageError:
    # Do not leak provider response bodies, endpoint credentials, or bucket
    # internals into API responses.
    return StorageError(
        "Object storage is temporarily unavailable.", "storage_unavailable"
    )


def _is_missing_object(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    error = response.get("Error", {})
    code = str(error.get("Code", "")) if isinstance(error, dict) else ""
    metadata = response.get("ResponseMetadata", {})
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, dict) else None
    return code in {"NoSuchKey", "NotFound", "404"} or status == 404


def save(data: bytes, content_type: str) -> str:
    """Write an upload and return its opaque local name or object key."""
    _validate_upload(data, content_type)
    name = _new_name(content_type)

    if settings.resource_storage_backend == "s3":
        key = f"{_prefix()}/{name}"
        try:
            _s3_client().put_object(
                Bucket=_bucket(), Key=key, Body=data, ContentType=content_type
            )
        except Exception as exc:
            raise _storage_unavailable() from exc
        return key

    (storage_root() / name).write_bytes(data)
    return name


def read(relative_path: str) -> bytes:
    if settings.resource_storage_backend == "s3":
        key = _s3_key(relative_path)
        try:
            response = _s3_client().get_object(Bucket=_bucket(), Key=key)
            body = response["Body"]
            try:
                return body.read()
            finally:
                body.close()
        except Exception as exc:
            if _is_missing_object(exc):
                raise StorageError("The stored file is missing.", "file_missing") from exc
            raise _storage_unavailable() from exc

    path = _resolve(relative_path)
    if not path.is_file():
        raise StorageError("The stored file is missing.", "file_missing")
    return path.read_bytes()


def delete(relative_path: str) -> None:
    """Delete a stored object; missing objects are harmless."""
    if settings.resource_storage_backend == "s3":
        key = _s3_key(relative_path)
        try:
            _s3_client().delete_object(Bucket=_bucket(), Key=key)
        except Exception as exc:
            raise _storage_unavailable() from exc
        return

    _resolve(relative_path).unlink(missing_ok=True)


def clear() -> None:
    """Clear local files for seeding; remote object deletion needs manual care."""
    if settings.resource_storage_backend == "s3":
        raise StorageError(
            "Bulk clearing remote objects is disabled. Manage the bucket prefix directly.",
            "clear_disabled",
        )

    for child in storage_root().iterdir():
        if child.is_file():
            child.unlink()
