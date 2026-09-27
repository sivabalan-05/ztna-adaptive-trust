"""S3-compatible storage behavior, exercised without network credentials."""

from __future__ import annotations

from io import BytesIO

import pytest
from pydantic import ValidationError

from app.core import storage
from app.core.config import Settings, settings


class ObjectMissing(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.bucket = "test-bucket"

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, ContentType: str):
        assert Bucket == self.bucket
        self.objects[Key] = (Body, ContentType)

    def get_object(self, *, Bucket: str, Key: str):
        assert Bucket == self.bucket
        if Key not in self.objects:
            raise ObjectMissing()
        data, _ = self.objects[Key]
        return {"Body": BytesIO(data)}

    def delete_object(self, *, Bucket: str, Key: str):
        assert Bucket == self.bucket
        self.objects.pop(Key, None)

    def get_paginator(self, operation: str):
        assert operation == "list_objects_v2"
        return self

    def paginate(self, *, Bucket: str, Prefix: str):
        assert Bucket == self.bucket
        yield {"Contents": [{"Key": key} for key in self.objects if key.startswith(Prefix)]}

    def delete_objects(self, *, Bucket: str, Delete: dict):
        assert Bucket == self.bucket
        for item in Delete["Objects"]:
            self.objects.pop(item["Key"], None)


@pytest.fixture
def s3_store(monkeypatch: pytest.MonkeyPatch) -> FakeS3:
    client = FakeS3()
    monkeypatch.setattr(settings, "resource_storage_backend", "s3")
    monkeypatch.setattr(settings, "s3_bucket_name", client.bucket)
    monkeypatch.setattr(settings, "s3_key_prefix", "test-app/resources")
    monkeypatch.setattr(storage, "_s3_client", lambda: client)
    return client


def test_s3_save_and_read_use_private_prefixed_uuid_keys(s3_store: FakeS3) -> None:
    key = storage.save(b"leave policy", "text/markdown")

    assert key.startswith("test-app/resources/")
    assert key.endswith(".md")
    assert s3_store.objects[key] == (b"leave policy", "text/markdown")
    assert storage.read(key) == b"leave policy"


def test_s3_missing_object_maps_to_file_missing(s3_store: FakeS3) -> None:
    with pytest.raises(storage.StorageError) as excinfo:
        storage.read("test-app/resources/00000000000000000000000000000000.md")

    assert excinfo.value.code == "file_missing"


@pytest.mark.parametrize(
    "key",
    ["../secret.txt", "/test-app/resources/secret.txt", "other/secret.txt", "test-app/resources/../secret.txt"],
)
def test_s3_rejects_keys_outside_its_generated_prefix(
    key: str, s3_store: FakeS3
) -> None:
    with pytest.raises(storage.StorageError) as excinfo:
        storage.read(key)

    assert excinfo.value.code == "path_escape"


def test_local_uuid_key_from_before_backend_switch_maps_to_missing_object(
    s3_store: FakeS3,
) -> None:
    with pytest.raises(storage.StorageError) as excinfo:
        storage.read("00000000000000000000000000000000.md")

    assert excinfo.value.code == "file_missing"


def test_s3_delete_is_single_object_and_bulk_clear_is_disabled(s3_store: FakeS3) -> None:
    key = storage.save(b"remove me", "text/plain")
    other_key = "another-app/resources/keep.txt"
    s3_store.objects[other_key] = (b"keep", "text/plain")

    storage.delete(key)

    assert key not in s3_store.objects
    assert s3_store.objects == {other_key: (b"keep", "text/plain")}
    with pytest.raises(storage.StorageError) as excinfo:
        storage.clear()
    assert excinfo.value.code == "clear_disabled"
    assert other_key in s3_store.objects


def test_s3_provider_errors_are_returned_without_provider_details(
    s3_store: FakeS3, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(**kwargs):
        raise RuntimeError("authorization header contains private data")

    monkeypatch.setattr(s3_store, "put_object", fail)
    with pytest.raises(storage.StorageError) as excinfo:
        storage.save(b"data", "text/plain")

    assert excinfo.value.code == "storage_unavailable"
    assert "private data" not in excinfo.value.message


def test_s3_configuration_requires_credentials_and_bucket() -> None:
    with pytest.raises(ValidationError, match="S3 storage is enabled"):
        Settings(
            _env_file=None,
            resource_storage_backend="s3",
            s3_bucket_name="",
            s3_endpoint_url="",
            s3_access_key_id="",
            s3_secret_access_key="",
        )


def test_production_s3_configuration_requires_https() -> None:
    with pytest.raises(ValidationError, match="must use HTTPS"):
        Settings(
            _env_file=None,
            app_env="production",
            resource_storage_backend="s3",
            s3_bucket_name="bucket",
            s3_endpoint_url="http://localhost:9000",
            s3_access_key_id="access",
            s3_secret_access_key="secret",
        )


def test_s3_client_uses_configured_addressing_style(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3

    monkeypatch.setattr(settings, "s3_addressing_style", "path")
    monkeypatch.setattr(boto3, "client", lambda service, **kwargs: kwargs)
    storage._s3_client.cache_clear()
    try:
        client_options = storage._s3_client()
    finally:
        storage._s3_client.cache_clear()

    assert client_options["config"].s3["addressing_style"] == "path"
