from __future__ import annotations

import json
from typing import Any, cast

import pytest

from c2hunter_controller.production import PostgresRepository


def test_json_replaces_nested_nul_with_visible_marker() -> None:
    encoded = PostgresRepository._json(
        {
            "domain": "pektbo.libre\x19.\x00",
            "nested": [
                {"value": "a\x00b"},
                ("c\x00d",),
            ],
        }
    )

    assert "\\u0000" not in encoded

    decoded = json.loads(encoded)
    assert decoded["domain"] == "pektbo.libre\x19.\\x00"
    assert decoded["nested"][0]["value"] == "a\\x00b"
    assert decoded["nested"][1][0] == "c\\x00d"


def test_json_preserves_non_nul_unicode_and_control_characters() -> None:
    encoded = PostgresRepository._json(
        {
            "korean": "도메인",
            "control": "before\x19after",
        }
    )

    assert "도메인" in encoded

    decoded = json.loads(encoded)
    assert decoded["korean"] == "도메인"
    assert decoded["control"] == "before\x19after"


class _FailingBlobStore:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def get(self, _key: str) -> bytes:
        raise self.error

    def open(self, _key: str) -> Any:
        raise self.error


def test_get_job_capture_only_treats_missing_objects_as_absent() -> None:
    repository = PostgresRepository.__new__(PostgresRepository)
    repository.blob_store = cast(Any, _FailingBlobStore(KeyError("missing")))
    assert repository.get_job_capture("job-a") is None

    repository.blob_store = cast(Any, _FailingBlobStore(TimeoutError("object store unavailable")))
    with pytest.raises(TimeoutError, match="object store unavailable"):
        repository.get_job_capture("job-a")


class _ObjectStoreError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("missing"),
        KeyError("missing"),
        _ObjectStoreError("NoSuchKey"),
        _ObjectStoreError("NoSuchObject"),
        _ObjectStoreError("NoSuchVersion"),
    ],
)
def test_postgres_open_job_capture_treats_only_authoritative_missing_as_absent(
    error: Exception,
) -> None:
    repository = PostgresRepository.__new__(PostgresRepository)
    repository.blob_store = cast(Any, _FailingBlobStore(error))

    assert repository.open_job_capture("job-a") is None


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("timeout"),
        PermissionError("denied"),
        ValueError("object response lacks immutable version identity"),
        _ObjectStoreError("AccessDenied"),
        _ObjectStoreError("nosuchkey"),
    ],
)
def test_postgres_open_job_capture_propagates_outages(error: Exception) -> None:
    repository = PostgresRepository.__new__(PostgresRepository)
    repository.blob_store = cast(Any, _FailingBlobStore(error))

    with pytest.raises(type(error), match=str(error)):
        repository.open_job_capture("job-a")


@pytest.mark.parametrize(
    "missing_error",
    [
        FileNotFoundError("missing"),
        KeyError("missing"),
        _ObjectStoreError("NoSuchKey"),
        _ObjectStoreError("NoSuchObject"),
        _ObjectStoreError("NoSuchVersion"),
    ],
)
def test_postgres_open_sensor_pcap_distinguishes_missing_from_outage(
    monkeypatch: pytest.MonkeyPatch, missing_error: Exception
) -> None:
    repository = PostgresRepository.__new__(PostgresRepository)
    repository.blob_store = cast(Any, _FailingBlobStore(missing_error))
    monkeypatch.setattr(
        repository,
        "_get",
        lambda kind, object_id: {"id": object_id, "object_key": "sensor/key.pcap"},
    )
    assert repository.open_sensor_pcap("segment-a") is None

    for outage in (
        TimeoutError("store timeout"),
        PermissionError("denied"),
        ValueError("object response lacks immutable version identity"),
        _ObjectStoreError("AccessDenied"),
        _ObjectStoreError("nosuchkey"),
    ):
        repository.blob_store = cast(Any, _FailingBlobStore(outage))
        with pytest.raises(type(outage), match=str(outage)):
            repository.open_sensor_pcap("segment-a")

    monkeypatch.setattr(repository, "_get", lambda kind, object_id: None)
    assert repository.open_sensor_pcap("missing-metadata") is None
