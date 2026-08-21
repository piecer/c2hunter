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


def test_get_job_capture_only_treats_missing_objects_as_absent() -> None:
    repository = PostgresRepository.__new__(PostgresRepository)
    repository.blob_store = cast(Any, _FailingBlobStore(KeyError("missing")))
    assert repository.get_job_capture("job-a") is None

    repository.blob_store = cast(Any, _FailingBlobStore(TimeoutError("object store unavailable")))
    with pytest.raises(TimeoutError, match="object store unavailable"):
        repository.get_job_capture("job-a")
