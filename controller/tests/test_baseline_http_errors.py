"""Finite closed domain-error transport registry and programmer-error identity."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_http_routes import SCOPE, headers, settings

ERRORS = {
    404: ["BASELINE_SCOPE_NOT_FOUND", "BASELINE_SOURCE_NOT_FOUND"],
    409: [
        "BASELINE_SCOPE_EXISTS",
        "BASELINE_REVISION_CONFLICT",
        "BASELINE_IDEMPOTENCY_CONFLICT",
        "BASELINE_FROZEN",
        "BASELINE_SOURCE_CHANGED",
        "BASELINE_SOURCE_STATE",
        "BASELINE_SOURCE_LINEAGE_INVALID",
        "BASELINE_SOURCE_QUALITY",
        "BASELINE_SCOPE_MISMATCH",
        "BASELINE_SOURCE_DUPLICATE",
        "BASELINE_EVENT_ORDER",
        "BASELINE_ROLLBACK_UNAVAILABLE",
        "BASELINE_GENERATION_MISMATCH",
    ],
    410: ["BASELINE_GENERATION_RETIRED"],
    413: [
        "BASELINE_SOURCE_LIMIT",
        "BASELINE_CANDIDATE_LIMIT",
        "BASELINE_PROFILE_LIMIT",
        "BASELINE_GENERATION_LIMIT",
        "BASELINE_CONTROL_LIMIT",
    ],
    422: ["BASELINE_SOURCE_INVALID"],
    429: ["BASELINE_SCOPE_LIMIT"],
    503: ["BASELINE_BUSY", "BASELINE_STORAGE_UNAVAILABLE"],
}


@pytest.mark.parametrize("status,code", [(s, c) for s, cs in ERRORS.items() for c in cs])
def test_closed_domain_error(status: int, code: str, monkeypatch: Any) -> None:
    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    error = bs.BaselineStorageError(code)
    error.args = ("private SQL path and rejected value",)

    def fail(*a: Any) -> Any:
        raise error

    monkeypatch.setattr(repo, "get_baseline_scope", fail)
    with TestClient(app) as client:
        response = client.get(SCOPE, headers=headers())
        value = response.json()
        assert response.status_code == status
        assert set(value) == {"error"} and set(value["error"]) == {
            "code",
            "message",
            "details",
            "request_id",
        }
        assert value["error"]["code"] == code and value["error"]["details"] is None
        assert "private" not in response.text
    repo.close()


def test_programmer_exception_not_mislabelled_busy(monkeypatch: Any) -> None:
    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    marker = TypeError("programmer failure")

    def fail(*a: Any) -> Any:
        raise marker

    monkeypatch.setattr(repo, "get_baseline_scope", fail)
    with TestClient(app) as client:
        with pytest.raises(TypeError) as error:
            client.get(SCOPE, headers=headers())
        assert error.value is marker
        assert not app.state.baseline_transport._pending
    repo.close()
