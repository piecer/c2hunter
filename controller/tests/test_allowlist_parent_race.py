from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from publication_fixtures import publication_adapter  # noqa: F401

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings


def test_allowlist_skips_only_deleted_parent_and_continues(
    adapter: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    for job_id in ("a", "b"):
        adapter.save_job({"id": job_id, "status": "COMPLETED", "candidate_count": 1})
        adapter.save_candidates(job_id, [{"id": job_id, "candidate_ip": "203.0.113.1"}])
    listing = adapter.list_candidate_sets
    metadata = adapter.save_job_metadata
    written = []

    def snapshot() -> dict[str, Any]:
        saved = listing()
        assert adapter.delete_job("a")
        return saved

    def save_metadata(job: dict[str, Any]) -> Any:
        written.append(job["id"])
        return metadata(job)

    monkeypatch.setattr(adapter, "list_candidate_sets", snapshot)
    monkeypatch.setattr(adapter, "save_job_metadata", save_metadata)
    response = TestClient(create_app(Settings(environment="test"), adapter)).post(
        "/api/v1/allowlist", json={"type": "IP", "value": "203.0.113.1", "description": "trusted"}
    )
    assert response.status_code == 201
    assert len(adapter.list_allowlist()) == 1
    assert adapter.get_job("a") is None
    assert adapter.get_candidates("a") == []
    assert adapter.get_candidates("b")[0]["excluded"] is True
    assert adapter.get_job("b")["candidate_count"] == 0
    assert written == ["b"]


@pytest.mark.parametrize("fault", [ValueError("unrelated"), RuntimeError("storage fault")])
def test_allowlist_preserves_unrelated_error_identity(
    adapter: Any, monkeypatch: pytest.MonkeyPatch, fault: Exception
) -> None:
    adapter.save_job({"id": "job", "status": "COMPLETED"})
    adapter.save_candidates("job", [{"id": "candidate", "candidate_ip": "203.0.113.1"}])

    def fail(*args: Any) -> None:
        raise fault

    monkeypatch.setattr(adapter, "save_candidates", fail)
    with pytest.raises(type(fault)) as caught:
        TestClient(create_app(Settings(environment="test"), adapter)).post(
            "/api/v1/allowlist",
            json={"type": "IP", "value": "203.0.113.1", "description": "trusted"},
        )
    assert caught.value is fault
