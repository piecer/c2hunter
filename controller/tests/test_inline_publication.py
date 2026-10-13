from __future__ import annotations

import importlib
from typing import Any

import pytest
from fastapi.testclient import TestClient
from publication_fixtures import publication_adapter  # noqa: F401
from test_durable_pipeline import flow, job_payload

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings


@pytest.mark.parametrize("winner", ["CANCELLED", "COMPLETED"])
def test_inline_returns_terminal_winner_without_replacement(
    adapter: Any, monkeypatch: pytest.MonkeyPatch, winner: str
) -> None:
    application = create_app(Settings(environment="test"), adapter)
    adapter.upsert_sensor({"sensor_id": "s1"})

    def calculation(job: dict[str, Any], allowlist: Any) -> list[dict[str, Any]]:
        saved = adapter.get_job(job["id"])
        saved.update(status=winner, candidate_count=0)
        assert adapter.transition_job_terminal(saved)
        return [{"id": "loser", "score": 90}]

    monkeypatch.setattr(
        importlib.import_module("c2hunter_controller.app"), "calculate", calculation
    )
    payload = {**job_payload(), "flow_records": [flow()]}
    response = TestClient(application).post("/api/v1/analysis-jobs", json=payload)
    assert response.status_code == 201
    assert response.json()["status"] == winner
    job_id = response.json()["id"]
    assert adapter.get_job(job_id)["status"] == winner
    assert adapter.get_candidates(job_id) == []
