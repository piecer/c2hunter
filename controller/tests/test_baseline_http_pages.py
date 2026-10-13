"""All eight real routes in one retained-state path, including SQLite reopen."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import SQLiteRepository
from tests import test_baseline_http_routes as routes
from tests.test_baseline_http_approval import approval
from tests.test_baseline_http_routes import BASE, SCOPE, headers, settings
from tests.test_historical_source import stored

repository = routes.repository

SOURCE_KEYS = {
    "source_receipt_id",
    "source_job_id",
    "root_job_id",
    "dataset_id",
    "root_identity",
    "ancestry_job_ids",
    "root_content_sha256",
    "source_binding_sha256",
    "observation_sha256",
    "feature_observation_sha256",
    "actual_sensor_id",
    "sensor_key",
    "event_start",
    "event_end",
    "origin",
    "origin_assurance",
    "normality",
    "approved_by",
    "approved_at",
    "reason",
    "quality_review",
    "producer_completeness",
    "known_partial",
    "limitations",
}


def test_eight_paths_sources_events_retire_reopen(repository: Any) -> None:
    repository.save_job(stored())
    with TestClient(create_app(settings(), repository=repository)) as client:
        body = approval(client)
        first = client.post(SCOPE + "/approvals", json=body, headers=headers())
        assert first.status_code == 201
        receipt = first.json()["receipt"]
        source_path = SCOPE + "/generations/" + receipt["generation_id"] + "/sources"
        sources = client.get(source_path, headers=headers("analyst"))
        assert sources.status_code == 200, sources.text
        page = sources.json()
        assert set(page) == {"items", "total", "offset", "limit", "next_offset"}
        assert page["total"] == 1 and set(page["items"][0]) == SOURCE_KEYS
        assert page["items"][0]["source_receipt_id"] == receipt["operation_id"]
        events = client.get(SCOPE + "/control-events?offset=0&limit=1", headers=headers("analyst"))
        assert events.status_code == 200
        assert set(events.json()) == {
            "items",
            "total",
            "offset",
            "limit",
            "next_offset",
            "earliest_retained_revision",
        }
        assert events.json()["items"] == [receipt]
        control = {
            "expected_revision": 1,
            "idempotency_key": "retire",
            "action": "RETIRE",
            "reason": "fixture",
            "generation_id": None,
        }
        retired = client.post(SCOPE + "/control", json=control, headers=headers())
        assert retired.status_code == 200 and retired.json()["scope"]["state"] == "RETIRED"
        gone = client.get(source_path, headers=headers("analyst"))
        assert (gone.status_code, gone.json()["error"]["code"]) == (
            410,
            "BASELINE_GENERATION_RETIRED",
        )
        events = client.get(
            SCOPE + "/control-events?offset=0&limit=1", headers=headers("analyst")
        ).json()
        assert (
            events["total"] == 2
            and events["next_offset"] == 1
            and events["earliest_retained_revision"] == 1
        )
        assert events["items"][0] == retired.json()["receipt"]
        assert client.get(BASE + "/scopes", headers=headers("viewer")).json()["total"] == 1
        assert client.get(SCOPE, headers=headers("viewer")).json()["control_revision"] == 2
    repository.delete_job("root")
    reopened = None
    if isinstance(repository, SQLiteRepository):
        path = repository._path
        repository.close()
        reopened = SQLiteRepository(path)
    try:
        with TestClient(create_app(settings(), repository=reopened or repository)) as client:
            replay = client.post(SCOPE + "/approvals", json=body, headers=headers())
            assert replay.status_code == 200 and replay.json()["receipt"] == receipt
            assert replay.json()["scope"]["state"] == "RETIRED"
    finally:
        if reopened is not None:
            reopened.close()
