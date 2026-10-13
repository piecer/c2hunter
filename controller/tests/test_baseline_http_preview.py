"""Structural preview, shared computation ownership and replay at real routes."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller import historical_generation as g
from c2hunter_controller.app import create_app
from c2hunter_controller.baseline_admission import BaselineLease
from tests import test_baseline_http_routes as routes
from tests.test_baseline_http_routes import SCOPE, headers, scope_body, settings
from tests.test_historical_source import stored

repository = routes.repository

PREVIEW = {"source_job_id": "root", "expected_revision": 0, "purpose": "APPROVAL"}
PREVIEW_KEYS = {
    "scope_id",
    "scope_revision",
    "scope_config_sha256",
    "source_job_id",
    "root_job_id",
    "dataset_id",
    "source_binding_sha256",
    "observation_sha256",
    "feature_observation_sha256",
    "origin",
    "origin_assurance",
    "actual_sensor_id",
    "event_start",
    "event_end",
    "flow_count",
    "profile_count",
    "eligible_profile_count",
    "excluded_profile_count",
    "admissible",
    "reasons",
    "required_review",
    "producer_completeness",
    "known_partial",
    "stored_clock_offset_ms",
}


def test_structural_preview_without_review_or_producer(repository: Any, monkeypatch: Any) -> None:
    repository.save_job(stored())
    calls = []

    def forbidden(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        raise AssertionError("forbidden generic or approval computation")

    app = create_app(settings(), repository=repository)
    for name in ["get_job", "list_jobs"]:
        monkeypatch.setattr(repository, name, forbidden)
    monkeypatch.setattr(g, "produce_generation", forbidden)
    with TestClient(app) as client:
        assert client.put(SCOPE, json=scope_body(), headers=headers()).status_code == 201
        response = client.post(SCOPE + "/preview", json=PREVIEW, headers=headers("analyst"))
        assert response.status_code == 200, response.text
        value = response.json()
        assert set(value) == PREVIEW_KEYS
        assert (
            value["eligible_profile_count"] + value["excluded_profile_count"]
            == value["profile_count"]
        )
        assert (
            value["producer_completeness"] == "UNKNOWN" and value["stored_clock_offset_ms"] is None
        )
        assert value["required_review"] == "EXPLICIT_NORMAL_AND_QUALITY_ASSERTION"
        assert calls == []
        assert client.get(SCOPE, headers=headers()).json()["control_revision"] == 0
        with pytest.raises(AssertionError):
            forbidden()
    assert calls == [True]


def test_preview_compute_busy_before_source_and_distinct_app(
    repository: Any, monkeypatch: Any
) -> None:
    from c2hunter_controller import historical_read as read

    repository.save_job(stored())
    app = create_app(settings(), repository=repository)
    other = create_app(settings(), repository=repository)
    with TestClient(app) as client, TestClient(other) as second:
        assert client.put(SCOPE, json=scope_body(), headers=headers()).status_code == 201
        admission = getattr(app.state, "baseline_admission", None)
        assert admission is not None, "one shared per-app computation permit required"
        lease = BaselineLease(admission)
        assert lease.acquire()
        calls = []

        def forbidden(*a: Any, **kw: Any) -> Any:
            calls.append(True)
            raise AssertionError("busy preview source IO")

        try:
            with monkeypatch.context() as m:
                m.setattr(read, "_memory_acquire", forbidden)
                m.setattr(read, "_sqlite_acquire", forbidden)
                m.setattr(read, "_postgres_acquire", forbidden)
                response = client.post(SCOPE + "/preview", json=PREVIEW, headers=headers("analyst"))
                assert (response.status_code, response.json()["error"]["code"], calls) == (
                    503,
                    "BASELINE_BUSY",
                    [],
                )
            assert (
                second.post(
                    SCOPE + "/preview", json=PREVIEW, headers=headers("analyst")
                ).status_code
                == 200
            )
        finally:
            lease.close()
        assert (
            client.post(SCOPE + "/preview", json=PREVIEW, headers=headers("analyst")).status_code
            == 200
        )


@pytest.mark.parametrize(
    "body,code,status",
    [
        (dict(PREVIEW, expected_revision=1), "BASELINE_REVISION_CONFLICT", 409),
        (dict(PREVIEW, source_job_id="missing"), "BASELINE_SOURCE_NOT_FOUND", 404),
        (dict(PREVIEW, expected_revision=True), "VALIDATION_ERROR", 422),
        (dict(PREVIEW, purpose="invalid"), "VALIDATION_ERROR", 422),
        (dict(PREVIEW, quality_review={}), "VALIDATION_ERROR", 422),
        ({}, "VALIDATION_ERROR", 422),
    ],
)
def test_preview_errors(repository: Any, body: dict[str, Any], code: str, status: int) -> None:
    with TestClient(create_app(settings(), repository=repository)) as client:
        assert client.put(SCOPE, json=scope_body(), headers=headers()).status_code == 201
        response = client.post(SCOPE + "/preview", json=body, headers=headers("analyst"))
        assert (response.status_code, response.json()["error"]["code"]) == (status, code)
