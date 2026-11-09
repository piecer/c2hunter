"""Legacy pathless helper and exact JOB/IP path slots."""

import json

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from c2hunter_controller import ai_investigation_http as ip_http
from c2hunter_controller import ai_job_investigation_http as job_http
from c2hunter_controller.ai_investigation_http import failure
from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_investigation_http_runtime import HEADERS, settings


@pytest.mark.parametrize(
    "path, expected",
    [
        (None, "RESPONSE_TOO_LARGE"),
        ("/api/v1/ai-job-investigations/capabilities", "JOB_RESPONSE_LIMIT"),
        ("/api/v1/analysis-jobs/job/ai-job-investigations/run/steps", "JOB_RESPONSE_LIMIT"),
        ("/api/v1/analysis-jobs/ai-job-investigations/ai-investigations/run", "RESPONSE_TOO_LARGE"),
        ("/api/v1/analysis-jobs/job/ai-investigations/ai-job-investigations", "RESPONSE_TOO_LARGE"),
        ("/other/ai-job-investigations", "RESPONSE_TOO_LARGE"),
        ("/api/v1/ai-investigations/capabilities", "RESPONSE_TOO_LARGE"),
    ],
)
def test_error_profile_uses_route_slot_not_any_segment(path, expected):
    scope = {"type": "http"}
    if path is not None:
        scope["path"] = path
        scope["headers"] = []
    response = failure(Request(scope), "RESPONSE_TOO_LARGE")
    assert json.loads(response.body)["error"]["code"] == expected


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/api/v1/ai-job-investigations/capabilities", "JOB_RESPONSE_LIMIT"),
        ("/api/v1/ai-investigations/capabilities", "RESPONSE_TOO_LARGE"),
        ("/api/v1/analysis-jobs/ai-job-investigations/ai-investigations", "RESPONSE_TOO_LARGE"),
        ("/api/v1/analysis-jobs/ai-investigations/ai-job-investigations", "JOB_RESPONSE_LIMIT"),
    ],
)
def test_actual_asgi_routes_preserve_error_profile(monkeypatch, path, expected):
    def refused(_):
        raise ip_http.TransportError("RESPONSE_TOO_LARGE")

    monkeypatch.setattr(ip_http, "_owner", refused)
    monkeypatch.setattr(job_http, "_owner", refused)
    repo = MemoryRepository()
    try:
        app = create_app(settings(), repo)
        with TestClient(app) as client:
            response = client.get(path, headers=HEADERS)
            assert response.status_code == 503
            assert response.json()["error"]["code"] == expected
    finally:
        repo.close()
