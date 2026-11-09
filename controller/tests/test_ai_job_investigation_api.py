"""Actual app authentication + owned supervisor + ASGI, no listening server."""

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.ai_job_investigation_runtime_schema import JobRun
from c2hunter_controller.app import create_app
from tests.test_ai_investigation_http_runtime import HEADERS, configured, settings
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted
from tests.test_ai_job_investigation_service import repository as _repository
from tests.test_ai_job_investigation_worker import wait_for

repository = _repository

BASE = "/api/v1/analysis-jobs/job/ai-job-investigations"
CAPS = "/api/v1/ai-job-investigations/capabilities"


def test_actual_asgi_opt_in_owned_worker_and_saved_history(repository, monkeypatch):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        app = create_app(
            settings(ai_job_investigation_enabled=True, ai_investigation_inline_enabled=True),
            repository,
            ai_gateway=configured(gateway),
        )
        with TestClient(app) as client:
            assert client.get(CAPS).status_code == 401
            assert client.get(CAPS, headers={"Authorization": "Bearer viewer"}).status_code == 403
            caps = client.get(CAPS, headers=HEADERS)
            assert caps.status_code == 200, caps.text
            assert caps.json()["dispatch_scope"] == "OWNED_CAPABLE_RUNTIME"
            posted = client.post(BASE, headers=HEADERS, json=request_for())
            assert posted.status_code == 202, posted.text
            queued = JobRun.model_validate_json(posted.content)
            path = BASE + "/" + queued.id

            def terminal():
                response = client.get(path, headers=HEADERS)
                assert response.status_code == 200, response.text
                run = JobRun.model_validate_json(response.content)
                return run if run.status == "COMPLETED" else None

            completed = wait_for(terminal)
            assert len(calls) == 3
            steps = client.get(path + "/steps", headers=HEADERS).json()
            evidence_id = next(s["evidence_id"] for s in steps["items"] if s["evidence_id"])
            assert client.get(path + "/evidence/" + evidence_id, headers=HEADERS).status_code == 200
            for suffix in ("", "/steps", "/evidence/" + evidence_id):
                assert client.get(path + suffix).status_code == 401
                assert (
                    client.get(
                        path.replace("/job/", "/other/") + suffix, headers=HEADERS
                    ).status_code
                    == 404
                )
            assert client.get(BASE + "?limit=2", headers=HEADERS).status_code == 422
            assert client.get(path + "/steps?limit=11", headers=HEADERS).status_code == 422
            assert client.get(BASE, headers=HEADERS).json()["items"][0]["id"] == queued.id
            repository.delete_job("job")
            app.state.job_investigation_service.enabled = False
            app.state.job_investigation_service.gateway = None
            replay = client.post(BASE, headers=HEADERS, json=request_for())
            assert (
                replay.status_code == 200
                and JobRun.model_validate_json(replay.content) == completed
            )
            assert client.get(path + "/evidence/" + evidence_id, headers=HEADERS).status_code == 200
        assert app.state.investigation_drained


@pytest.mark.parametrize(
    "enabled,inline,expected",
    [(False, True, "JOB_DISABLED"), (True, False, "JOB_DISPATCH_UNSUPPORTED")],
)
def test_disabled_or_dispatch_missing_no_admission(
    repository, monkeypatch, enabled, inline, expected
):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        app = create_app(
            settings(ai_job_investigation_enabled=enabled, ai_investigation_inline_enabled=inline),
            repository,
            ai_gateway=configured(gateway),
        )
        with TestClient(app) as client:
            response = client.post(BASE, headers=HEADERS, json=request_for())
            assert response.status_code == 503
            assert response.json()["error"]["code"] == expected
            assert client.get(CAPS, headers=HEADERS).json()["availability"] == "UNAVAILABLE"
            assert calls == []
            assert client.post(BASE, headers=HEADERS, content=b"x" * 16385).status_code == 413
            raw = b'{"version":"job-investigation-v1","version":"job-investigation-v1"}'
            assert client.post(BASE, headers=HEADERS, content=raw).status_code == 422
