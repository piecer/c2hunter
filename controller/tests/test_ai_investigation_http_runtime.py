"""Actual authenticated ASGI + durable store + loopback structured HTTP provider."""

import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.ai_gateway import OpenAICompatibleGateway
from c2hunter_controller.ai_investigation_schema import InvestigationRun, SourcePreview
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_loop import adaptive, structured_provider

BASE = "/api/v1/analysis-jobs/job/ai-investigations"
CAPS = "/api/v1/ai-investigations/capabilities"
HEADERS = {"Authorization": "Bearer analyst"}


def settings(**changes):
    return Settings(
        environment="test",
        ai_analysis_enabled=True,
        api_auth_required=True,
        analyst_token_sha256=hashlib.sha256(b"analyst").hexdigest(),
        viewer_token_sha256=hashlib.sha256(b"viewer").hexdigest(),
        **changes,
    )


def configured(gateway):
    return OpenAICompatibleGateway(
        base_url=gateway.base_url,
        model="scripted-functional-only",
        context_tokens=65536,
        max_output_tokens=2048,
    )


def wait_for(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("bounded wait expired")


def request_from(preview, key="one"):
    return {
        "target_ip": "2001:db8::1",
        "question": "관측된 사실을 설명해 주세요",
        "language": "ko",
        "idempotency_key": key,
        "expected_source_sha256": preview["source"]["source_sha256"],
    }


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_http_preview_create_worker_saved_result_and_physical_drain(tmp_path, backend):
    repo = MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "http.db")
    repo.save_job(job([flow(domain="updates.example.test"), flow(source_ip="10.0.0.2")]))
    with structured_provider(adaptive) as (gateway, calls):
        app = create_app(
            settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
        )
        with TestClient(app) as client:
            caps = client.get(CAPS, headers=HEADERS)
            assert caps.status_code == 200, caps.text
            assert caps.json()["availability"] == "CONFIGURED_NOT_PROBED"
            preview = client.post(
                BASE + "/source-preview", headers=HEADERS, json={"target_ip": "2001:db8::1"}
            )
            assert preview.status_code == 200, preview.text
            assert SourcePreview.model_validate_json(preview.content).counts.matched == 2
            assert calls == []
            payload = request_from(preview.json())
            posted = client.post(BASE, headers=HEADERS, json=payload)
            assert posted.status_code == 202, posted.text
            run = InvestigationRun.model_validate_json(posted.content)
            path = BASE + "/" + run.id

            def completed():
                response = client.get(path, headers=HEADERS)
                assert response.status_code == 200, response.text
                saved = InvestigationRun.model_validate_json(response.content)
                return saved if saved.status == "COMPLETED" else None

            saved = wait_for(completed)
            assert saved.result.verdict == "NEEDS_REVIEW"
            assert saved.result.facts[0].value == 2
            assert len(calls) == 3
            runtime = app.state.investigation_runtime
            wait_for(lambda: runtime.active_count == 0)
            assert runtime.quarantined_count == 0
            steps = client.get(path + "/steps?limit=2", headers=HEADERS)
            assert steps.status_code == 200 and steps.json()["next_cursor"] == 2
            evidence = client.get(
                path + "/evidence/" + saved.result.support[0].evidence_ids[0], headers=HEADERS
            )
            assert evidence.status_code == 200
            assert evidence.json()["counts"]["matched"] == 2
            repo.delete_job("job")
            replay = client.post(BASE, headers=HEADERS, json=payload)
            assert replay.status_code == 200, replay.text
            assert InvestigationRun.model_validate_json(replay.content) == saved
            assert len(calls) == 3
            assert client.get(BASE, headers=HEADERS).json()["items"][0]["id"] == run.id
            assert client.get(path, headers={"Authorization": "Bearer viewer"}).status_code == 403
        assert runtime.close(2)
        assert not runtime.running and runtime.active_count == 0
    repo.close()


def test_settings_enable_actual_inline_dispatch_without_python_factory_flag():
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    with structured_provider(adaptive) as (gateway, calls):
        app = create_app(
            settings(
                ai_investigation_inline_enabled=True,
                ai_model_provider="openai-compatible",
                ai_model_base_url=gateway.base_url,
                ai_model_name="scripted-functional-only",
                ai_model_context_tokens=65536,
                ai_model_max_output_tokens=2048,
            ),
            repo,
        )
        with TestClient(app) as client:
            assert (
                client.get(CAPS, headers=HEADERS).json()["availability"] == "CONFIGURED_NOT_PROBED"
            )
            preview = client.post(
                BASE + "/source-preview", headers=HEADERS, json={"target_ip": "2001:db8::1"}
            ).json()
            response = client.post(BASE, headers=HEADERS, json=request_from(preview))
            assert response.status_code == 202
            path = BASE + "/" + response.json()["id"]
            wait_for(lambda: client.get(path, headers=HEADERS).json()["status"] == "COMPLETED")
            assert len(calls) == 3
        assert app.state.investigation_drained
    repo.close()
