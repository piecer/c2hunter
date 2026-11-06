"""LR03 acceptance: deliberately RED on the frozen pre-correction loop.

Run again with the independently accepted producer/store/loop overlay. Do not
weaken this to tolerate a missing execution identity or invent one in HTTP.
"""

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_http_runtime import (
    BASE,
    HEADERS,
    configured,
    request_from,
    settings,
    wait_for,
)
from tests.test_ai_investigation_loop import adaptive, structured_provider


def test_queued_gateway_drift_refused_and_history_keeps_admitted_identity(monkeypatch):
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    with structured_provider(adaptive) as (gateway, calls):
        app_a = create_app(
            settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
        )
        monkeypatch.setattr(app_a.state.investigation_service.store, "claim", lambda _: None)
        with TestClient(app_a) as client:
            preview = client.post(
                BASE + "/source-preview", headers=HEADERS, json={"target_ip": "2001:db8::1"}
            ).json()
            payload = request_from(preview)
            response = client.post(BASE, headers=HEADERS, json=payload)
            assert response.status_code == 202
            admitted = response.json()
            assert admitted["execution"]["model"] == "scripted-functional-only"
        other = configured(gateway)
        other.model = "different-declared-model"
        app_b = create_app(settings(), repo, ai_gateway=other, local_ai_worker_enabled=True)
        with TestClient(app_b) as client:
            path = BASE + "/" + admitted["id"]
            saved = wait_for(
                lambda: (
                    r
                    if (r := client.get(path, headers=HEADERS).json())["status"] == "FAILED"
                    else None
                )
            )
            assert saved["result"]["reason"] == "EXECUTION_IDENTITY_CHANGED"
            assert saved["execution"] == admitted["execution"]
            assert saved["result"]["execution"] == admitted["execution"]
            assert calls == []
            repo.delete_job("job")
            replay = client.post(BASE, headers=HEADERS, json=payload)
            assert replay.status_code == 200
            assert replay.json() == saved
        assert app_b.state.investigation_drained
    repo.close()
