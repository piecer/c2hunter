"""Actual HTTP admission/cancellation and runtime deadlines, not direct model mocks."""

import threading
import time

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


def test_http_cancel_during_real_provider_wait_and_saved_terminal():
    entered = threading.Event()
    release = threading.Event()

    def respond(body, index):
        entered.set()
        assert release.wait(4)
        return adaptive(body, index)

    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    with structured_provider(respond) as (gateway, calls):
        app = create_app(
            settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
        )
        with TestClient(app) as client:
            preview = client.post(
                BASE + "/source-preview", json={"target_ip": "2001:db8::1"}, headers=HEADERS
            ).json()
            started = time.monotonic()
            created = client.post(BASE, headers=HEADERS, json=request_from(preview))
            assert created.status_code == 202 and time.monotonic() - started < 1
            path = BASE + "/" + created.json()["id"]
            try:
                assert entered.wait(2)
                result = client.post(path + "/cancel", headers=HEADERS)
                assert result.status_code == 200 and result.json()["status"] == "CANCELLED"
            finally:
                release.set()
            wait_for(lambda: app.state.investigation_runtime.active_count == 0)
            saved = client.get(path, headers=HEADERS).json()
            assert saved["status"] == "CANCELLED" and saved["result"] is None
            assert len(calls) == 1
        assert app.state.investigation_drained
    repo.close()


def test_queue_expiry_is_reconciled_by_real_polling_without_model(monkeypatch):
    repo = MemoryRepository()
    repo.save_job(job())
    with structured_provider(adaptive) as (gateway, calls):
        app = create_app(
            settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
        )
        store = app.state.investigation_service.store
        allowed = threading.Event()
        claim = store.claim
        monkeypatch.setattr(
            store, "claim", lambda worker: claim(worker) if allowed.is_set() else None
        )
        clock = [time.time()]
        monkeypatch.setattr(store, "clock", lambda: clock[0])
        with TestClient(app) as client:
            preview = client.post(
                BASE + "/source-preview", json={"target_ip": "2001:db8::1"}, headers=HEADERS
            ).json()
            created = client.post(BASE, headers=HEADERS, json=request_from(preview))
            assert created.status_code == 202
            path = BASE + "/" + created.json()["id"]
            clock[0] += 61
            allowed.set()
            saved = wait_for(
                lambda: (
                    r
                    if (r := client.get(path, headers=HEADERS).json())["status"] == "FAILED"
                    else None
                )
            )
            assert saved["reason"] == "QUEUE_EXPIRED"
            assert calls == []
        assert app.state.investigation_drained
    repo.close()


def test_preparation_and_owner_queue_busy_are_closed_http_errors(monkeypatch):
    from c2hunter_controller.ai_investigation import _PREPARATION_GATE

    repo = MemoryRepository()
    repo.save_job(job())
    with structured_provider(adaptive) as (gateway, calls):
        app = create_app(
            settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
        )
        monkeypatch.setattr(app.state.investigation_service.store, "claim", lambda _: None)
        with TestClient(app) as client:
            assert _PREPARATION_GATE.acquire(False) and _PREPARATION_GATE.acquire(False)
            try:
                busy = client.post(
                    BASE + "/source-preview", json={"target_ip": "2001:db8::1"}, headers=HEADERS
                )
                assert busy.status_code == 429 and busy.json()["error"]["code"] == "SOURCE_BUSY"
            finally:
                _PREPARATION_GATE.release()
                _PREPARATION_GATE.release()
            preview = client.post(
                BASE + "/source-preview", json={"target_ip": "2001:db8::1"}, headers=HEADERS
            ).json()
            for index in range(4):
                assert (
                    client.post(
                        BASE, headers=HEADERS, json=request_from(preview, str(index))
                    ).status_code
                    == 202
                )
            full = client.post(BASE, headers=HEADERS, json=request_from(preview, "extra"))
            assert full.status_code == 429 and full.json()["error"]["code"] == "OWNER_QUEUE_FULL"
            assert (
                client.post(BASE, headers=HEADERS, json=request_from(preview, "0")).status_code
                == 200
            )
            assert calls == []
    repo.close()


def test_app_shutdown_reports_undrained_then_eventual_actual_join(monkeypatch):
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    parked = threading.Event()
    release = threading.Event()
    with structured_provider(adaptive) as (gateway, _):
        app = create_app(
            settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
        )
        service = app.state.investigation_service
        execute = service.execute_claim

        def held(*args, **kwargs):
            result = execute(*args, **kwargs)
            parked.set()
            assert release.wait(7)
            return result

        monkeypatch.setattr(service, "execute_claim", held)
        runtime = app.state.investigation_runtime
        try:
            with TestClient(app) as client:
                preview = client.post(
                    BASE + "/source-preview", json={"target_ip": "2001:db8::1"}, headers=HEADERS
                ).json()
                assert (
                    client.post(BASE, headers=HEADERS, json=request_from(preview)).status_code
                    == 202
                )
                assert parked.wait(3)
            assert app.state.investigation_drained is False
            assert runtime.running and runtime.active_count == 1 and not runtime.accepting
        finally:
            release.set()
            assert runtime.close(2)
        assert not runtime.running and runtime.active_count == 0
    repo.close()
