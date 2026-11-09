"""Additional independent final-store clock, HTTP send and physical-owner schedules."""

import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller import ai_investigation_store as custody
from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_http import RESPONSE_LIMIT
from c2hunter_controller.ai_investigation_worker import InvestigationSupervisor
from c2hunter_controller.ai_job_investigation_store import JobInvestigationRunStore
from c2hunter_controller.app import create_app
from tests import test_ai_job_review_lifecycle as lifecycle
from tests.test_ai_investigation_http_runtime import HEADERS, configured, settings
from tests.test_ai_investigation_loop import adaptive as ip_adaptive
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted, service_for
from tests.test_ai_job_review_lifecycle import BASE, key, wait_for

repo = lifecycle.repo
OBSERVATIONS = {}


@pytest.mark.parametrize("boundary", ["selection_encode", "final_encode"])
@pytest.mark.parametrize("expired", [False, True])
def test_store_own_300_second_deadline_after_encoding(repo, monkeypatch, boundary, expired):
    clock = [1000.0]
    store = JobInvestigationRunStore(repo, clock=lambda: clock[0])
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        svc = service_for(repo, gateway)
        svc.store = store
        run, _ = svc.admit("alice", "job", request_for())
        claim = store.claim("worker")
        assert claim["deadline"] == 1300
        fired = []
        old = custody._encode

        def encode(value):
            text = old(value)
            if type(value) is dict and value.get("id") == run.id and not fired:
                is_target = (
                    value.get("status") == "COMPLETED"
                    if boundary == "final_encode"
                    else value.get("selected_peer_ids") and value.get("selection_reserved") is False
                )
                if is_target:
                    fired.append(dict(deadline=claim["deadline"], encoding_started=clock[0]))
                    if expired:
                        clock[0] = 1301.0
            return text

        monkeypatch.setattr(custody, "_encode", encode)
        outcome = svc.execute_claim(claim, deadline_monotonic=time.monotonic() + 10)
        saved = svc.get("alice", "job", run.id)
        OBSERVATIONS[key(repo, f"wall-deadline:{boundary}:{expired}")] = dict(
            clock=clock[0],
            fired=fired,
            status=saved.status,
            selection=saved.selection.state,
            tool_calls=saved.progress.tool_calls,
            model_calls=len(calls),
            outcome=outcome.code,
            ack=outcome.acknowledge_exit,
        )
        assert len(fired) == 1
        if not expired:
            assert saved.status == "COMPLETED" and outcome.acknowledge_exit
        elif boundary == "final_encode":
            assert saved.status != "COMPLETED", (
                "store final encoding crossed its own deadline yet committed COMPLETED"
            )
        else:
            assert saved.selection.state == "PENDING", (
                "selection committed after claim deadline during encoding"
            )


def test_real_shared_workers_join_precedes_matching_store_release(repo, monkeypatch):
    entered = []
    release = threading.Event()
    joined = []
    acknowledged = []

    def policy(data, index):
        if "pool" in data:
            return adaptive(data, index)
        return ip_adaptive({"messages": [{}, {"content": json.dumps(data)}]}, index)

    with scripted(monkeypatch, policy) as (gateway, calls):
        ip = InvestigationService(repo, custody.InvestigationRunStore(repo), gateway)
        jb = service_for(repo, gateway)
        snapshot = repo.read_investigation_source("job")
        iprun, _ = ip.admit(
            "bob",
            "job",
            dict(
                target_ip="2001:db8::1",
                question="inspect",
                idempotency_key="ip",
                expected_source_sha256=snapshot.binding.source_sha256,
            ),
        )
        jrun, _ = jb.admit("alice", "job", request_for())
        native_join = threading.Thread.join

        def join(thread, *a, **kw):
            result = native_join(thread, *a, **kw)
            if thread.name.endswith("-executor") and not thread.is_alive():
                joined.append(thread.ident)
            return result

        monkeypatch.setattr(threading.Thread, "join", join)
        for name, svc in [("ip", ip), ("job", jb)]:
            execute = svc.execute_claim
            ack = svc.store.worker_exited

            def held(*a, _name=name, _execute=execute, **kw):
                outcome = _execute(*a, **kw)
                entered.append((_name, threading.current_thread().ident, outcome.claim["id"]))
                assert release.wait(4)
                return outcome

            def ack_after_join(claim, _name=name, _ack=ack):
                owner = next(item for item in entered if item[0] == _name)
                assert owner[1] in joined
                assert owner[2] == claim["id"]
                acknowledged.append(_name)
                return _ack(claim)

            monkeypatch.setattr(svc, "execute_claim", held)
            monkeypatch.setattr(svc.store, "worker_exited", ack_after_join)
        runtime = InvestigationSupervisor(ip, job_service=jb, poll_seconds=0.05)
        runtime.start()
        try:
            wait_for(lambda: len(entered) == 2)
            assert runtime.active_count == 2 and not acknowledged
            assert ip.get("bob", "job", iprun.id).status == "COMPLETED"
            assert jb.get("alice", "job", jrun.id).status == "COMPLETED"
            assert not runtime.close(0.02) and not runtime.accepting
        finally:
            release.set()
            assert runtime.close(4)
        assert sorted(acknowledged) == ["ip", "job"] and not runtime.running
        OBSERVATIONS[key(repo, "physical-join")] = dict(
            entered=entered,
            joined=joined,
            acknowledged=acknowledged,
            model_calls=len(calls),
            active=runtime.active_count,
            quarantine=runtime.quarantined_count,
        )


@pytest.mark.parametrize("launched", [False, True])
def test_supervisor_start_failure_keeps_ownership_and_truthful_close(repo, monkeypatch, launched):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        ip = InvestigationService(repo, custody.InvestigationRunStore(repo), gateway)
        jb = service_for(repo, gateway)
        runtime = InvestigationSupervisor(ip, job_service=jb, poll_seconds=0.05)
        native_start = threading.Thread.start
        original_run = runtime._run
        entered, release = threading.Event(), threading.Event()
        primary = RuntimeError("independent native-start reply lost")

        def parked():
            entered.set()
            assert release.wait(3)
            original_run()

        monkeypatch.setattr(runtime, "_run", parked)

        def start(thread):
            if thread.name == runtime.worker_id:
                if launched:
                    native_start(thread)
                raise primary
            return native_start(thread)

        monkeypatch.setattr(threading.Thread, "start", start)
        try:
            with pytest.raises(RuntimeError) as exc:
                runtime.start()
            assert exc.value is primary and runtime.owns_thread and not runtime.accepting
            if launched:
                assert entered.wait(2)
            drained = runtime.close(0.02)
            assert drained is (not launched)
            assert calls == []
        finally:
            release.set()
            assert runtime.close(3)
        OBSERVATIONS[key(repo, "start:" + str(launched))] = dict(
            initial_drained=drained,
            final_drained=not runtime.running,
            accepted=False,
            calls=len(calls),
        )


def test_http_no_headers_before_request_and_response_byte_refusal(repo, monkeypatch):
    events = []
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        app = create_app(
            settings(ai_job_investigation_enabled=True, ai_investigation_inline_enabled=True),
            repo,
            ai_gateway=configured(gateway),
        )

        async def observed(scope, receive, send):
            async def emit(message):
                if scope["type"] == "http":
                    events.append(
                        dict(
                            type=message["type"],
                            status=message.get("status"),
                            body_bytes=len(message.get("body", b"")),
                        )
                    )
                await send(message)

            await app(scope, receive, emit)

        with TestClient(observed) as client:
            post = client.post(BASE, headers=HEADERS, json=request_for())
            assert post.status_code == 202
            path = BASE + "/" + post.json()["id"]
            wait_for(lambda: client.get(path, headers=HEADERS).json()["status"] == "COMPLETED")
            svc = app.state.job_investigation_service
            monkeypatch.setattr(svc, "get", lambda *a: {"oversized": "x" * RESPONSE_LIMIT})
            events.clear()
            refused = client.get(path, headers=HEADERS)
            response_events = list(events)
            assert (
                refused.status_code == 503
                and refused.json()["error"]["code"] == "JOB_RESPONSE_LIMIT"
            )
            assert [e["status"] for e in response_events if e["type"] == "http.response.start"] == [
                503
            ]
            assert sum(e["body_bytes"] for e in response_events) < 1024
            events.clear()
            admissions = []
            monkeypatch.setattr(svc, "admit", lambda *a: admissions.append(a))
            refused = client.post(BASE, headers=HEADERS, content=iter([b" " * 8192, b" " * 8193]))
            request_events = list(events)
            assert refused.status_code == 413 and admissions == []
            assert [e["status"] for e in request_events if e["type"] == "http.response.start"] == [
                413
            ]
            assert len(calls) == 3
            OBSERVATIONS[key(repo, "http-byte-boundary")] = dict(
                response_events=response_events,
                request_events=request_events,
                admissions=len(admissions),
            )
        assert app.state.investigation_drained
