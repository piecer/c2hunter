"""HW-R1: physical supervisor ownership survives a lost start result."""

import asyncio
import json
import logging
import threading

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.ai_analysis import AIAnalysisService
from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.ai_investigation_worker import InvestigationSupervisor
from c2hunter_controller.ai_worker import AIAnalysisWorker
from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_http_runtime import BASE, CAPS, HEADERS, configured, settings
from tests.test_ai_investigation_loop import adaptive, request_for, structured_provider


def test_failed_application_startup_publishes_truthful_drain(tmp_path, monkeypatch):
    repo = SQLiteRepository(tmp_path / "application.db")
    repo.save_job(job([flow(domain="updates.example.test")]))
    with structured_provider(adaptive) as (gateway, calls):
        app = create_app(
            settings(ai_investigation_inline_enabled=True), repo, ai_gateway=configured(gateway)
        )
        runtime = app.state.investigation_runtime
        entered, release, actual, joined, claims, failure = park_start(monkeypatch, runtime)
        close_calls = []
        close = runtime.close

        def observed_close(timeout):
            result = close(timeout)
            close_calls.append(result)
            return result

        monkeypatch.setattr(runtime, "close", observed_close)
        monkeypatch.setattr(repo, "close", lambda: pytest.fail("borrowed repository closed"))
        try:
            with pytest.raises(RuntimeError) as raised:
                with TestClient(app):
                    pytest.fail("failed startup admitted application")
            assert raised.value is failure
            assert entered.wait(2) and len(actual) == 1
            assert app.state.investigation_drained is False
            assert close_calls == [False]  # ASGI skips normal shutdown on startup failure
            assert runtime._thread is actual[0] and actual[0].is_alive()
            assert not runtime.accepting and not calls and not claims and not joined
            assert repo.connection.execute("SELECT 1").fetchone()[0] == 1
            client = TestClient(app)  # no lifespan: exercise guards even after failed startup
            try:
                assert client.get(CAPS, headers=HEADERS).json()["availability"] == "UNAVAILABLE"
                response = client.post(BASE, headers=HEADERS, json=request_for(repo))
                assert response.status_code == 503
                assert response.json()["error"]["code"] == "UNAVAILABLE"
            finally:
                client.close()
            with pytest.raises(RuntimeError, match="cannot be restarted"):
                runtime.start()
            assert len(actual) == 1
            release.set()
            shutdown = next(
                handler
                for handler in app.router.on_shutdown
                if handler.__name__ == "stop_investigation_runtime"
            )
            asyncio.run(shutdown())
            assert app.state.investigation_drained is True
            assert not actual[0].is_alive() and actual[0] in joined
        finally:
            release.set()
            drained = close(2)
            remaining = [t for t in actual if t.is_alive()]
            print({"before_rescue_drained": drained, "remaining": [t.name for t in remaining]})
            for thread in remaining:
                thread.join(2)
            assert not any(t.is_alive() for t in actual)
            SQLiteRepository.close(repo)
        assert drained and actual[0] in joined and not calls and not claims


@pytest.mark.parametrize("launched", [False, True])
def test_existing_worker_finalization_preserves_start_failure_and_health(
    tmp_path, monkeypatch, launched
):
    repo, _ = supervisor(tmp_path)

    class Queue:
        def claim(self, timeout):
            pytest.fail("legacy admission after failed startup")

        def ack(self, receipt):
            pytest.fail("blind legacy ACK")

        def depth(self):
            return 0, 0

    with structured_provider(adaptive) as (gateway, calls):
        health = tmp_path / "health.json"
        worker = AIAnalysisWorker(
            Queue(), AIAnalysisService(repo, configured(gateway)), health_path=health
        )
        runtime = worker.investigation_runtime
        entered, release, actual, joined, claims, failure = park_start(monkeypatch, runtime)
        if not launched:

            def failed_start(thread):
                raise failure

            monkeypatch.setattr(threading.Thread, "start", failed_start)
        try:
            with pytest.raises(RuntimeError) as raised:
                worker.run(threading.Event())
            assert raised.value is failure
            assert worker.investigation_drained is (not launched)
            assert json.loads(health.read_text())["status"] == (
                "STOPPING" if launched else "STOPPED"
            )
            if launched:
                assert entered.wait(2) and len(actual) == 1
                assert runtime._thread is actual[0] and actual[0].is_alive()
                assert not runtime.close(0.01) and not joined
            assert not calls and not claims and not runtime.accepting
            assert repo.connection.execute("SELECT 1").fetchone()[0] == 1
        finally:
            release.set()
            drained = runtime.close(2)
            remaining = [t for t in actual if t.is_alive()]
            print({"before_rescue_drained": drained, "remaining": [t.name for t in remaining]})
            for thread in remaining:
                thread.join(2)
            assert not any(t.is_alive() for t in actual)
            repo.close()
        assert drained and not calls and not claims


@pytest.mark.parametrize("cleanup_fault", ["executor-spawn", "drain-log"])
def test_primary_start_error_survives_secondary_cleanup_failure(
    tmp_path, monkeypatch, cleanup_fault
):
    repo = SQLiteRepository(tmp_path / "secondary-cleanup.db")
    repo.save_job(job([flow(domain="updates.example.test")]))

    class StartupFailure(RuntimeError):
        pass

    primary = StartupFailure("primary supervisor start result lost")
    secondary = RuntimeError("secondary cleanup failure")
    entered, release = threading.Event(), threading.Event()
    actual, joined, close_calls, faults, claims, acknowledgements = [], [], [], [], [], []
    native_start, native_join = threading.Thread.start, threading.Thread.join
    with structured_provider(adaptive) as (gateway, model_calls):
        app = create_app(
            settings(ai_investigation_inline_enabled=True), repo, ai_gateway=configured(gateway)
        )
        runtime = app.state.investigation_runtime
        stop_latch = runtime._stop
        startup = next(
            h for h in app.router.on_startup if h.__name__ == "start_investigation_runtime"
        )
        shutdown = next(
            h for h in app.router.on_shutdown if h.__name__ == "stop_investigation_runtime"
        )
        real_run, real_close = runtime._run, runtime.close

        def parked():
            entered.set()
            assert release.wait(5)
            real_run()

        def start(thread):
            if thread.name == runtime.worker_id:
                native_start(thread)
                actual.append(thread)
                faults.append("supervisor-start")
                raise primary
            if cleanup_fault == "executor-spawn" and thread.name.startswith("asyncio_"):
                faults.append(cleanup_fault)
                raise secondary
            return native_start(thread)

        def join(thread, *args, **kwargs):
            result = native_join(thread, *args, **kwargs)
            if thread in actual and not thread.is_alive():
                joined.append(thread)
            return result

        def close(timeout):
            result = real_close(timeout)
            close_calls.append((timeout, result))
            return result

        class FailingDrainHandler(logging.Handler):
            def emit(self, record):
                if (
                    record.getMessage()
                    == "Investigation shutdown retains unresolved worker ownership"
                ):
                    faults.append("drain-log")
                    raise secondary

        logger = logging.getLogger("c2hunter_controller.app")
        sink = FailingDrainHandler()
        monkeypatch.setattr(runtime, "_run", parked)
        monkeypatch.setattr(runtime, "close", close)
        monkeypatch.setattr(runtime.service.store, "claim", lambda *_: claims.append(True))
        monkeypatch.setattr(
            runtime.service.store, "worker_exited", lambda *_: acknowledgements.append(True)
        )
        monkeypatch.setattr(threading.Thread, "join", join)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(threading.Thread, "start", start)
                if cleanup_fault == "drain-log":
                    logger.addHandler(sink)
                try:
                    with pytest.raises(RuntimeError) as raised:
                        asyncio.run(startup())
                finally:
                    logger.removeHandler(sink)
            assert entered.wait(2)
            assert faults == ["supervisor-start", cleanup_fault]
            assert len(actual) == 1 and actual[0] is runtime._thread and actual[0].is_alive()
            assert runtime._stop is stop_latch and stop_latch.is_set()
            assert app.state.investigation_drained is False
            assert not runtime.accepting and not model_calls and not claims and not acknowledgements
            assert not joined
            assert close_calls == ([] if cleanup_fault == "executor-spawn" else [(2.0, False)])
            assert repo.connection.execute("SELECT 1").fetchone()[0] == 1
            with pytest.raises(RuntimeError, match="cannot be restarted"):
                runtime.start()
            client = TestClient(app)  # no lifespan: failed-start admission stays closed
            try:
                assert client.get(CAPS, headers=HEADERS).json()["availability"] == "UNAVAILABLE"
                response = client.post(BASE, headers=HEADERS, json=request_for(repo))
                assert response.status_code == 503
                assert response.json()["error"]["code"] == "UNAVAILABLE"
            finally:
                client.close()
        finally:
            release.set()
            asyncio.run(shutdown())
            remaining = [t for t in actual if t.is_alive()]
            print(
                {
                    "secondary_fault": cleanup_fault,
                    "remaining_before_rescue": [t.name for t in remaining],
                }
            )
            for thread in remaining:
                native_join(thread, 2)
            assert not remaining
            assert app.state.investigation_drained is True and actual[0] in joined
            assert runtime._thread is actual[0] and runtime._stop is stop_latch
            assert stop_latch.is_set() and not runtime.accepting
            assert not model_calls and not claims and not acknowledgements
            repo.close()
        assert raised.value is primary
        assert type(raised.value) is StartupFailure
        assert str(raised.value) == "primary supervisor start result lost"


def supervisor(tmp_path):
    repo = SQLiteRepository(tmp_path / "supervisor.db")
    initialize_investigation_store(repo)
    service = InvestigationService(repo, InvestigationRunStore(repo), None)
    return repo, InvestigationSupervisor(service, poll_seconds=0.05)


def park_start(monkeypatch, runtime):
    entered, release = threading.Event(), threading.Event()
    actual, joined, claims = [], [], []
    run = runtime._run
    native_start, native_join = threading.Thread.start, threading.Thread.join
    failure = RuntimeError("supervisor start result lost")

    def parked():
        entered.set()
        assert release.wait(5)
        run()

    def uncertain(thread):
        result = native_start(thread)
        if thread.name == runtime.worker_id:
            actual.append(thread)
            raise failure
        return result

    def join(thread, *args, **kwargs):
        result = native_join(thread, *args, **kwargs)
        if thread in actual and not thread.is_alive():
            joined.append(thread)
        return result

    monkeypatch.setattr(runtime, "_run", parked)
    monkeypatch.setattr(runtime.service.store, "claim", lambda *_: claims.append(True))
    monkeypatch.setattr(threading.Thread, "start", uncertain)
    monkeypatch.setattr(threading.Thread, "join", join)
    return entered, release, actual, joined, claims, failure


def test_before_native_start_failure_can_close_without_masking_error(tmp_path, monkeypatch):
    repo, runtime = supervisor(tmp_path)
    failure = RuntimeError("before native start")

    def failed_start(thread):
        raise failure

    monkeypatch.setattr(threading.Thread, "start", failed_start)
    with pytest.raises(RuntimeError) as raised:
        runtime.start()
    assert raised.value is failure
    assert runtime.close(0.01)
    assert not runtime.accepting
    assert not any(t.name == runtime.worker_id for t in threading.enumerate())
    repo.close()


def test_pending_native_bootstrap_is_not_proved_unstarted(tmp_path, monkeypatch):
    repo, runtime = supervisor(tmp_path)
    entered, release = threading.Event(), threading.Event()
    actual = []
    native_init, bootstrap = threading.Thread.__init__, threading.Thread._bootstrap
    failure = RuntimeError("native start observation interrupted")

    def delayed_bootstrap(thread):
        entered.set()
        assert release.wait(5)
        bootstrap(thread)

    def init(thread, *args, **kwargs):
        native_init(thread, *args, **kwargs)
        if thread.name == runtime.worker_id:
            actual.append(thread)
            monkeypatch.setattr(thread, "_bootstrap", lambda: delayed_bootstrap(thread))

            def interrupted_wait(*args, **kwargs):
                assert entered.wait(2)
                raise failure

            monkeypatch.setattr(thread._started, "wait", interrupted_wait)

    monkeypatch.setattr(threading.Thread, "__init__", init)
    try:
        with pytest.raises(RuntimeError) as raised:
            runtime.start()
        assert raised.value is failure
        assert runtime._thread is actual[0]
        assert actual[0].ident is None and not actual[0].is_alive()
        assert actual[0] in threading.enumerate()  # CPython native-start limbo
        assert not runtime.close(0.01)
        assert not runtime.accepting
        assert repo.connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        release.set()
        # _started.wait was the fault seam; observe real bootstrap completion.
        assert actual[0]._started.__class__.wait(actual[0]._started, 2)
        drained = runtime.close(2)
        remaining = [t for t in actual if t.is_alive()]
        print({"before_rescue_drained": drained, "remaining": [t.name for t in remaining]})
        for thread in remaining:
            thread.join(2)
        assert not any(t.is_alive() for t in actual)
        repo.close()
    assert drained


def test_lost_start_result_retains_owner_until_physical_join(tmp_path, monkeypatch):
    repo, runtime = supervisor(tmp_path)
    entered, release, actual, joined, claims, failure = park_start(monkeypatch, runtime)
    try:
        with pytest.raises(RuntimeError) as raised:
            runtime.start()
        assert raised.value is failure
        assert entered.wait(2) and len(actual) == 1
        assert runtime._thread is actual[0]
        assert not runtime.accepting
        assert not runtime.close(0.01)
        assert actual[0].is_alive() and not joined and not claims
        assert repo.connection.execute("SELECT 1").fetchone()[0] == 1
        with pytest.raises(RuntimeError, match="cannot be restarted"):
            runtime.start()
        release.set()
        assert runtime.close(2)
        assert actual[0] in joined and not actual[0].is_alive()
        assert not claims and not runtime.accepting
    finally:
        # Observe product drain before the test's last-resort owned-thread rescue.
        release.set()
        drained = runtime.close(2)
        remaining = [thread for thread in actual if thread.is_alive()]
        print({"before_rescue_drained": drained, "remaining": [t.name for t in remaining]})
        for thread in remaining:
            thread.join(2)
        assert not any(thread.is_alive() for thread in actual)
        repo.close()
