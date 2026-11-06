"""Physical join, queue fairness, shutdown and ambiguous-outcome regressions."""

import threading

import pytest

from c2hunter_controller.ai_analysis import AIAnalysisService
from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.ai_investigation_worker import InvestigationSupervisor
from c2hunter_controller.ai_worker import AIAnalysisWorker
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_http_runtime import configured, wait_for
from tests.test_ai_investigation_loop import adaptive, request_for, structured_provider


def prepared(gateway):
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    initialize_investigation_store(repo)
    service = InvestigationService(repo, InvestigationRunStore(repo), gateway)
    run, _ = service.admit("alice", "job", request_for(repo))
    return repo, service, run


def test_existing_worker_dispatches_investigation_while_legacy_claim_blocks():
    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()

    class LegacyQueue:
        def depth(self):
            return 0, 0

        def claim(self, timeout):
            entered.set()
            assert release.wait(5)
            return None

    with structured_provider(adaptive) as (gateway, calls):
        repo, service, run = prepared(gateway)
        worker = AIAnalysisWorker(LegacyQueue(), AIAnalysisService(repo, configured(gateway)))
        thread = threading.Thread(target=worker.run, args=(stopped,))
        thread.start()
        try:
            assert entered.wait(2)
            wait_for(lambda: service.get("alice", "job", run.id).status == "COMPLETED", seconds=3)
            assert len(calls) == 3
            stopped.set()
            wait_for(lambda: not worker.investigation_runtime.running, seconds=1)
            assert thread.is_alive()  # old queue is still blocked, new queue stopped independently
        finally:
            stopped.set()
            release.set()
            thread.join(4)
        assert not thread.is_alive()
        assert worker.investigation_runtime.close(1)
        assert not worker.investigation_runtime.running
    repo.close()


def test_join_precedes_exit_ack_and_short_close_retains_slot(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    acknowledgements = []
    with structured_provider(adaptive) as (gateway, _):
        repo, service, run = prepared(gateway)
        execute = service.execute_claim
        executor = []

        def parked(*args, **kwargs):
            executor.append(threading.current_thread())
            result = execute(*args, **kwargs)
            entered.set()
            assert release.wait(5)
            return result

        monkeypatch.setattr(service, "execute_claim", parked)
        original = service.store.worker_exited

        def acknowledge(claim):
            assert not executor[0].is_alive(), "ACK before physical exit"
            acknowledgements.append(claim["id"])
            return original(claim)

        monkeypatch.setattr(service.store, "worker_exited", acknowledge)
        runtime = InvestigationSupervisor(service, poll_seconds=0.05)
        runtime.start()
        try:
            assert entered.wait(3)
            assert service.get("alice", "job", run.id).status == "COMPLETED"
            assert not runtime.close(0.01)
            assert runtime.active_count == 1 and not acknowledgements
            assert service.store.claim("peer") is None  # same owner retains slot
        finally:
            release.set()
            assert runtime.close(2)
        assert acknowledgements == [run.id]
    repo.close()


def test_unknown_commit_quarantines_without_ack_or_resubmission(monkeypatch):
    from c2hunter_controller.ai_investigation_store import InvestigationOutcomeUnknown

    with structured_provider(adaptive) as (gateway, calls):
        repo, service, run = prepared(gateway)
        publish = service.store.publish

        def ambiguous(*args):
            publish(*args)
            raise InvestigationOutcomeUnknown("private driver token")

        monkeypatch.setattr(service.store, "publish", ambiguous)
        monkeypatch.setattr(service.store, "worker_exited", lambda *_: pytest.fail("uncertain ACK"))
        runtime = InvestigationSupervisor(service, poll_seconds=0.05)
        runtime.start()
        wait_for(lambda: runtime.quarantined_count == 1)
        assert not runtime.close(2)
        assert not runtime.running and runtime.active_count == 0
        assert service.get("alice", "job", run.id).status == "COMPLETED"
        assert len(calls) == 3
        assert not runtime.accepting
    repo.close()


def test_two_executors_bound_and_no_peer_cleanup(monkeypatch):
    with structured_provider(adaptive) as (gateway, calls):
        repo, service, first = prepared(gateway)
        second, _ = service.admit("bob", "job", request_for(repo, idempotency_key="second"))
        third, _ = service.admit("carol", "job", request_for(repo, idempotency_key="third"))
        entered = []
        release = threading.Event()
        original = service.execute_claim

        def blocked(claim, **kwargs):
            entered.append(claim["id"])
            assert release.wait(4)
            return original(claim, **kwargs)

        monkeypatch.setattr(service, "execute_claim", blocked)
        monkeypatch.setattr(repo, "close", lambda: pytest.fail("borrowed repository closed"))
        runtime = InvestigationSupervisor(service, poll_seconds=0.05)
        runtime.start()
        try:
            wait_for(lambda: len(entered) == 2)
            assert runtime.active_count == 2
            assert service.get("carol", "job", third.id).status == "QUEUED"
            assert not runtime.close(0.02)
            assert runtime.active_count == 2 and not runtime.accepting
            assert service.get("carol", "job", third.id).status == "QUEUED"
        finally:
            release.set()
            assert runtime.close(2)
        assert service.get("alice", "job", first.id).status == "CANCELLED"
        assert service.get("bob", "job", second.id).status == "CANCELLED"
        assert len(calls) == 0


def test_executor_start_failure_quarantines_without_join_or_model(monkeypatch):
    with structured_provider(adaptive) as (gateway, calls):
        repo, service, _ = prepared(gateway)
        start = threading.Thread.start

        def fail(thread):
            if thread.name.endswith("-executor"):
                raise RuntimeError("injected start failure")
            return start(thread)

        monkeypatch.setattr(threading.Thread, "start", fail)
        monkeypatch.setattr(service.store, "worker_exited", lambda *_: pytest.fail("unstarted ACK"))
        runtime = InvestigationSupervisor(service, poll_seconds=0.05)
        runtime.start()
        wait_for(lambda: runtime.quarantined_count == 1)
        assert not runtime.close(2)
        assert not runtime.running and runtime.active_count == 0 and len(calls) == 0
    repo.close()


def test_original_deadline_captured_before_delayed_claim(monkeypatch):
    import time

    with structured_provider(adaptive) as (gateway, _):
        repo, service, _ = prepared(gateway)
        claim = service.store.claim
        times = []
        original = service.execute_claim

        def delayed(worker_id):
            before = time.monotonic()
            result = claim(worker_id)
            if result:
                time.sleep(0.1)
                times.append(before)
            return result

        def execute(claim, *, deadline_monotonic):
            assert deadline_monotonic <= times[0] + 300
            return original(claim, deadline_monotonic=deadline_monotonic)

        monkeypatch.setattr(service.store, "claim", delayed)
        monkeypatch.setattr(service, "execute_claim", execute)
        runtime = InvestigationSupervisor(service, poll_seconds=0.05)
        runtime.start()
        wait_for(lambda: bool(times) and runtime.active_count == 0)
        assert runtime.close(2)
    repo.close()


def test_idle_polling_is_bounded_and_has_no_extra_heartbeat(monkeypatch):
    import time

    repo = MemoryRepository()
    initialize_investigation_store(repo)
    service = InvestigationService(repo, InvestigationRunStore(repo), None)
    claims = []
    original = service.store.claim

    def counted(worker):
        claims.append(time.monotonic())
        return original(worker)

    monkeypatch.setattr(service.store, "claim", counted)
    monkeypatch.setattr(service.store, "heartbeat", lambda *_: pytest.fail("supervisor heartbeat"))
    runtime = InvestigationSupervisor(service, poll_seconds=0.05)
    runtime.start()
    time.sleep(0.18)
    assert runtime.close(1)
    assert 2 <= len(claims) <= 5
    assert all(b - a >= 0.045 for a, b in zip(claims, claims[1:], strict=False))
    repo.close()


def test_stop_winning_during_claim_never_starts_model(monkeypatch):
    with structured_provider(adaptive) as (gateway, calls):
        repo, service, run = prepared(gateway)
        stopped = threading.Event()
        claim = service.store.claim

        def stop_after_claim(worker):
            result = claim(worker)
            stopped.set()
            return result

        monkeypatch.setattr(service.store, "claim", stop_after_claim)
        runtime = InvestigationSupervisor(service, poll_seconds=0.05)
        runtime.start(stopped)
        wait_for(lambda: not runtime.running)
        assert runtime.close(1)
        assert service.get("alice", "job", run.id).status == "CANCELLED"
        assert calls == []
    repo.close()


def test_blocked_investigation_http_does_not_starve_existing_queue():
    from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
    from tests.test_ai_worker import candidate

    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()

    def respond(body, index):
        entered.set()
        assert release.wait(4)
        return adaptive(body, index)

    with structured_provider(respond) as (gateway, calls):
        repo, _, _ = prepared(gateway)
        repo.save_job({"id": "legacy", "status": "COMPLETED"})
        repo.save_candidates("legacy", [candidate()])
        service = AIAnalysisService(repo, configured(gateway))
        old, _ = service.create_run(
            analysis_job_id="legacy",
            idempotency_key="legacy",
            candidate_limit=5,
            created_by="analyst",
        )
        service.cancel(old["id"], "terminal replay fixture")
        queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": old["id"], "receipt": "old-receipt"}])
        original = queue.claim

        def gated(timeout):
            assert entered.wait(2)
            if queue.acked:
                stopped.wait(2)
                return None
            return original(timeout)

        queue.claim = gated
        worker = AIAnalysisWorker(queue, service)
        thread = threading.Thread(target=worker.run, args=(stopped,))
        thread.start()
        try:
            wait_for(lambda: queue.acked == ["old-receipt"])
            assert not release.is_set() and len(calls) == 1
            assert worker.processed_runs == 1
        finally:
            release.set()
            stopped.set()
            thread.join(3)
        assert not thread.is_alive() and worker.investigation_drained
    repo.close()
