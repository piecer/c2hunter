"""Custody fault/cancellation boundaries through the concrete JOB broker."""

import threading
import time

import pytest

from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_store import (
    InvestigationOutcomeUnknown,
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.ai_investigation_worker import InvestigationSupervisor
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted, service_for
from tests.test_ai_job_investigation_service import repository as _repository
from tests.test_ai_job_investigation_worker import wait_for

repository = _repository


@pytest.mark.parametrize("boundary", ["selection", "evidence", "publish"])
def test_unknown_write_outcome_retains_quarantine(repository, monkeypatch, boundary):
    initialize_investigation_store(repository)
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        service = service_for(repository, gateway)
        store = service.store
        method = {
            "selection": "commit_selection",
            "evidence": "save_evidence",
            "publish": "publish",
        }[boundary]
        original = getattr(store, method)
        fired = []

        def unknown(*args, **kwargs):
            original(*args, **kwargs)
            fired.append(True)
            raise InvestigationOutcomeUnknown("STORAGE_OUTCOME_UNKNOWN")

        monkeypatch.setattr(store, method, unknown)
        run, _ = service.admit("alice", "job", request_for())
        runtime = InvestigationSupervisor(
            InvestigationService(repository, InvestigationRunStore(repository), gateway),
            job_service=service,
            poll_seconds=0.05,
        )
        runtime.start()
        try:
            wait_for(lambda: runtime.quarantined_count == 1)
            assert fired == [True] and not runtime.accepting
            assert service.store.claim("other") is None
            assert len(calls) == (3 if boundary == "publish" else 1)
            assert service.get("alice", "job", run.id).selection.state == "COMMITTED"
        finally:
            assert not runtime.close(3)
        assert not runtime.running and runtime.active_count == 0


def test_cancellation_during_transport_is_terminal_and_join_precedes_release(
    repository, monkeypatch
):
    initialize_investigation_store(repository)
    entered, release = threading.Event(), threading.Event()

    def respond(data, index):
        entered.set()
        assert release.wait(4)
        return adaptive(data, index)

    with scripted(monkeypatch, respond) as (gateway, calls):
        service = service_for(repository, gateway)
        queued, _ = service.admit("alice", "job", request_for())
        runtime = InvestigationSupervisor(
            InvestigationService(repository, InvestigationRunStore(repository), gateway),
            job_service=service,
            poll_seconds=0.05,
        )
        runtime.start()
        try:
            assert entered.wait(3)
            cancelled = service.cancel("alice", "job", queued.id)
            assert cancelled.status == "CANCELLED" and cancelled.result is None
            assert runtime.active_count == 1
            assert cancelled.progress.model_calls == cancelled.progress.transport_attempts == 1
        finally:
            release.set()
            wait_for(lambda: runtime.active_count == 0)
            assert runtime.close(3)
        assert service.get("alice", "job", queued.id) == cancelled and len(calls) == 1


def test_stale_claim_and_null_intent_concurrent_winner(repository, monkeypatch):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        service = service_for(repository, gateway)
        original = repository.read_job_investigation_source
        entered = [False]

        def read(*args, **kwargs):
            if not entered[0]:
                entered[0] = True
                winner, _ = service.admit("alice", "job", request_for())
                repository.delete_job("job")
            return original(*args, **kwargs)

        monkeypatch.setattr(repository, "read_job_investigation_source", read)
        run, created = service.admit("alice", "job", request_for())
        assert not created and run.request.expected_source_sha256 is None
        claim = service.store.claim("worker")
        latest = service.store.heartbeat(claim)
        outcome = service.execute_claim(claim, deadline_monotonic=time.monotonic() + 300)
        assert outcome.code == "STALE_CLAIM" and not outcome.acknowledge_exit and calls == []
        good = service.execute_claim(latest, deadline_monotonic=time.monotonic() + 300)
        assert good.acknowledge_exit and service.get("alice", "job", run.id).status == "COMPLETED"


def test_ip_and_job_share_two_executors_and_correct_stores(repository, monkeypatch):
    from tests.test_ai_investigation_loop import adaptive as ip_adaptive

    initialize_investigation_store(repository)
    entered = []
    release = threading.Event()

    def respond(data, index):
        # Wrap IP context back into the actual provider request shape expected by
        # its retained scripted policy. No legacy provider fixture is launched.
        if "pool" not in data:
            return ip_adaptive(
                {"messages": [{}, {"content": __import__("json").dumps(data)}]}, index
            )
        return adaptive(data, index)

    with scripted(monkeypatch, respond) as (gateway, calls):
        service = service_for(repository, gateway)
        ip = InvestigationService(repository, InvestigationRunStore(repository), gateway)
        for svc in (service, ip):
            original = svc.execute_claim

            def held(*a, _original=original, _svc=svc, **kw):
                entered.append(_svc)
                assert release.wait(5)
                return _original(*a, **kw)

            monkeypatch.setattr(svc, "execute_claim", held)
        jobrun, _ = service.admit("alice", "job", request_for())
        snapshot = repository.read_investigation_source("job")
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
        runtime = InvestigationSupervisor(ip, job_service=service, poll_seconds=0.05)
        runtime.start()
        try:
            wait_for(lambda: len(entered) == 2)
            assert runtime.active_count == 2 and set(entered) == {ip, service}
        finally:
            release.set()
            wait_for(lambda: runtime.active_count == 0)
            assert runtime.close(3)
        assert service.get("alice", "job", jobrun.id).status == "COMPLETED"
        assert ip.get("bob", "job", iprun.id).status == "COMPLETED"
