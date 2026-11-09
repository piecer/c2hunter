"""Shared physical owner routes each claim to its actual service/store."""

import threading
import time

from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.ai_investigation_worker import InvestigationSupervisor
from c2hunter_controller.ai_job_investigation import JobInvestigationService
from c2hunter_controller.ai_job_investigation_store import JobInvestigationRunStore
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted
from tests.test_ai_job_investigation_service import repository as _repository

repository = _repository


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("owned worker did not converge")


def test_owned_ip_job_dispatch_and_physical_retirement(repository, monkeypatch):
    initialize_investigation_store(repository)
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        ip = InvestigationService(repository, InvestigationRunStore(repository), gateway)
        service = JobInvestigationService(
            repository,
            JobInvestigationRunStore(repository),
            gateway,
            enabled=True,
            dispatch_available=lambda: runtime.accepts_job(service),
        )
        runtime = InvestigationSupervisor(ip, job_service=service, poll_seconds=0.05)
        assert not runtime.accepts_job(service)
        entered, release = threading.Event(), threading.Event()
        original = service.execute_claim

        def held(*args, **kwargs):
            result = original(*args, **kwargs)
            entered.set()
            assert release.wait(5)
            return result

        monkeypatch.setattr(service, "execute_claim", held)
        runtime.start()
        try:
            assert runtime.accepts_job(service)
            run, _ = service.admit("alice", "job", request_for())
            assert entered.wait(4)
            assert service.get("alice", "job", run.id).status == "COMPLETED"
            assert runtime.active_count == 1
            # Completion is not physical retirement.
            assert service.store.claim("other") is None
        finally:
            release.set()
            wait_for(lambda: runtime.active_count == 0)
            assert runtime.close(3)
        assert len(calls) == 3 and runtime.quarantined_count == 0
        assert not runtime.accepts_job(service)


def test_routing_rejects_foreign_repository(repository, monkeypatch):
    from c2hunter_controller.ai_job_investigation_store import initialize_job_investigation_store
    from c2hunter_controller.repositories import MemoryRepository

    initialize_investigation_store(repository)
    other = MemoryRepository()
    initialize_job_investigation_store(other)
    import pytest

    with pytest.raises(ValueError, match="repository"):
        InvestigationSupervisor(
            InvestigationService(repository, InvestigationRunStore(repository), None),
            job_service=JobInvestigationService(other, JobInvestigationRunStore(other), None),
        )
    other.close()
