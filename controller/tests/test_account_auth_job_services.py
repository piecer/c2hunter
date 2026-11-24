"""Both real investigation services with SQL custody and a fake HTTP transport."""

import time

import pytest
from test_account_auth_job_investigations import authority

from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.ai_job_investigation import JobInvestigationService
from c2hunter_controller.ai_job_investigation_store import (
    JobInvestigationRunStore,
    initialize_job_investigation_store,
)
from c2hunter_controller.auth_models import AuthError
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_ai_investigation_loop import finish
from tests.test_ai_investigation_loop import request_for as ip_request
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted
from tests.test_ai_job_investigation_source import flow, job


@pytest.mark.parametrize("native_handoff", [False, True])
@pytest.mark.parametrize("family", ["ip_investigation", "job_investigation"])
def test_real_service_terminal_redelivery_repairs_without_model(
    family, tmp_path, monkeypatch, native_handoff
):
    repo = SQLiteRepository(tmp_path / "domain.sqlite")
    try:
        repo.save_job(job([flow(domain="updates.example.test")]))
        auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
        auth.initialize()
        responder = (
            adaptive
            if family == "job_investigation"
            else lambda data, _: finish(data["observations"][0])
        )
        with scripted(monkeypatch, responder) as (gateway, requests):
            if family == "job_investigation":
                initialize_job_investigation_store(repo)
                store = JobInvestigationRunStore(repo)
                service = JobInvestigationService(
                    repo, store, gateway, enabled=True, dispatch_available=lambda: True
                )
                request = request_for()
            else:
                initialize_investigation_store(repo)
                store = InvestigationRunStore(repo)
                service = InvestigationService(repo, store, gateway)
                request = ip_request(repo)
            store.auth_store = auth
            if native_handoff:
                from concurrent.futures import ThreadPoolExecutor
                from functools import partial

                with authority(auth) as context:
                    callback = partial(context.reserve, family)
                with ThreadPoolExecutor(max_workers=1) as executor:
                    row, created = executor.submit(
                        service.admit, "alice", "job", request, before_publish=callback
                    ).result(5)
            else:
                with authority(auth):
                    row, created = service.admit("alice", "job", request)
            assert created
            original = auth.pending_job_links()["items"][0]
            with authority(auth, "bob"):
                replay, created = service.admit("alice", "job", request)
            assert not created and replay.id == row.id
            assert auth.pending_job_links()["items"][0] == original
            finish_audit = auth.finish_job

            def unavailable(*args):
                raise AuthError("SECURITY_UNAVAILABLE", 503)

            monkeypatch.setattr(auth, "finish_job", unavailable)
            outcome = service.run_next("worker")
            assert outcome.acknowledge_exit
            assert service.get("alice", "job", row.id).status == "COMPLETED"
            assert auth.job_audit_status(family, row.id) == "pending"
            count = len(requests)
            monkeypatch.setattr(auth, "finish_job", finish_audit)
            service.execute_claim(outcome.claim, deadline_monotonic=time.monotonic() + 30)
            assert auth.job_audit_status(family, row.id) == "complete"
            assert len(requests) == count
    finally:
        repo.close()
