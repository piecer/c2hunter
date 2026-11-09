"""Approved late-COMMIT outcome through the actual supervisor; no runtime changes."""

import json
import sqlite3
import time

import pytest

from c2hunter_controller import ai_investigation_store as custody
from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_worker import InvestigationSupervisor
from c2hunter_controller.ai_job_investigation_store import initialize_job_investigation_store
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted, service_for
from tests.test_ai_job_investigation_source import flow, job
from tests.test_ai_job_review_lifecycle import wait_for

OBSERVATIONS = {}


@pytest.mark.parametrize("fault", ["late_commit", "ambiguous", "on_time_commit"])
def test_supervisor_preserves_real_committed_row_and_ack_boundary(tmp_path, monkeypatch, fault):
    repo = SQLiteRepository(tmp_path / "supervisor.db")
    repo.save_job(job([flow(domain="updates.example.test")]))
    custody.initialize_investigation_store(repo)
    initialize_job_investigation_store(repo)
    native = repo.connection
    clock = [1000.0]
    outcomes, acknowledgments, fired = [], [], []
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        svc = service_for(repo, gateway)
        svc.store.clock = lambda: clock[0]
        run, _ = svc.admit("alice", "job", request_for())
        execute = svc.execute_claim
        acknowledge = svc.store.worker_exited

        def observe(claim, *, deadline_monotonic):
            assert claim["deadline"] == 1300.0
            # The real supervisor still supplied its full original 300-second budget.
            assert 290 < deadline_monotonic - time.monotonic() <= 300
            result = execute(claim, deadline_monotonic=deadline_monotonic)
            outcomes.append(result)
            return result

        def ack(claim):
            acknowledgments.append(claim["id"])
            return acknowledge(claim)

        class Connection:
            def __getattr__(self, name):
                return getattr(native, name)

            def commit(self):
                row = native.execute(
                    "SELECT data FROM objects WHERE kind=? AND id=?",
                    ("ai_job_investigation_state_v1", run.id),
                ).fetchone()
                final = row and json.loads(row[0])["status"] == "COMPLETED" and not fired
                if final:
                    fired.append(fault)
                    if fault == "late_commit":
                        clock[0] = 1301.0
                native.commit()
                if final and fault == "ambiguous":
                    raise sqlite3.OperationalError("commit reply lost")

        repo.connection = Connection()
        monkeypatch.setattr(svc, "execute_claim", observe)
        monkeypatch.setattr(svc.store, "worker_exited", ack)
        ip = InvestigationService(repo, custody.InvestigationRunStore(repo), gateway)
        runtime = InvestigationSupervisor(ip, job_service=svc, poll_seconds=0.05)
        runtime.start()
        try:
            wait_for(lambda: outcomes and (acknowledgments or runtime.quarantined_count))
            drained = runtime.close(4)
            assert not runtime.running and runtime.active_count == 0
            with sqlite3.connect("file:" + repo._path + "?mode=ro", uri=True) as reader:
                durable = json.loads(
                    reader.execute(
                        "SELECT data FROM objects WHERE kind=? AND id=?",
                        ("ai_job_investigation_state_v1", run.id),
                    ).fetchone()[0]
                )
            assert fired == [fault] and len(calls) == 3 and len(outcomes) == 1
            outcome = outcomes[0]
            assert durable["status"] == "COMPLETED"
            if fault == "on_time_commit":
                assert drained and outcome.acknowledge_exit and outcome.code is None
                assert acknowledgments == [run.id] and durable["slot"] == "FREE"
                assert runtime.quarantined_count == 0
            else:
                assert not drained and not outcome.acknowledge_exit
                assert outcome.code == "STORAGE_OUTCOME_UNKNOWN"
                assert acknowledgments == [] and durable["slot"] == "HELD"
                assert runtime.quarantined_count == 1 and not runtime.accepting
                with pytest.raises(custody.InvestigationOutcomeUnknown):
                    svc.admit("alice", "job", request_for())
            OBSERVATIONS[fault] = dict(
                status=durable["status"],
                slot=durable["slot"],
                outcome=outcome.code,
                acknowledge_exit=outcome.acknowledge_exit,
                worker_exited_calls=acknowledgments,
                quarantine=runtime.quarantined_count,
                drained=drained,
                model_calls=len(calls),
                clock=clock[0],
                original_claim_deadline=1300.0,
            )
        finally:
            runtime.close(4)
            assert not runtime.running and runtime.active_count == 0
            repo.connection = native
            repo.close()
