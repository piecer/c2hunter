"""AI service admission and terminal audit use real SQL and fake inference."""

import pytest
from test_account_auth_job_investigations import assert_one_terminal, authority
from test_ai_analysis import candidate, completed_job

from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway
from c2hunter_controller.auth_models import AuthError
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.repositories import SQLiteRepository


@pytest.fixture
def domain(tmp_path):
    repo = SQLiteRepository(tmp_path / "domain.sqlite")
    repo.create_job({**completed_job(), "idempotency_key": "analysis"})
    repo.save_candidates("job-1", [candidate()])
    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    service = AIAnalysisService(repo, FakeGateway())
    service.auth_store = auth
    yield service, auth
    repo.connection.close()


def create(service, **kwargs):
    return service.create_run(
        analysis_job_id="job-1",
        idempotency_key="key",
        candidate_limit=1,
        created_by="user:alice",
        **kwargs,
    )


@pytest.mark.parametrize("inline", [False, True])
def test_reservation_outage_prevents_ai_run_publication(domain, monkeypatch, inline):
    service, auth = domain

    def unavailable(*args):
        raise AuthError("SECURITY_UNAVAILABLE", 503)

    monkeypatch.setattr(auth, "reserve_job", unavailable)
    calls = []
    monkeypatch.setattr(service.gateway, "assess", lambda bundle: calls.append(bundle))
    with authority(auth), pytest.raises(AuthError):
        if inline:
            service.create_and_execute(
                analysis_job_id="job-1",
                idempotency_key="key",
                candidate_limit=1,
                created_by="user:alice",
            )
        else:
            create(service)
    assert service.repository.list_ai_runs("job-1") == []
    assert calls == []


def test_admitted_actor_survives_logout_and_real_new_user_replay(domain):
    from uuid import uuid4

    from c2hunter_controller.auth_job_context import bind_job_audit
    from c2hunter_controller.security import Role

    service, auth = domain
    password = "generated-Strong-Password-42"
    auth.bootstrap("first", password)
    first = auth.login("first", password)
    auth.create_user(first.token, "second", password, Role.ANALYST)
    second_initial = auth.login("second", password)
    auth.change_password(second_initial.token, password, password + "-changed")
    second = auth.login("second", password + "-changed")
    with bind_job_audit(auth, first.actor, str(uuid4()), uuid4().hex):
        run, created = create(service)
    assert created
    auth.logout(first.token)
    with bind_job_audit(auth, second.actor, str(uuid4()), uuid4().hex):
        replay, created = create(service)
    assert not created and replay["id"] == run["id"]
    assert service.execute(run["id"])["status"] == "COMPLETED"
    assert_one_terminal(auth, run["id"], first.user.id)


def test_ai_terminal_worker_repair_precedes_ack(domain):
    from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
    from c2hunter_controller.ai_worker import AIAnalysisWorker

    service, auth = domain
    with authority(auth):
        run, _ = create(service)
    service.auth_store = None
    service.cancel(run["id"], "cancel")
    service.auth_store = auth

    class ObservedQueue(MemoryAIAnalysisWorkerQueue):
        def ack(self, receipt):
            assert auth.job_audit_status("ai_run", run["id"]) == "complete"
            super().ack(receipt)

    queue = ObservedQueue(
        [{"ai_run_id": run["id"], "receipt": "one"}, {"ai_run_id": run["id"], "receipt": "two"}]
    )
    worker = AIAnalysisWorker(queue, service)
    assert worker.run_once(timeout=0)
    assert worker.run_once(timeout=0)
    assert queue.acked == ["one", "two"]
    assert service.repository.list_ai_assessments(run["id"]) == []
    assert_one_terminal(auth, run["id"])


def test_ai_native_handoff_reserves_before_independent_read(domain, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from functools import partial

    service, auth = domain
    observer = SQLiteRepository(service.repository._path)
    original = service.repository.create_ai_run
    observed = []

    def publish(run):
        assert observer.list_ai_runs("job-1") == []
        assert auth.job_audit_status("ai_run", run["id"]) == "pending"
        observed.append(run["id"])
        return original(run)

    monkeypatch.setattr(service.repository, "create_ai_run", publish)
    try:
        with authority(auth) as context:
            callback = partial(context.reserve, "ai_run")
        with ThreadPoolExecutor(max_workers=1) as executor:
            run, created = executor.submit(create, service, before_publish=callback).result(5)
        assert created and observed == [run["id"]]
        assert observer.get_ai_run(run["id"])["status"] == "QUEUED"
    finally:
        observer.close()


@pytest.mark.parametrize("terminal", ["execute", "cancel"])
def test_ai_terminal_gap_repaired_without_provider_replay(domain, monkeypatch, terminal):
    service, auth = domain
    with authority(auth):
        run, _ = create(service)
    original = auth.pending_job_links()["items"][0]
    with authority(auth, "bob"):
        replay, created = create(service)
    assert not created and replay["id"] == run["id"]
    assert (
        next(x for x in auth.pending_job_links()["items"] if x.resource_id == run["id"]) == original
    )
    calls = []
    assess = service.gateway.assess

    def observed(bundle):
        calls.append(bundle)
        return assess(bundle)

    monkeypatch.setattr(service.gateway, "assess", observed)
    finish = auth.finish_job

    def unavailable(*args):
        raise AuthError("SECURITY_UNAVAILABLE", 503)

    monkeypatch.setattr(auth, "finish_job", unavailable)
    if terminal == "execute":
        result = service.execute(run["id"])
        assert result["status"] == "COMPLETED"
        assert len(calls) == 1
    else:
        result = service.cancel(run["id"], "user cancel")
        assert result["status"] == "CANCELLED"
        assert calls == []
    assert auth.job_audit_status("ai_run", run["id"]) == "pending"
    monkeypatch.setattr(auth, "finish_job", finish)
    assert service.execute(run["id"])["status"] == result["status"]
    assert auth.job_audit_status("ai_run", run["id"]) == "complete"
    service.execute(run["id"])
    assert len(calls) == (1 if terminal == "execute" else 0)
    assert_one_terminal(auth, run["id"])
