"""Historical AI admission must share the actual resource reservation boundary."""

import pytest
from test_account_auth_job_investigations import authority

from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway
from c2hunter_controller.auth_models import AuthError
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_historical_ai_storage import prepared


def test_historical_admission_outage_publishes_no_runnable(tmp_path, monkeypatch):
    repo = SQLiteRepository(tmp_path / "domain.sqlite")
    try:
        request, _, _ = prepared(repo)
        service = AIAnalysisService(repo, FakeGateway())
        auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
        auth.initialize()
        service.auth_store = auth

        def unavailable(*args):
            raise AuthError("SECURITY_UNAVAILABLE", 503)

        monkeypatch.setattr(auth, "reserve_job", unavailable)
        with authority(auth), pytest.raises(AuthError):
            service.create_run(
                analysis_job_id=request.analysis_job_id,
                created_by=request.actor,
                **request.payload.to_mapping(),
            )
        assert repo.list_ai_runs(request.analysis_job_id) == []
    finally:
        repo.close()


@pytest.fixture
def historical_domain(tmp_path):
    repo = SQLiteRepository(tmp_path / "domain.sqlite")
    try:
        request, _, _ = prepared(repo)
        auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
        auth.initialize()
        service = AIAnalysisService(repo, FakeGateway())
        service.auth_store = auth
        yield service, auth, request
    finally:
        repo.close()


def create_historical(service, request, **kwargs):
    return service.create_run(
        analysis_job_id=request.analysis_job_id,
        created_by=request.actor,
        **request.payload.to_mapping(),
        **kwargs,
    )


def test_historical_native_handoff_reserves_before_independent_reader(
    historical_domain, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor

    from c2hunter_controller.auth_job_context import current_job_audit

    service, auth, request = historical_domain
    observer = SQLiteRepository(service.repository._path)
    auth_reader = AuthStore(sqlite_path=auth.sqlite_path)
    original = service.repository.admit_historical_ai_run
    observed = []
    reserved = []

    def publish(admission_request, builder, **kwargs):
        assert current_job_audit() is None
        assert observer.list_ai_runs(request.analysis_job_id) == []
        assert auth_reader.job_audit_status("ai_run", admission_request.run_id) == "pending"
        observed.append(admission_request.run_id)
        return original(admission_request, builder, **kwargs)

    monkeypatch.setattr(service.repository, "admit_historical_ai_run", publish)
    try:
        with authority(auth) as context:

            def callback(identifier):
                assert current_job_audit() is None
                reserved.append(identifier)
                return context.reserve("ai_run", identifier)

        with ThreadPoolExecutor(max_workers=1) as executor:
            run, created = executor.submit(
                create_historical, service, request, before_publish=callback
            ).result(5)
        assert created and observed == reserved == [run["id"]]
        assert observer.get_ai_run(run["id"])["status"] == "QUEUED"
    finally:
        observer.close()


@pytest.mark.parametrize("terminal", ["execute", "cancel"])
def test_historical_durable_terminal_redelivery_repairs_only(
    historical_domain, monkeypatch, terminal
):
    from test_account_auth_job_investigations import assert_one_terminal

    from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
    from c2hunter_controller.ai_worker import AIAnalysisWorker

    service, auth, request = historical_domain
    with authority(auth):
        run, created = create_historical(service, request)
    assert created
    original_link = auth.pending_job_links()["items"][0]
    original_owner = run["_historical_admission"]
    calls = []
    assess = service.gateway.assess

    def observed(bundle):
        calls.append(bundle)
        return assess(bundle)

    def unavailable(*args):
        raise AuthError("SECURITY_UNAVAILABLE", 503)

    monkeypatch.setattr(service.gateway, "assess", observed)
    monkeypatch.setattr(auth, "finish_job", unavailable)
    result = (
        service.execute(run["id"]) if terminal == "execute" else service.cancel(run["id"], "cancel")
    )
    assert result["status"] == ("COMPLETED" if terminal == "execute" else "CANCELLED")
    assert len(calls) == (1 if terminal == "execute" else 0)
    assert auth.job_audit_status("ai_run", run["id"]) == "pending"
    assert auth.pending_job_links()["items"] == [original_link]

    # Fresh service and independent SQL/auth readers simulate terminal redelivery.
    observer = SQLiteRepository(service.repository._path)
    restarted_auth = AuthStore(sqlite_path=auth.sqlite_path)
    restarted = AIAnalysisService(observer, FakeGateway())
    restarted.auth_store = restarted_auth

    def forbidden(*args, **kwargs):
        pytest.fail("terminal redelivery repeated provider/source/publication work")

    monkeypatch.setattr(restarted.gateway, "assess", forbidden)
    monkeypatch.setattr(observer, "get_job", forbidden)
    monkeypatch.setattr(observer, "get_candidates", forbidden)
    monkeypatch.setattr(observer, "admit_historical_ai_run", forbidden)
    monkeypatch.setattr(observer, "save_ai_run", forbidden)
    try:
        assert observer.get_ai_run(run["id"]) == result
        with authority(restarted_auth, "bob"):
            replay, created = create_historical(restarted, request, before_publish=forbidden)
        assert not created and replay == result
        assert restarted_auth.pending_job_links()["items"] == [original_link]

        class ObservedQueue(MemoryAIAnalysisWorkerQueue):
            def ack(self, receipt):
                assert restarted_auth.job_audit_status("ai_run", run["id"]) == "complete"
                super().ack(receipt)

        queue = ObservedQueue(
            [
                {"ai_run_id": run["id"], "receipt": "one"},
                {"ai_run_id": run["id"], "receipt": "two"},
            ]
        )
        worker = AIAnalysisWorker(queue, restarted)
        assert worker.run_once(timeout=0)
        assert worker.run_once(timeout=0)
        assert queue.acked == ["one", "two"]
        assert observer.get_ai_run(run["id"]) == result
        assert result["_historical_admission"] == original_owner
        assert_one_terminal(restarted_auth, run["id"])
    finally:
        observer.close()


def test_historical_explicit_callback_wins_over_ambient_actor(historical_domain):
    from functools import partial

    service, auth, request = historical_domain
    with authority(auth) as context:
        callback = partial(context.reserve, "ai_run")
    with authority(auth, "bob"):
        run, created = create_historical(service, request, before_publish=callback)
    assert created
    link = auth.pending_job_links()["items"][0]
    assert link.resource_id == run["id"] and link.actor == context.actor


def test_historical_replay_and_invalid_input_precede_reservation(historical_domain, monkeypatch):
    from c2hunter_controller.historical_ai import HistoricalAIError

    service, auth, request = historical_domain
    with authority(auth):
        run, _ = create_historical(service, request)
    original = auth.pending_job_links()["items"]

    def forbidden(*args, **kwargs):
        pytest.fail("replay or invalid input attempted new reservation/publication")

    monkeypatch.setattr(auth, "reserve_job", forbidden)
    monkeypatch.setattr(service.repository, "admit_historical_ai_run", forbidden)
    with authority(auth, "bob"):
        replay, created = create_historical(service, request, before_publish=forbidden)
        assert not created and replay == run
        payload = request.payload.to_mapping()
        with pytest.raises(HistoricalAIError, match="BASELINE_IDEMPOTENCY_CONFLICT"):
            service.create_run(
                analysis_job_id=request.analysis_job_id,
                created_by="another-owner",
                before_publish=forbidden,
                **payload,
            )
        payload["candidate_limit"] = 0
        with pytest.raises(ValueError):
            service.create_run(
                analysis_job_id=request.analysis_job_id,
                created_by=request.actor,
                before_publish=forbidden,
                **payload,
            )
    assert auth.pending_job_links()["items"] == original
    assert service.repository.list_ai_runs(request.analysis_job_id) == [run]
