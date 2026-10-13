"""Real stored snapshots through direct and queue worker callers (no model server)."""

from copy import deepcopy
from pathlib import Path

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import historical_ai_storage as custody
from c2hunter_controller import repositories
from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
from c2hunter_controller.ai_worker import AIAnalysisWorker
from c2hunter_controller.historical_ai_builder import build_historical_target_snapshot
from tests.test_historical_ai_storage import prepared


@pytest.fixture(params=["memory", "sqlite"])
def repository(request, tmp_path):
    repo = (
        repositories.MemoryRepository()
        if request.param == "memory"
        else repositories.SQLiteRepository(tmp_path / "worker.db")
    )
    yield repo
    if request.param == "sqlite":
        repo.connection.close()


class RecordingGateway(ai.FakeGateway):
    def __init__(self):
        self.calls = []

    def assess(self, bundle):
        self.calls.append(bundle.model_dump(mode="json", by_alias=True))
        return super().assess(bundle)


def admitted(repo):
    request, _, _ = prepared(repo)
    run, created = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    assert created
    return run


def forbidden(*args, **kwargs):
    pytest.fail("historical execution must not re-read or reconstruct live source")


def test_worker_uses_only_saved_bundles_and_persists_results(repository, monkeypatch):
    assert Path(ai.__file__).resolve().is_relative_to(Path.cwd())
    run = admitted(repository)
    original = deepcopy(run[custody.OWNER_KEY])
    view, bundles = custody.materialize_historical_run(run)
    for name in ("get_job", "get_candidates", "read_historical_source", "get_baseline_scope"):
        monkeypatch.setattr(repository, name, forbidden)
    monkeypatch.setattr(ai, "build_evidence_bundle", forbidden)
    gateway = RecordingGateway()
    queue = MemoryAIAnalysisWorkerQueue(
        [
            {"ai_run_id": run["id"], "receipt": "first"},
            {"ai_run_id": run["id"], "receipt": "replay"},
        ]
    )
    worker = AIAnalysisWorker(queue, ai.AIAnalysisService(repository, gateway))
    assert worker.run_once(timeout=0)
    saved = repository.get_ai_run(run["id"])
    assert saved["status"] == "COMPLETED"
    assert saved[custody.OWNER_KEY] == original
    assert gateway.calls == [b.model_dump(mode="json", by_alias=True) for b in bundles]
    assessments = repository.list_ai_assessments(run["id"])
    assert len(assessments) == len(bundles) == len(view["candidate_ids"])
    for assessment, bundle in zip(assessments, bundles, strict=True):
        assert assessment["evidence_bundle"] == bundle.model_dump(mode="json", by_alias=True)
        assert assessment["evidence_bundle_hash"] == bundle.metadata.canonical_sha256
        assert repository.list_ai_artifacts(assessment["id"])
    assert worker.run_once(timeout=0)
    assert len(gateway.calls) == len(bundles)
    assert queue.acked == ["first", "replay"]


def test_service_admission_and_replay_precede_source_and_new_identity(repository, monkeypatch):
    from c2hunter_controller import historical_ai as dto

    request, _, _ = prepared(repository)
    payload = request.payload.to_mapping()
    service = ai.AIAnalysisService(repository, RecordingGateway())
    run, created = service.create_run(
        analysis_job_id=request.analysis_job_id, created_by=request.actor, **payload
    )
    assert created
    view, bundles = custody.materialize_historical_run(run)
    assert bundles and view["baseline_mode"] == "historical"
    for name in ("get_job", "get_candidates", "read_historical_source", "get_baseline_scope"):
        monkeypatch.setattr(repository, name, forbidden)
    monkeypatch.setattr(ai.uuid, "uuid4", forbidden)
    replay, created = service.create_run(
        analysis_job_id=request.analysis_job_id, created_by=request.actor, **payload
    )
    assert not created and replay == run
    payload["language"] = "en"
    with pytest.raises(
        (dto.HistoricalAIError, custody.HistoricalStorageError),
        match="BASELINE_IDEMPOTENCY_CONFLICT",
    ):
        service.create_run(
            analysis_job_id=request.analysis_job_id, created_by=request.actor, **payload
        )


def corrupt_snapshot(repo, run):
    from c2hunter_controller import historical_ai_sql as sql

    before = run[custody.OWNER_KEY]["snapshot_canonical_json"]
    bad = before.replace('"dataset_id":"dataset-3"', '"dataset_id":"dataset-4"')
    assert bad != before and len(bad.encode()) == len(before.encode())
    if isinstance(repo, repositories.MemoryRepository):
        repo._historical_admissions[run["id"]]["snapshot_canonical_json"] = bad
    else:
        repo.connection.execute("DROP TRIGGER ai_runs_hist_owner_update")
        repo.connection.execute(
            "UPDATE ai_analysis_runs SET historical_snapshot_json=? WHERE run_id=?",
            (bad, run["id"]),
        )
        repo.connection.execute(sql.sqlite_guards()["ai_runs_hist_owner_update"])
        repo.connection.commit()


def test_invalid_saved_snapshot_gets_safe_failure_without_model(repository):
    run = admitted(repository)
    corrupt_snapshot(repository, run)
    owner = repository.get_ai_run(run["id"])[custody.OWNER_KEY]
    gateway = RecordingGateway()
    queue = MemoryAIAnalysisWorkerQueue(
        [{"ai_run_id": run["id"], "receipt": "bad"}, {"ai_run_id": run["id"], "receipt": "again"}]
    )
    worker = AIAnalysisWorker(queue, ai.AIAnalysisService(repository, gateway))
    assert worker.run_once(timeout=0)
    assert worker.run_once(timeout=0)
    saved = repository.get_ai_run(run["id"])
    assert saved["status"] == "FAILED"
    assert saved["error_code"] == "HISTORICAL_SNAPSHOT_INVALID"
    assert saved[custody.OWNER_KEY] == owner
    assert gateway.calls == []
    assert repository.list_ai_assessments(run["id"]) == []
    assert queue.acked == ["bad", "again"]


def test_corrupted_successful_terminal_is_not_acknowledged(repository):
    run = admitted(repository)
    gateway = RecordingGateway()
    service = ai.AIAnalysisService(repository, gateway)
    assert service.execute(run["id"])["status"] == "COMPLETED"
    calls = len(gateway.calls)
    corrupt_snapshot(repository, run)
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": "bad-terminal"}])
    assert not AIAnalysisWorker(queue, service).run_once(timeout=0)
    assert queue.acked == [] and len(gateway.calls) == calls


def test_local_owner_proxy_does_not_skip_historical_custody_validation(repository):
    from concurrent.futures import Future

    from c2hunter_controller.local_ai_runtime import LocalAIRuntime, LocalAITaskQueue

    run = admitted(repository)
    service = ai.AIAnalysisService(repository, RecordingGateway())
    winner = service.cancel(run["id"], "cancelled")
    invalid = deepcopy(winner)
    invalid[custody.OWNER_KEY]["expected_snapshot_sha256"] = "0" * 64
    runtime = LocalAIRuntime(LocalAITaskQueue(), service)
    future = Future()
    runtime.calls.put_nowait(("save_ai_run", (invalid,), future))
    runtime.service_call()
    with pytest.raises(custody.HistoricalStorageError):
        future.result(timeout=1)
    assert repository.get_ai_run(run["id"]) == winner


@pytest.mark.parametrize("point", ["save", "cancel_callback"])
def test_storage_failure_is_not_model_failure_or_queue_ack(repository, monkeypatch, point):
    from c2hunter_controller._baseline_storage import BaselineStorageError

    run = admitted(repository)
    calls = []
    original_save = repository.save_ai_run
    original_get = repository.get_ai_run

    def fail(*args):
        raise BaselineStorageError()

    def save(value):
        calls.append(value["status"])
        if point == "save":
            raise BaselineStorageError()
        return original_save(value)

    class Gateway(RecordingGateway):
        def assess_cancellable(self, bundle, *, should_cancel):
            monkeypatch.setattr(repository, "get_ai_run", fail)
            should_cancel()
            pytest.fail("callback storage failure was ignored")

    monkeypatch.setattr(repository, "save_ai_run", save)
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": "storage-fault"}])
    worker = AIAnalysisWorker(queue, ai.AIAnalysisService(repository, Gateway()))
    assert not worker.run_once(timeout=0)
    monkeypatch.setattr(repository, "get_ai_run", original_get)
    assert "FAILED" not in calls
    assert repository.get_ai_run(run["id"])["status"] == (
        "QUEUED" if point == "save" else "ANALYZING"
    )
    assert queue.acked == []


@pytest.mark.parametrize("outcome", ["success", "timeout", "invalid", "cancel"])
def test_local_historical_compute_uses_owner_thread_and_saved_input(tmp_path, outcome):
    import asyncio
    import threading

    from c2hunter_controller.local_ai_runtime import LocalAIRuntime, LocalAITaskQueue

    async def exercise():
        owner_thread = threading.get_ident()
        repo = repositories.SQLiteRepository(tmp_path / "local.db")
        run = admitted(repo)
        owner = deepcopy(run[custody.OWNER_KEY])
        entered, release = threading.Event(), threading.Event()

        class Gateway(RecordingGateway):
            def assess(self, bundle):
                assert threading.get_ident() != owner_thread
                entered.set()
                assert release.wait(5)
                if outcome == "timeout":
                    raise TimeoutError("private provider diagnostic")
                if outcome == "invalid":
                    return {"private": "invalid"}
                return super().assess(bundle)

        for name in ("get_ai_run", "save_ai_run", "save_ai_assessment", "save_ai_artifact"):
            operation = getattr(repo, name)

            def checked(*args, _operation=operation):
                assert threading.get_ident() == owner_thread
                return _operation(*args)

            setattr(repo, name, checked)
        service = ai.AIAnalysisService(repo, Gateway())
        queue = LocalAITaskQueue()
        queue.enqueue(run["id"])
        runtime = LocalAIRuntime(queue, service)
        await runtime.start()
        repo.get_job = forbidden
        repo.get_candidates = forbidden
        try:
            async with asyncio.timeout(5):
                while not entered.is_set():
                    await asyncio.sleep(0.01)
            if outcome == "cancel":
                service.cancel(run["id"], "test cancellation")
            release.set()
            async with asyncio.timeout(5):
                while runtime.inflight is not None or queue.depth():
                    await asyncio.sleep(0.01)
            assert runtime.thread is not None
            await asyncio.to_thread(runtime.thread.join, 1)
            assert not runtime.thread.is_alive()
            saved = repo.get_ai_run(run["id"])
            assert (
                saved["status"]
                == {
                    "success": "COMPLETED",
                    "timeout": "FAILED",
                    "invalid": "FAILED",
                    "cancel": "CANCELLED",
                }[outcome]
            )
            assert saved[custody.OWNER_KEY] == owner
            assert len(repo.list_ai_assessments(run["id"])) == (1 if outcome == "success" else 0)
            reopened = repositories.SQLiteRepository(tmp_path / "local.db")
            try:
                assert reopened.get_ai_run(run["id"]) == saved
            finally:
                reopened.close()
        finally:
            release.set()
            await runtime.stop()
            repo.close()

    asyncio.run(exercise())


def test_cancel_validates_saved_semantics_before_terminal_shortcut(repository):
    run = admitted(repository)
    service = ai.AIAnalysisService(repository, RecordingGateway())
    service.cancel(run["id"], "cancelled")
    corrupt_snapshot(repository, run)
    with pytest.raises(ValueError):
        service.cancel(run["id"], "cancelled again")


@pytest.mark.parametrize("count", [0, 5])
def test_zero_and_maximum_candidates_complete_saved_lifecycle(repository, count):
    from c2hunter_controller import historical_ai as dto
    from c2hunter_controller import historical_baseline as h
    from tests.historical_ai_fixtures import START, job, rule, world

    target = job()
    target["flow_records"] = []
    rows = [rule(f"203.0.113.{9 + i}", f"rule-{i}") for i in range(count)]
    inputs = world(target=target, candidates=rows, sources=0)
    repository.create_baseline_scope(inputs["scope"].config, "fixture-admin", START)
    repository.save_job(target)
    repository.save_candidates(target["id"], rows)
    request = dto.HistoricalAdmissionRequest.model_validate(inputs["request"])
    run, _ = repository.admit_historical_ai_run(request, build_historical_target_snapshot)
    before = h.canonical_json(repository.get_job(target["id"]))
    gateway = RecordingGateway()
    saved = ai.AIAnalysisService(repository, gateway).execute(run["id"])
    assert saved["status"] == "COMPLETED"
    assert len(gateway.calls) == count
    assert len(saved["transitions"]) <= 16
    assert before == h.canonical_json(repository.get_job(target["id"]))


@pytest.mark.parametrize("boundary", ["assessment", "artifact"])
def test_redelivery_resumes_saved_run_after_persistence_failure(repository, monkeypatch, boundary):
    from c2hunter_controller._baseline_storage import BaselineStorageError

    run = admitted(repository)
    method = "save_ai_" + boundary
    original = getattr(repository, method)
    fault = []

    def after_write(value):
        original(value)
        fault.append(value["id"])
        raise BaselineStorageError()

    monkeypatch.setattr(repository, method, after_write)
    gateway = RecordingGateway()
    service = ai.AIAnalysisService(repository, gateway)
    queue = MemoryAIAnalysisWorkerQueue(
        [
            {"ai_run_id": run["id"], "receipt": "uncertain"},
            {"ai_run_id": run["id"], "receipt": "retry"},
        ]
    )
    worker = AIAnalysisWorker(queue, service)
    assert not worker.run_once(timeout=0)
    assert len(fault) == 1 and queue.acked == []
    monkeypatch.setattr(repository, method, original)
    assert worker.run_once(timeout=0)
    assert repository.get_ai_run(run["id"])["status"] == "COMPLETED"
    assessments = repository.list_ai_assessments(run["id"])
    assert len(assessments) == 1
    assert len(gateway.calls) == 1
    assert len(repository.list_ai_artifacts(assessments[0]["id"])) == 3
    assert queue.acked == ["retry"]


@pytest.mark.parametrize("state", ["PREPARING", "ANALYZING", "VALIDATING", "COMPLETED"])
def test_redelivery_after_lifecycle_commit_has_no_extra_transitions(repository, monkeypatch, state):
    from c2hunter_controller._baseline_storage import BaselineStorageError

    run = admitted(repository)
    original = repository.save_ai_run
    fault = []

    def after_commit(value):
        saved = original(value)
        if value["status"] == state and not fault:
            fault.append(state)
            raise BaselineStorageError()
        return saved

    monkeypatch.setattr(repository, "save_ai_run", after_commit)
    gateway = RecordingGateway()
    service = ai.AIAnalysisService(repository, gateway)
    queue = MemoryAIAnalysisWorkerQueue(
        [
            {"ai_run_id": run["id"], "receipt": "uncertain"},
            {"ai_run_id": run["id"], "receipt": "retry"},
        ]
    )
    worker = AIAnalysisWorker(queue, service)
    assert not worker.run_once(timeout=0)
    assert fault == [state] and queue.acked == []
    assert worker.run_once(timeout=0)
    saved = repository.get_ai_run(run["id"])
    assert saved["status"] == "COMPLETED"
    assert [step["to_status"] for step in saved["transitions"]] == [
        "QUEUED",
        "PREPARING",
        "ANALYZING",
        "VALIDATING",
        "COMPLETED",
    ]
    assert len(repository.list_ai_assessments(run["id"])) == 1
    # A response not yet durably saved may require re-inference; a saved result never does.
    assert len(gateway.calls) == (2 if state == "VALIDATING" else 1)
    assert queue.acked == ["retry"]
