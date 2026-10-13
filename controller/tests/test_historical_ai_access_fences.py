"""Publication interleavings and pre-copy/pre-transfer byte admission."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from c2hunter_controller import historical_ai_descendants as descendants
from c2hunter_controller import repositories
from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway
from c2hunter_controller.historical_ai_access import public_ai_access
from c2hunter_controller.historical_ai_storage import HistoricalStorageError
from tests.test_historical_ai_access import completed
from tests.test_historical_ai_access import repo as _repository_fixture
from tests.test_historical_ai_descendants import staged
from tests.test_historical_ai_execution import admitted
from tests.test_historical_ai_storage import advance

repo = _repository_fixture


@pytest.mark.parametrize("delete", [False, True])
def test_cancellation_or_delete_wins_while_worker_waits_to_publish(repo, monkeypatch, delete):
    run = admitted(repo)
    waiting, release = Event(), Event()
    actual_save = repo.save_ai_assessment

    def paused(proposal):
        waiting.set()
        assert release.wait(10)
        return actual_save(proposal)

    monkeypatch.setattr(repo, "save_ai_assessment", paused)
    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(AIAnalysisService(repo, FakeGateway()).execute, run["id"])
        try:
            assert waiting.wait(10)
            current = repo.get_ai_run(run["id"])
            repo.save_ai_run(advance(current, "CANCELLED", 80))
            if delete:
                assert repo.delete_job(run["analysis_job_id"])
        finally:
            release.set()
        with pytest.raises(HistoricalStorageError):
            result.result(timeout=10)
    assert repo.list_ai_assessments(run["id"]) == []


def test_missing_target_job_is_not_a_worker_publication_owner(repo, monkeypatch):
    run, proposal = staged(repo, monkeypatch)
    if isinstance(repo, repositories.MemoryRepository):
        del repo.jobs[run["analysis_job_id"]]
    else:
        repo.connection.execute(
            "DELETE FROM objects WHERE kind='job' AND id=?", (run["analysis_job_id"],)
        )
        repo.connection.commit()
    with pytest.raises(HistoricalStorageError):
        repo.save_ai_assessment(proposal)


def test_authorized_cap_precedes_private_body_transfer(repo, monkeypatch):
    _, assessment, artifact = completed(repo)
    kind = "T"
    monkeypatch.setitem(descendants.CAPS, kind, 64)
    if isinstance(repo, repositories.MemoryRepository):

        class NoCopy:
            def __deepcopy__(self, memo):
                pytest.fail("copy before byte admission")

        repo.ai_artifacts[artifact["id"]]["later_private"] = NoCopy()
    else:

        def reject_body(cursor, row):
            assert not any(isinstance(value, str) and '"content"' in value for value in row), (
                "body transferred before byte gate"
            )
            return row

        repo.connection.row_factory = reject_body
    with public_ai_access(2), pytest.raises(HistoricalStorageError):
        repo.get_ai_artifact(artifact["id"])


@pytest.mark.parametrize(
    "value",
    [
        {"s": "a" * 100},
        {"s": "\u007f" * 100},
        {"s": 'é😺\n\\"' * 30},
        {"a": [None, True, False, 12, 0.2, {"nested": "x"}]},
    ],
)
def test_exact_native_json_budget(value):
    size = len(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode())
    descendants.admit_body(value, size)
    with pytest.raises(HistoricalStorageError):
        descendants.admit_body(value, size - 1)


def test_deleted_historical_run_cannot_be_resurrected(repo):
    run = admitted(repo)
    cancelled = repo.save_ai_run(advance(run, "CANCELLED", 0))
    assert repo.delete_job(run["analysis_job_id"])
    with pytest.raises(HistoricalStorageError):
        repo.save_ai_run(cancelled)
    assert repo.get_ai_run(run["id"]) is None


def test_historical_identity_and_timestamp_are_validated_before_copy(repo, monkeypatch):
    _, proposal = staged(repo, monkeypatch)
    for field, value in [("id", "not-a-uuid"), ("created_at", "not-a-timestamp")]:
        malformed = {**proposal, field: value}
        with pytest.raises(HistoricalStorageError):
            repo.save_ai_assessment(malformed)


def test_off_feedback_duplicate_retains_adapter_return_contract(repo):
    original = {
        "id": "legacy-feedback",
        "assessment_id": "missing",
        "created_at": "2026-01-01",
        "note": "original",
    }
    proposal = {**original, "note": "duplicate"}
    assert repo.save_ai_feedback(original) == original
    expected = original if isinstance(repo, repositories.MemoryRepository) else proposal
    assert repo.save_ai_feedback(proposal) == expected
    assert repo.list_ai_feedback("missing") == [original]


@pytest.mark.parametrize("rollback", [False, True])
def test_sqlite_same_facade_reader_waits_through_publication(tmp_path, monkeypatch, rollback):
    from threading import current_thread

    from c2hunter_controller._baseline_storage import BaselineStorageError
    from tests.test_historical_ai_descendants import drafts

    repository = repositories.SQLiteRepository(tmp_path / "visibility.db")
    _, _, artifacts, _ = drafts(repository, monkeypatch)
    entered, attempted, release = Event(), Event(), Event()
    actual_lock = repository._lock

    class ObservedLock:
        def __enter__(self):
            if current_thread().name.startswith("access-reader"):
                attempted.set()
            return actual_lock.__enter__()

        def __exit__(self, *args):
            return actual_lock.__exit__(*args)

    repository._lock = ObservedLock()

    def pause():
        entered.set()
        assert release.wait(10)
        return 1

    repository.connection.create_function("pause_publication", 0, pause)
    suffix = "SELECT RAISE(ABORT,'publication fault');" if rollback else ""
    repository.connection.execute(
        "CREATE TEMP TRIGGER pause_artifact AFTER INSERT ON ai_generated_artifacts "
        "BEGIN SELECT pause_publication(); " + suffix + " END"
    )
    try:
        with (
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="access-writer") as writers,
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="access-reader") as readers,
        ):
            write = writers.submit(repository.save_ai_artifact, artifacts[0])
            try:
                assert entered.wait(10)
                read = readers.submit(repository.get_ai_artifact, artifacts[0]["id"])
                assert attempted.wait(10)
                assert not read.done()
            finally:
                release.set()
            if rollback:
                with pytest.raises(BaselineStorageError):
                    write.result(timeout=10)
                assert read.result(timeout=10) is None
            else:
                assert read.result(timeout=10) == write.result(timeout=10)
        assert not repository.connection.in_transaction
    finally:
        repository.connection.close()


def test_sqlite_descendant_readback_failure_is_uncertain_not_false_success(tmp_path, monkeypatch):
    import sqlite3

    from c2hunter_controller.historical_ai_storage import HistoricalStorageOutcomeUnknown
    from tests.test_historical_ai_descendants import drafts

    path = tmp_path / "readback.db"
    repository = repositories.SQLiteRepository(path)
    _, _, _, feedback = drafts(repository, monkeypatch)
    connect = sqlite3.connect
    calls = []

    def observer(*args, **kwargs):
        connection = connect(*args, **kwargs)
        calls.append(args[0])
        connection.set_authorizer(
            lambda action, table, *_: sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_READ and table == "ai_feedback"
            else sqlite3.SQLITE_OK
        )
        return connection

    monkeypatch.setattr(sqlite3, "connect", observer)
    with pytest.raises(HistoricalStorageOutcomeUnknown):
        repository.save_ai_feedback(feedback)
    assert calls and repository._historical_quarantined
    with connect(path.as_uri() + "?mode=ro", uri=True) as durable:
        stored = json.loads(
            durable.execute(
                "SELECT data FROM ai_feedback WHERE feedback_id=?", (feedback["id"],)
            ).fetchone()[0]
        )
        assert stored["baseline_mode"] == "historical" and stored["note"] == feedback["note"]


def test_context_is_reset_and_is_not_inherited_by_worker_thread(repo):
    run = admitted(repo)
    with public_ai_access(None):
        with ThreadPoolExecutor(max_workers=1) as executor:
            assert executor.submit(repo.get_ai_run, run["id"]).result() == run
    assert repo.get_ai_run(run["id"]) == run
