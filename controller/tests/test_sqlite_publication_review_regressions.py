"""Persistent independent publication probes, including four reader barriers."""

import copy
import importlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from test_result_publication import Delivery, seed

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.fixture(params=["memory", "sqlite"])
def repo(request, tmp_path):
    repository = (
        MemoryRepository()
        if request.param == "memory"
        else SQLiteRepository(tmp_path / "review.db")
    )
    yield repository
    if isinstance(repository, SQLiteRepository):
        repository.close()


@pytest.mark.parametrize("stage", ["job", "candidates", "audit_job", "audit_candidates"])
def test_memory_copy_and_audit_errors_do_not_publish(stage, monkeypatch):
    repository = MemoryRepository()
    original = seed(repository)
    target = {**original, "status": "COMPLETED"}
    candidates = [{"id": "new", "score": 90}]
    audits = copy.deepcopy(repository.audit_events)
    fault = RuntimeError("memory staged copy failure: " + stage)
    real = copy.deepcopy
    fired = []

    def injected(value):
        is_job = value is target
        is_candidates = value is candidates
        is_audit_job = (
            isinstance(value, dict)
            and value.get("status") == "COMPLETED"
            and "flow_records" not in value
        )
        is_audit_candidates = (
            isinstance(value, list) and value == candidates and value is not candidates
        )
        if dict(
            job=is_job,
            candidates=is_candidates,
            audit_job=is_audit_job,
            audit_candidates=is_audit_candidates,
        )[stage]:
            fired.append(stage)
            raise fault
        return real(value)

    module = importlib.import_module("c2hunter_controller.repositories")
    with monkeypatch.context() as scoped:
        scoped.setattr(module, "deepcopy", injected)
        with pytest.raises(RuntimeError) as caught:
            repository.complete_job_with_candidates(target, candidates)
    assert caught.value is fault
    assert fired == [stage]
    assert repository.get_job("job") == original
    assert repository.get_candidates("job") == [{"id": "old", "score": 40}]
    assert repository.audit_events == audits
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert (
            pool.submit(repository.complete_job_with_candidates, target, candidates).result(3)
            is True
        )


def snapshot(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as reader:
        return {
            table: reader.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            for table in [
                "objects",
                "candidate_records",
                "job_flow_records",
                "job_payload_signatures",
                "audit_events",
            ]
        }


@pytest.mark.parametrize("point", ["metadata", "candidate_second", "audit_second", "commit"])
def test_sqlite_real_fault_full_independent_snapshot_and_reuse(tmp_path, point):
    path = tmp_path / "fault.db"
    repository = SQLiteRepository(path)
    seed(repository)
    queue = Delivery()
    queue.result["result"]["candidates"].append({"id": "new2", "score": 10})
    app = create_app(Settings(environment="test"), repository, queue=queue)
    before = snapshot(path)
    fired = []
    conn = repository.connection
    conn.create_function("review_hit", 0, lambda: fired.append(point) or 1)
    event, table, condition = {
        "metadata": ("UPDATE", "objects", "NEW.kind='job'"),
        "candidate_second": ("INSERT", "candidate_records", "NEW.candidate_id='new2'"),
        "audit_second": ("INSERT", "audit_events", "NEW.kind='candidates'"),
        "commit": ("INSERT", "audit_events", "NEW.kind='candidates'"),
    }[point]
    if point == "commit":
        conn.executescript(
            "PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); "
            "CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);"
        )
        body = "INSERT INTO child VALUES(1);"
    else:
        body = "SELECT RAISE(ABORT,'review SQL fault');"
    conn.execute(
        f"CREATE TEMP TRIGGER review_fault AFTER {event} ON {table} "
        f"WHEN {condition} BEGIN SELECT review_hit(); {body} END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        app.state.process_results_once()
    # First post-failure operation is an independent reader, never writer cleanup.
    assert snapshot(path) == before
    assert fired == [point]
    assert not conn.in_transaction
    assert queue.acked == []
    conn.execute("DROP TRIGGER review_fault")
    assert app.state.process_results_once() is True
    assert queue.acked == ["delivery-1"]
    assert [x["id"] for x in repository.get_candidates("job")] == ["new", "new2"]
    assert repository.get_job("job")["status"] == "COMPLETED"
    app.state.wait_for_candidate_enrichment()
    repository.close()


@pytest.mark.parametrize("reader", ["page", "refs", "workflow", "http"])
def test_retained_sqlite_readers_wait_for_failed_publication(tmp_path, monkeypatch, reader):
    path = tmp_path / "reader.db"
    repository = SQLiteRepository(path)
    seed(repository)
    queue = Delivery()
    app = create_app(Settings(environment="test"), repository, queue=queue)
    entered, release, settled = threading.Event(), threading.Event(), threading.Event()
    reader_thread = []
    real_lock = repository._lock
    real_serialize = repository._serialize
    fault = RuntimeError("after delete before insert")

    class ObservedLock:
        def __enter__(self):
            if threading.get_ident() in reader_thread:
                settled.set()
            return real_lock.__enter__()

        def __exit__(self, *args):
            return real_lock.__exit__(*args)

    def serializer(value):
        if isinstance(value, dict) and value.get("id") == "new":
            entered.set()
            assert release.wait(10)
            raise fault
        return real_serialize(value)

    monkeypatch.setattr(repository, "_lock", ObservedLock())
    monkeypatch.setattr(repository, "_serialize", serializer)
    query = dict(minimum_score=0, severity=None, include_suppressed=True)

    def read():
        reader_thread.append(threading.get_ident())
        if reader == "page":
            return repository.query_candidate_page(**query, sort="-score", page=1, page_size=50)
        if reader == "refs":
            return repository.query_candidate_refs(**query)
        if reader == "workflow":
            return repository.candidate_workflow_counts(**query)
        # ASGI sync handler runs in AnyIO's own thread; signal lock attempts there too.
        return TestClient(app).get("/api/v1/candidates").json()

    # HTTP needs a thread-independent signal at the actual retained repository reader.
    if reader == "http":
        original_page = repository.query_candidate_page

        def page(*args, **kwargs):
            reader_thread.append(threading.get_ident())
            return original_page(*args, **kwargs)

        monkeypatch.setattr(repository, "query_candidate_page", page)

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(app.state.process_results_once)
        try:
            assert entered.wait(10)
            before = snapshot(path)
            assert before["candidate_records"][0][0] == "old"
            observer = pool.submit(read)
            observer.add_done_callback(lambda _: settled.set())
            assert settled.wait(5), "reader neither attempted facade lock nor completed"
        finally:
            release.set()
        with pytest.raises(RuntimeError) as caught:
            writer.result(5)
        assert caught.value is fault
        observed = observer.result(5)
    assert snapshot(path) == before
    assert not repository.connection.in_transaction
    assert queue.acked == []
    repository.close()
    print("READER", reader, "OBSERVED", observed)
    if reader == "page":
        assert observed == ([("job", {"id": "old", "score": 40})], 1)
    elif reader == "refs":
        assert observed == [("old", False)]
    elif reader == "workflow":
        assert observed["needs_review"] == 1
    else:
        assert observed["total"] == 1
        assert [x["id"] for x in observed["items"]] == ["old"]


@pytest.mark.parametrize(
    "args", [("candidate parent job not found", "extra"), ("candidate parent job not found ",)]
)
def test_allowlist_does_not_swallow_near_match(repo, monkeypatch, args):
    seed(repo)
    repo.save_candidates("job", [{"id": "old", "candidate_ip": "203.0.113.1"}])
    fault = ValueError(*args)

    def fail(*args):
        raise fault

    monkeypatch.setattr(repo, "save_candidates", fail)
    with pytest.raises(ValueError) as caught:
        TestClient(create_app(Settings(environment="test"), repo)).post(
            "/api/v1/allowlist", json={"type": "IP", "value": "203.0.113.1", "description": "test"}
        )
    assert caught.value is fault


def test_enrichment_completion_after_parent_delete_never_republishes_candidates(repo):
    seed(repo)
    queue = Delivery()
    queue.result["result"]["candidates"][0]["candidate_ip"] = "203.0.113.1"
    entered, release = threading.Event(), threading.Event()
    calls = []

    class Intel:
        def lookup_ip(self, ip):
            calls.append(ip)
            entered.set()
            assert release.wait(10)
            return {}

    app = create_app(Settings(environment="test"), repo, queue=queue, threat_intel_service=Intel())
    try:
        assert app.state.process_results_once()
        assert entered.wait(5)
        assert repo.delete_job("job") is True
    finally:
        release.set()
    app.state.wait_for_candidate_enrichment()
    assert calls == ["203.0.113.1"]
    assert repo.get_job("job") is None
    assert repo.get_candidates("job") == []
    assert app.state.process_results_once()
    assert calls == ["203.0.113.1"]
    assert queue.acked == ["delivery-1", "delivery-1"]
    # Lookup history is intentionally a separate retained ledger, not a candidate writer.
    assert repo.list_candidate_ti_lookups("new")[0]["status"] == "COMPLETED"
    app.router.on_shutdown[-1]()
