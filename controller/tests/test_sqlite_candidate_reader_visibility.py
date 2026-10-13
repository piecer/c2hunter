"""Same-facade reader fences through SQL, materialization and delivery."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_result_publication import Delivery, seed
from test_sqlite_publication_review_regressions import snapshot

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository

QUERY = {"minimum_score": 0, "severity": None, "include_suppressed": True}


def read_candidate(repository: Any, app: Any, reader: str) -> Any:
    if reader == "page":
        return repository.query_candidate_page(**QUERY, sort="-score", page=1, page_size=50)
    if reader == "refs":
        return repository.query_candidate_refs(**QUERY)
    if reader == "workflow":
        return repository.candidate_workflow_counts(**QUERY)
    client = TestClient(app)
    try:
        response = client.get("/api/v1/candidates")
    finally:
        client.close()
    assert response.status_code == 200
    return response.json()


def assert_candidate(value: Any, reader: str, candidate_id: str, score: int) -> None:
    if reader == "page":
        assert value == ([("job", {"id": candidate_id, "score": score})], 1)
    elif reader == "refs":
        assert value == [(candidate_id, False)]
    elif reader == "workflow":
        assert value["needs_review"] == 1
    else:
        assert value["total"] == 1
        assert [item["id"] for item in value["items"]] == [candidate_id]


@pytest.mark.parametrize("reader", ["page", "refs", "workflow", "http"])
def test_ordinary_candidate_reader_control(tmp_path, reader):
    repository = SQLiteRepository(tmp_path / "normal.db")
    seed(repository)
    app = create_app(Settings(environment="test"), repository)
    try:
        assert_candidate(read_candidate(repository, app, reader), reader, "old", 40)
        assert not repository.connection.in_transaction
    finally:
        repository.close()


@pytest.mark.parametrize("reader", ["page", "refs", "workflow", "http"])
@pytest.mark.parametrize("fail", [False, True], ids=["commit", "rollback"])
def test_candidate_readers_wait_for_delivery_and_allow_reuse(tmp_path, monkeypatch, reader, fail):
    path = tmp_path / "delivery.db"
    repository = SQLiteRepository(path)
    seed(repository)
    delivery = Delivery()
    app = create_app(Settings(environment="test"), repository, queue=delivery)
    before = snapshot(path)
    entered, release, settled = threading.Event(), threading.Event(), threading.Event()
    attempted = threading.Event()
    reader_threads: set[int] = set()
    real_lock, real_serialize = repository._lock, repository._serialize
    fault = RuntimeError("replacement serialization after DELETE")
    fired = []

    class ObservedLock:
        def __enter__(self):
            if threading.get_ident() in reader_threads:
                attempted.set()
                settled.set()
            return real_lock.__enter__()

        def __exit__(self, *args):
            return real_lock.__exit__(*args)

    def serialize(value):
        if isinstance(value, dict) and value.get("id") == "new":
            fired.append("after-delete")
            entered.set()
            assert release.wait(10)
            if fail:
                raise fault
        return real_serialize(value)

    original_page = repository.query_candidate_page

    def page(**kwargs):
        reader_threads.add(threading.get_ident())
        return original_page(**kwargs)

    def read():
        reader_threads.add(threading.get_ident())
        return read_candidate(repository, app, reader)

    with monkeypatch.context() as scoped:
        scoped.setattr(repository, "_lock", ObservedLock())
        scoped.setattr(repository, "_serialize", serialize)
        if reader == "http":
            scoped.setattr(repository, "query_candidate_page", page)
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(app.state.process_results_once)
            try:
                assert entered.wait(10)
                assert snapshot(path) == before
                observer = pool.submit(read)
                observer.add_done_callback(lambda _: settled.set())
                assert settled.wait(5), "reader neither attempted facade lock nor completed"
                waited = attempted.is_set() and not observer.done()
            finally:
                release.set()
            if fail:
                with pytest.raises(RuntimeError) as caught:
                    writer.result(5)
                assert caught.value is fault
            else:
                assert writer.result(5) is True
            observed = observer.result(5)
    try:
        assert fired == ["after-delete"]
        assert waited, "candidate reader bypassed the publication fence"
        assert not repository.connection.in_transaction
        if fail:
            assert snapshot(path) == before
            assert delivery.acked == []
            assert_candidate(observed, reader, "old", 40)
            # Cross-thread public reuse proves the failed publication released its lock.
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert pool.submit(app.state.process_results_once).result(5) is True
        else:
            assert_candidate(observed, reader, "new", 90)
        assert delivery.acked == ["delivery-1"]
        assert repository.get_job("job")["status"] == "COMPLETED"
        assert_candidate(read_candidate(repository, app, reader), reader, "new", 90)
        assert not repository.connection.in_transaction
        app.state.wait_for_candidate_enrichment()
    finally:
        repository.close()


@pytest.mark.parametrize("reader", ["page", "refs", "workflow"])
@pytest.mark.parametrize("fail", [False, True], ids=["return", "exception"])
def test_candidate_reader_holds_full_body_fence(tmp_path, monkeypatch, reader, fail):
    repository = SQLiteRepository(tmp_path / "body.db")
    seed(repository)
    real_connection, real_lock = repository.connection, repository._lock
    real_parts = repository._candidate_query_parts
    real_records = repository.list_candidate_workflow_records
    owner = threading.local()
    events = []
    fault = RuntimeError("reader materialization fault")
    fired = []

    def observe(stage):
        events.append((stage, getattr(owner, "depth", 0) > 0))

    class ObservedLock:
        def __enter__(self):
            result = real_lock.__enter__()
            owner.depth = getattr(owner, "depth", 0) + 1
            return result

        def __exit__(self, *args):
            owner.depth -= 1
            return real_lock.__exit__(*args)

    class Row:
        def __init__(self, value):
            self.value = value

        def __getitem__(self, key):
            observe("materialize")
            if fail and not fired:
                fired.append("materialize")
                raise fault
            return self.value[key]

    class Cursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def fetchone(self):
            observe("fetchone")
            # Page count conversion is inside the fence too.
            row = self.cursor.fetchone()
            return Row(row) if row else None

        def fetchall(self):
            observe("fetchall")
            return [Row(row) for row in self.cursor.fetchall()]

    class Connection:
        def execute(self, *args):
            observe("execute")
            return Cursor(real_connection.execute(*args))

    def parts(*args):
        observe("query-parts")
        return real_parts(*args)

    def records(*args):
        observe("workflow-records")
        # Exercise a nested acquisition explicitly: the facade fence is reentrant.
        with repository._lock:
            return real_records(*args)

    with monkeypatch.context() as scoped:
        scoped.setattr(repository, "_lock", ObservedLock())
        scoped.setattr(repository, "connection", Connection())
        scoped.setattr(repository, "_candidate_query_parts", parts)
        scoped.setattr(repository, "list_candidate_workflow_records", records)
        if fail:
            with pytest.raises(RuntimeError) as caught:
                read_candidate(repository, None, reader)
            assert caught.value is fault
            assert fired == ["materialize"]
        else:
            assert_candidate(read_candidate(repository, None, reader), reader, "old", 40)
    try:
        assert {"query-parts", "execute", "materialize"} <= {stage for stage, _ in events}
        if reader == "workflow" and not fail:
            assert ("workflow-records", True) in events
        assert all(held for _, held in events), events
        assert not real_connection.in_transaction
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert_candidate(
                pool.submit(read_candidate, repository, None, reader).result(5), reader, "old", 40
            )
    finally:
        repository.close()
