"""Observed barriers on new reader fences, not a replay of writer matrices."""

import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from c2hunter_controller import historical_read as r
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_historical_read import read
from tests.test_historical_read_bounds import adapter as adapter
from tests.test_historical_read_postgres import pg_repo as pg_repo
from tests.test_historical_source import stored


class ObservedLock:
    def __init__(self, inner: Any, attempted: threading.Event) -> None:
        self.inner, self.attempted = inner, attempted

    def __enter__(self) -> Any:
        if threading.current_thread().name.startswith("writer"):
            self.attempted.set()
        return self.inner.__enter__()

    def __exit__(self, *args: Any) -> Any:
        return self.inner.__exit__(*args)


def pg_blocked(observer: Any, pid: int, future: Any) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if observer.execute("SELECT cardinality(pg_blocking_pids(%s))", (pid,)).fetchone()[0]:
            return
        assert not future.done(), "writer finished before the held-reader fence"
    raise AssertionError("database lock barrier was not observed")


@pytest.mark.parametrize("mutation", ["replace", "delete"])
def test_reader_holds_fence_through_projection(
    adapter: Any,  # noqa: F811 -- imported pytest fixture
    mutation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter.save_job(stored())
    old = {"id": "old", "candidate_ip": "203.0.113.9", "score": 40}
    adapter.save_candidates("root", [old])
    admitted, release, attempted = threading.Event(), threading.Event(), threading.Event()
    finish = r._finish
    fired = []

    def blocked_finish(*args: Any, **kwargs: Any) -> Any:
        fired.append(True)
        admitted.set()
        if not release.wait(15):
            raise AssertionError("reader barrier timeout")
        return finish(*args, **kwargs)

    monkeypatch.setattr(r, "_finish", blocked_finish)
    peer, observer = adapter, None
    if isinstance(adapter, PostgresRepository):
        import psycopg

        peer = PostgresRepository(adapter.database_url, None)
        peer_pid = peer.connection.info.backend_pid
        observer = psycopg.connect(adapter.database_url, autocommit=True)
    else:
        monkeypatch.setattr(adapter, "_lock", ObservedLock(adapter._lock, attempted))
    try:
        with (
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="reader") as readers,
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="writer") as writers,
        ):
            result = readers.submit(read, adapter)
            assert admitted.wait(10)
            pending = (
                writers.submit(peer.delete_job, "root")
                if mutation == "delete"
                else writers.submit(peer.save_candidates, "root", [dict(old, id="new", score=80)])
            )
            try:
                if observer is not None:
                    pg_blocked(observer, peer_pid, pending)
                    assert observer.execute(
                        "SELECT candidate_id FROM candidate_records WHERE job_id='root'"
                    ).fetchone() == ("old",)
                else:
                    assert attempted.wait(10)
                assert not pending.done()
            finally:
                release.set()
            snapshot = result.result(timeout=10)
            pending.result(timeout=10)
        assert fired == [True]
        assert dict(snapshot.candidates[0].fields.entries)["id"] == "old"
        monkeypatch.setattr(r, "_finish", finish)
        if mutation == "delete":
            with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_NOT_FOUND$"):
                read(adapter)
        else:
            assert dict(read(adapter).candidates[0].fields.entries)["id"] == "new"
    finally:
        release.set()
        if observer is not None:
            observer.close()
            peer.connection.close()


@pytest.mark.parametrize("rollback", [False, True])
def test_sqlite_publication_reader_and_raw_snapshot(
    tmp_path: Path, rollback: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "publication.sqlite"
    repo = SQLiteRepository(path)
    raw = stored()
    raw.update(status="ANALYZING", candidate_count=1)
    repo.save_job(raw)
    repo.save_candidates("root", [{"id": "old", "candidate_ip": "203.0.113.9", "score": 40}])
    paused, release, attempted = threading.Event(), threading.Event(), threading.Event()
    fired = []

    def pause() -> int:
        fired.append(True)
        paused.set()
        if not release.wait(15):
            raise RuntimeError("publication barrier timeout")
        return 0

    repo.connection.create_function("h4_pause", 0, pause)
    repo.connection.execute(
        "CREATE TEMP TRIGGER h4_pause BEFORE INSERT ON candidate_records "
        "WHEN NEW.candidate_id='fresh' BEGIN SELECT h4_pause(); "
        + ("SELECT RAISE(ABORT,'h4 rollback'); " if rollback else "")
        + "END"
    )
    # ObservedLock labels its watched contender 'writer'; here that contender is
    # the reader, so we can observe lock entry without sleeping.
    monkeypatch.setattr(repo, "_lock", ObservedLock(repo._lock, attempted))
    complete = dict(raw, status="COMPLETED")
    with (
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="publisher") as writers,
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="writer-reader") as readers,
    ):
        publication = writers.submit(
            repo.complete_job_with_candidates,
            complete,
            [{"id": "fresh", "candidate_ip": "203.0.113.9", "score": 80}],
        )
        assert paused.wait(10)
        result = readers.submit(read, repo)
        try:
            assert attempted.wait(10)
            assert not result.done()
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as independent:
                assert (
                    json.loads(
                        independent.execute("SELECT data FROM objects WHERE kind='job'").fetchone()[
                            0
                        ]
                    )["status"]
                    == "ANALYZING"
                )
                assert independent.execute(
                    "SELECT candidate_id FROM candidate_records"
                ).fetchone() == ("old",)
        finally:
            release.set()
        if rollback:
            with pytest.raises(sqlite3.IntegrityError, match="h4 rollback"):
                publication.result(timeout=10)
            with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_STATE$"):
                result.result(timeout=10)
        else:
            assert publication.result(timeout=10)
            assert dict(result.result(timeout=10).candidates[0].fields.entries)["id"] == "fresh"
    assert fired == [True]
    assert not repo.connection.in_transaction
    repo.save_job(dict(raw, status="COMPLETED"))
    assert read(repo).source.original.id == "root"
    repo.close()


def test_pg_discovered_parent_change_does_not_chase(
    pg_repo: Any,  # noqa: F811 -- imported pytest fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psycopg

    pg_repo.save_job(stored())
    changed = dict(stored(), id="another")
    pg_repo.save_job(changed)
    original = r._pg_metadata
    calls = []
    with psycopg.connect(pg_repo.database_url, autocommit=True) as writer:

        def swap(cursor: Any, key: str) -> Any:
            value = original(cursor, key)
            calls.append(key)
            if len(calls) == 1:
                writer.execute(
                    "UPDATE controller_objects SET "
                    "data=jsonb_set(data,'{parent_job_id}','\"another\"') "
                    "WHERE kind='job' AND id='root'"
                )
            return value

        monkeypatch.setattr(r, "_pg_metadata", swap)
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_CHANGED$"):
            read(pg_repo)
        assert calls == ["root", "root"]
    monkeypatch.setattr(r, "_pg_metadata", original)
    assert len(read(pg_repo).source.lineage) == 2


@pytest.mark.parametrize("rollback", [False, True])
def test_pg_transaction_barrier_coherent_parts_and_candidates(
    pg_repo: Any,  # noqa: F811 -- imported pytest fixture
    rollback: bool,
) -> None:
    import psycopg

    pg_repo.save_job(stored())
    pg_repo.save_candidates("root", [{"id": "rule", "candidate_ip": "203.0.113.9", "score": 40}])
    pid = pg_repo.connection.info.backend_pid
    with (
        psycopg.connect(pg_repo.database_url) as writer,
        psycopg.connect(pg_repo.database_url, autocommit=True) as observer,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        writer.execute(
            "SELECT id FROM controller_objects WHERE kind='job' AND id='root' FOR UPDATE"
        )
        writer.execute(
            "UPDATE job_flow_record_chunks SET data=jsonb_set(data,'{0,total_bytes}','200') "
            "WHERE job_id='root'"
        )
        writer.execute(
            "UPDATE candidate_records SET data=jsonb_set(data,'{score}','80'),score=80 "
            "WHERE job_id='root'"
        )
        future = pool.submit(read, pg_repo)
        try:
            pg_blocked(observer, pid, future)
            assert observer.execute(
                "SELECT data->0->>'total_bytes' FROM job_flow_record_chunks WHERE job_id='root'"
            ).fetchone() == ("100",)
            assert observer.execute(
                "SELECT score FROM candidate_records WHERE job_id='root'"
            ).fetchone() == (40,)
        finally:
            writer.rollback() if rollback else writer.commit()
        result = future.result(timeout=10)
        assert result.source.strict_flows[0].total_bytes == (100 if rollback else 200)
        assert dict(result.candidates[0].fields.entries)["score"] == (40 if rollback else 80)
    assert read(pg_repo).source_binding_sha256 == result.source_binding_sha256
