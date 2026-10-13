from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from publication_fixtures import publication_adapter  # noqa: F401
from test_candidate_fencing_races import wait_for_pg_block
from test_result_publication import seed

from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.mark.parametrize("contender", ["success", "cancel"])
def test_publication_holds_fence_until_both_parts_are_ready(adapter: Any, contender: str) -> None:
    original = seed(adapter)
    entered, release, attempted = threading.Event(), threading.Event(), threading.Event()

    class HeldId(str):
        def __str__(self) -> str:
            entered.set()
            if not release.wait(10):
                raise RuntimeError("publication barrier timed out")
            return "winner"

    target = {**original, "status": "COMPLETED"}
    if isinstance(adapter, PostgresRepository):
        import psycopg

        second = PostgresRepository(adapter.database_url, adapter.blob_store)
        second._connection = psycopg.connect(adapter.database_url)
        observer = psycopg.connect(adapter.database_url, autocommit=True)
        pid = second.connection.info.backend_pid
    elif isinstance(adapter, SQLiteRepository):
        path = adapter.connection.execute("PRAGMA database_list").fetchone()[2]
        second = SQLiteRepository(path)
        second.connection.set_trace_callback(
            lambda sql: attempted.set() if sql == "BEGIN IMMEDIATE" else None
        )
    else:
        second = adapter

    def compete() -> bool:
        attempted.set()
        if contender == "cancel":
            return second.transition_job_terminal({**original, "status": "CANCELLED"})
        return second.complete_job_with_candidates(target, [{"id": "loser", "score": 1}])

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(
                adapter.complete_job_with_candidates,
                target,
                [{"id": HeldId("winner"), "score": 99}],
            )
            assert entered.wait(10)
            other = executor.submit(compete)
            try:
                assert attempted.wait(10)
                if isinstance(adapter, PostgresRepository):
                    wait_for_pg_block(observer, pid, other)
                    assert observer.execute(
                        "SELECT data->>'status' FROM controller_objects "
                        "WHERE kind='job' AND id='job'"
                    ).fetchone() == ("ANALYZING",)
                    assert observer.execute(
                        "SELECT candidate_id FROM candidate_records"
                    ).fetchall() == [("old",)]
                elif isinstance(adapter, SQLiteRepository):
                    import sqlite3

                    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as reader:
                        assert reader.execute(
                            "SELECT json_extract(data,'$.status') FROM objects WHERE kind='job'"
                        ).fetchone() == ("ANALYZING",)
                        assert reader.execute(
                            "SELECT candidate_id FROM candidate_records"
                        ).fetchall() == [("old",)]
                assert not other.done()
            finally:
                release.set()
            assert first.result(timeout=10) is True
            assert other.result(timeout=10) is False
        assert adapter.get_job("job")["status"] == "COMPLETED"
        assert adapter.get_candidates("job")[0]["id"] == "winner"
    finally:
        release.set()
        if second is not adapter:
            second.close()
        if isinstance(adapter, PostgresRepository):
            observer.close()


@pytest.mark.parametrize(
    "method,args",
    [
        ("get_candidates", ("job",)),
        ("get_candidate", ("old",)),
        ("list_candidate_sets", ()),
        ("get_job", ("job",)),
        ("get_job_summary", ("job",)),
        ("list_jobs", ()),
        ("query_candidates", ()),
    ],
)
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_public_readers_respect_publication_fence(
    method: str, args: tuple[Any, ...], backend: str, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "readers.db")
    )
    seed(repository)
    entered = threading.Event()
    real = repository._lock

    class ObservedLock:
        def __enter__(self) -> Any:
            entered.set()
            return real.__enter__()

        def __exit__(self, *args: Any) -> Any:
            return real.__exit__(*args)

    repository._lock = ObservedLock()  # type: ignore[assignment]
    with ThreadPoolExecutor(max_workers=1) as executor:
        with real:
            future = executor.submit(getattr(repository, method), *args)
            # A completed reader without even attempting the fence is a bypass.
            while not entered.wait(0.01) and not future.done():
                pass
            assert entered.is_set(), "reader bypassed publication fence"
        assert future.result(timeout=10) is not None
