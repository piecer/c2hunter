from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from publication_fixtures import publication_adapter  # noqa: F401
from test_result_publication import seed

from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import SQLiteRepository


def wait_for_pg_block(observer: Any, pid: int, future: Any) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        row = observer.execute("SELECT cardinality(pg_blocking_pids(%s))", (pid,)).fetchone()
        if row[0]:
            return
        if future.done():
            future.result()
            pytest.fail("candidate writer bypassed owning job fence")
        threading.Event().wait(0.01)
    pytest.fail("writer did not reach the owning job fence")


@pytest.mark.parametrize("operation", ["replace", "update", "delete"])
def test_pg_candidate_writer_waits_for_job_fence(adapter: Any, operation: str) -> None:
    if not isinstance(adapter, PostgresRepository):
        pytest.skip("PostgreSQL two-connection lock test")
    import psycopg

    seed(adapter)
    with (
        psycopg.connect(adapter.database_url) as reader,
        psycopg.connect(adapter.database_url, autocommit=True) as observer,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        reader.execute("SELECT id FROM controller_objects WHERE kind='job' AND id='job' FOR UPDATE")
        before = reader.execute("SELECT data FROM candidate_records ORDER BY position").fetchall()
        operations = {
            "replace": lambda: adapter.save_candidates("job", [{"id": "new", "score": 99}]),
            "update": lambda: adapter.update_candidate("old", {"score": 99, "excluded": True}),
            "delete": lambda: adapter.delete_candidate("old"),
        }
        pid = adapter.connection.info.backend_pid
        future = executor.submit(operations[operation])
        try:
            wait_for_pg_block(observer, pid, future)
            assert (
                reader.execute("SELECT data FROM candidate_records ORDER BY position").fetchall()
                == before
            )
        finally:
            reader.commit()
        future.result(timeout=10)


def test_sqlite_update_reads_inside_write_fence(tmp_path: Path) -> None:
    first = SQLiteRepository(tmp_path / "fence.db")
    second = SQLiteRepository(tmp_path / "fence.db")
    seed(first)
    first.connection.execute("BEGIN IMMEDIATE")
    first.connection.execute(
        "UPDATE candidate_records SET score=70,data=? WHERE candidate_id='old'",
        (json.dumps({"id": "old", "score": 70}),),
    )
    reached_write = threading.Event()
    second.connection.set_trace_callback(
        lambda sql: reached_write.set() if sql.startswith(("BEGIN", "UPDATE")) else None
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(second.update_candidate, "old", {"score_adjustment": 10})
        try:
            assert reached_write.wait(10)
        finally:
            first.connection.commit()
        assert future.result(timeout=10)["score"] == 80
    assert not second.connection.in_transaction
    first.close()
    second.close()


@pytest.mark.parametrize("operation", ["update", "delete"])
@pytest.mark.parametrize("change", ["delete_parent", "move_candidate"])
def test_pg_per_id_writer_rereads_owner_after_wait(
    adapter: Any, operation: str, change: str
) -> None:
    if not isinstance(adapter, PostgresRepository):
        pytest.skip("PostgreSQL two-connection ownership race")
    import psycopg

    seed(adapter)
    adapter.save_job({"id": "other", "status": "COMPLETED"})
    pid = adapter.connection.info.backend_pid
    with (
        psycopg.connect(adapter.database_url) as owner,
        psycopg.connect(adapter.database_url, autocommit=True) as observer,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        owner.execute("SELECT id FROM controller_objects WHERE kind='job' AND id='job' FOR UPDATE")
        action = (
            (lambda: adapter.update_candidate("old", {"score": 99}))
            if operation == "update"
            else lambda: adapter.delete_candidate("old")
        )
        future = executor.submit(action)
        try:
            wait_for_pg_block(observer, pid, future)
            if change == "delete_parent":
                owner.execute("DELETE FROM candidate_records WHERE job_id='job'")
                owner.execute("DELETE FROM controller_objects WHERE kind='job' AND id='job'")
            else:
                owner.execute(
                    "UPDATE candidate_records SET job_id='other' WHERE candidate_id='old'"
                )
        finally:
            owner.commit()
        result = future.result(timeout=10)
        assert result is (None if operation == "update" else False)
    if change == "move_candidate":
        assert adapter.get_candidate("old") == ("other", {"id": "old", "score": 40})
    else:
        assert adapter.get_candidate("old") is None
