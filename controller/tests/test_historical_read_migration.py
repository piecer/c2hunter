"""Actual initializer/read schedule at standalone legacy representation selection."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from c2hunter_controller import historical_read as r
from c2hunter_controller.production import PostgresRepository
from tests.test_historical_read import read
from tests.test_historical_read_postgres import pg_repo  # noqa: F401
from tests.test_historical_source import stored


def test_standalone_legacy_initializer_preserves_reader_snapshot(
    pg_repo: Any,  # noqa: F811 -- imported fixture
    monkeypatch: Any,
) -> None:
    import psycopg

    raw = stored()
    pg_repo.save_job(raw)
    pg_repo.connection.execute("DELETE FROM job_flow_record_chunks WHERE job_id='root'")
    pg_repo.connection.execute(
        "INSERT INTO job_flow_records(job_id,data) VALUES('root',%s::jsonb)",
        (json.dumps(raw["flow_records"]),),
    )
    pg_repo.connection.commit()
    expected = read(pg_repo)
    assert len(expected.source.strict_flows) == 32
    # Resolve this facade property before its worker acquires the facade lock.
    reader_pid = pg_repo.connection.info.backend_pid
    initializer = PostgresRepository(pg_repo.database_url, None)
    ddl_done, release_initializer = threading.Event(), threading.Event()
    selected, release_reader = threading.Event(), threading.Event()
    initializer_pid = []
    seams = []
    execute = psycopg.Cursor.execute
    flows = r._pg_flows

    def observe_execute(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        if (
            threading.current_thread().name.startswith("initializer")
            and isinstance(query, str)
            and query.startswith("SELECT id FROM controller_objects WHERE kind='job' AND (")
        ):
            initializer_pid.append(cursor.connection.info.backend_pid)
            seams.append("initializer-after-bootstrap-commit")
            ddl_done.set()
            assert release_initializer.wait(15), "initializer seam timed out"
        return execute(cursor, query, *args, **kwargs)

    class SelectionBarrier:
        def __init__(self, cursor: Any) -> None:
            self.cursor = cursor

        def __getattr__(self, name: str) -> Any:
            return getattr(self.cursor, name)

        def execute(self, query: str, *args: Any, **kwargs: Any) -> Any:
            if query.startswith("SELECT COALESCE(sum(octet_length(data::text)),0)"):
                assert "FROM job_flow_records WHERE" in query
                seams.append("reader-selected-standalone-legacy")
                selected.set()
                assert release_reader.wait(15), "reader seam timed out"
            return self.cursor.execute(query, *args, **kwargs)

    monkeypatch.setattr(psycopg.Cursor, "execute", observe_execute)
    monkeypatch.setattr(r, "_pg_flows", lambda cursor, key: flows(SelectionBarrier(cursor), key))
    blocked_query = None
    try:
        with (
            psycopg.connect(pg_repo.database_url, autocommit=True) as observer,
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="initializer") as initializers,
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="reader") as readers,
        ):
            pending = initializers.submit(lambda: initializer.connection)
            try:
                assert ddl_done.wait(10), "bootstrap did not reach the data-migration seam"
                result = readers.submit(read, pg_repo)
                assert selected.wait(10)
                release_initializer.set()
                deadline = time.monotonic() + 10
                while not pending.done():
                    blockers, query = observer.execute(
                        "SELECT pg_blocking_pids(pid),query FROM pg_stat_activity WHERE pid=%s",
                        (initializer_pid[0],),
                    ).fetchone()
                    if reader_pid in blockers:
                        blocked_query = query
                        break
                    assert time.monotonic() < deadline, "neither commit nor parent fence observed"
                if blocked_query is None:
                    pending.result(timeout=5)
                    # RED control: the actual initializer moved storage while the
                    # actual reader still owns the source parent row.
                    assert observer.execute(
                        "SELECT count(*) FROM job_flow_records WHERE job_id='root'"
                    ).fetchone() == (0,)
                    assert observer.execute(
                        "SELECT jsonb_array_length(data) FROM job_flow_record_chunks "
                        "WHERE job_id='root'"
                    ).fetchone() == (32,)
                else:
                    assert "ORDER BY id FOR UPDATE" in blocked_query
                    assert observer.execute(
                        "SELECT jsonb_array_length(data) FROM job_flow_records WHERE job_id='root'"
                    ).fetchone() == (32,)
            finally:
                release_reader.set()
                release_initializer.set()
            snapshot = result.result(timeout=10)
            pending.result(timeout=10)
        assert seams == [
            "initializer-after-bootstrap-commit",
            "reader-selected-standalone-legacy",
        ]
        assert snapshot == expected
        assert blocked_query is not None, "standalone migration bypassed the source parent fence"
        monkeypatch.undo()
        assert read(pg_repo) == expected
        assert initializer.get_job("root")["flow_records"] == raw["flow_records"]
    finally:
        release_reader.set()
        release_initializer.set()
        initializer.close()
