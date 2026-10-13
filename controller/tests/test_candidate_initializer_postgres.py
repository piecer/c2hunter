from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from publication_fixtures import publication_adapter  # noqa: F401
from test_candidate_fencing_races import wait_for_pg_block

from c2hunter_controller.production import PostgresRepository


@pytest.mark.parametrize("remove_parent", [False, True])
def test_online_initializer_locks_parents_in_order_then_rereads(
    adapter: Any, monkeypatch: pytest.MonkeyPatch, remove_parent: bool
) -> None:
    if not isinstance(adapter, PostgresRepository):
        pytest.skip("real PostgreSQL online initializer")
    import psycopg

    for job_id in ("a", "z"):
        adapter.save_job({"id": job_id, "status": "ANALYZING"})
        adapter.connection.execute(
            "INSERT INTO job_candidates(job_id,data) VALUES(%s,%s::jsonb)",
            (job_id, '[{"id":"' + job_id + '-old"}]'),
        )
        adapter.connection.commit()
    connect = psycopg.connect
    opened = threading.Event()
    backend: list[int] = []
    initializer = PostgresRepository(adapter.database_url, adapter.blob_store)
    with (
        connect(adapter.database_url) as owner,
        connect(adapter.database_url, autocommit=True) as observer,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        owner.execute("SELECT id FROM controller_objects WHERE kind='job' AND id='z' FOR UPDATE")

        def owned_connect(*args: Any, **kwargs: Any) -> Any:
            connection = connect(*args, **kwargs)
            backend.append(connection.info.backend_pid)
            opened.set()
            return connection

        monkeypatch.setattr(psycopg, "connect", owned_connect)
        future = executor.submit(lambda: initializer.connection)
        try:
            assert opened.wait(10)
            wait_for_pg_block(observer, backend[0], future)
            query = observer.execute(
                "SELECT query FROM pg_stat_activity WHERE pid=%s", (backend[0],)
            ).fetchone()[0]
            assert "ORDER BY id FOR UPDATE" in query
            with pytest.raises(psycopg.errors.LockNotAvailable):
                observer.execute(
                    "SELECT id FROM controller_objects WHERE kind='job' "
                    "AND id='a' FOR UPDATE NOWAIT"
                )
            if remove_parent:
                owner.execute("DELETE FROM controller_objects WHERE kind='job' AND id='z'")
            else:
                owner.execute(
                    "UPDATE job_candidates SET data='[{\"id\":\"z-fresh\"}]' WHERE job_id='z'"
                )
        finally:
            owner.commit()
        future.result(timeout=10)
    try:
        assert initializer.get_candidates("a") == [{"id": "a-old"}]
        assert initializer.get_candidates("z") == ([] if remove_parent else [{"id": "z-fresh"}])
    finally:
        initializer.close()
