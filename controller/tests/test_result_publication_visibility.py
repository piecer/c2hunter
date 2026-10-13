from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from publication_fixtures import publication_adapter  # noqa: F401
from test_candidate_fencing_races import wait_for_pg_block
from test_result_publication import Delivery, seed

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.mark.parametrize("point", ["insert", "metadata", "audit"])
def test_independent_reader_never_observes_inflight_publication(adapter: Any, point: str) -> None:
    if isinstance(adapter, MemoryRepository):
        pytest.skip("independent SQL reader")
    seed(adapter)
    queue = Delivery()
    application = create_app(Settings(environment="test"), adapter, queue=queue)
    connection = adapter.connection
    entered, release = threading.Event(), threading.Event()
    if isinstance(adapter, SQLiteRepository):
        path = connection.execute("PRAGMA database_list").fetchone()[2]

        def hold() -> int:
            entered.set()
            assert release.wait(10)
            return 1

        connection.create_function("hold_publication", 0, hold)
        event, table = {
            "insert": ("INSERT", "candidate_records"),
            "metadata": ("UPDATE", "objects"),
            "audit": ("INSERT", "audit_events"),
        }[point]
        connection.execute(
            f"CREATE TEMP TRIGGER hold_result AFTER {event} ON {table} "
            "BEGIN SELECT hold_publication(); END"
        )
        reader = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        import psycopg

        reader = psycopg.connect(adapter.database_url, autocommit=True)
        reader.execute("SELECT pg_advisory_lock(87654123)")
        connection.execute(
            "CREATE FUNCTION hold_publication() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN PERFORM pg_advisory_xact_lock(87654123); RETURN NEW; END $$"
        )
        event, table = {
            "insert": ("INSERT", "candidate_records"),
            "metadata": ("UPDATE", "controller_objects"),
            "audit": ("INSERT", "audit_events"),
        }[point]
        connection.execute(
            f"CREATE TRIGGER hold_result AFTER {event} ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION hold_publication()"
        )
        connection.commit()
        pid = connection.info.backend_pid
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(application.state.process_results_once)
            try:
                if isinstance(adapter, SQLiteRepository):
                    assert entered.wait(10)
                    stored = json.loads(
                        reader.execute(
                            "SELECT data FROM objects WHERE kind='job' AND id='job'"
                        ).fetchone()[0]
                    )
                else:
                    wait_for_pg_block(reader, pid, future)
                    stored = reader.execute(
                        "SELECT data FROM controller_objects WHERE kind='job' AND id='job'"
                    ).fetchone()[0]
                assert stored["status"] == "ANALYZING"
                assert reader.execute("SELECT candidate_id FROM candidate_records").fetchall() == [
                    ("old",)
                ]
                assert queue.acked == []
            finally:
                if isinstance(adapter, SQLiteRepository):
                    release.set()
                else:
                    reader.execute("SELECT pg_advisory_unlock(87654123)")
            assert future.result(timeout=10) is True
        assert adapter.get_job("job")["status"] == "COMPLETED"
        assert adapter.get_candidates("job")[0]["id"] == "new"
        assert queue.acked == ["delivery-1"]
        application.state.wait_for_candidate_enrichment()
    finally:
        release.set()
        reader.close()
