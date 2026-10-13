from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest
from publication_fixtures import publication_adapter  # noqa: F401
from test_result_publication import Delivery, seed

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.mark.parametrize("status", ["COMPLETED", "PARTIALLY_COMPLETED"])
@pytest.mark.parametrize("empty", [True, False])
def test_completion_closed_boolean_preserves_parts_and_first_terminal(
    adapter: Any, status: str, empty: bool
) -> None:
    original = seed(adapter)
    candidates = [] if empty else [{"id": "new", "score": 80}]
    target = {
        **original,
        "status": status,
        "candidate_count": len(candidates),
        "flow_records": [],
        "payload_signatures": [],
    }
    assert adapter.complete_job_with_candidates(target, candidates) is True
    stored = adapter.get_job("job")
    assert stored["status"] == status
    assert stored["flow_records"] == original["flow_records"]
    assert stored["payload_signatures"] == original["payload_signatures"]
    assert adapter.get_candidates("job") == candidates
    # The nonempty duplicate must be valid, but lose without replacing anything.
    assert adapter.complete_job_with_candidates(target, candidates) is False
    assert adapter.transition_job_terminal({**target, "status": "CANCELLED"}) is False
    assert adapter.get_candidates("job") == candidates


@pytest.mark.parametrize(
    "updates",
    [
        {"status": "FAILED"},
        {"status": "ANALYZING"},
        {"candidate_count": 2},
        {"candidate_count": True},
        {"candidate_count": "1"},
    ],
)
def test_completion_rejects_invalid_targets_without_mutation(
    adapter: Any, updates: dict[str, Any]
) -> None:
    original = seed(adapter)
    with pytest.raises(ValueError):
        adapter.complete_job_with_candidates(
            {**original, "status": "COMPLETED", **updates}, [{"id": "new"}]
        )
    assert adapter.get_job("job") == original
    assert adapter.get_candidates("job") == [{"id": "old", "score": 40}]


def test_completion_audits_only_winning_publication(adapter: Any) -> None:
    original = seed(adapter)

    def events() -> list[Any]:
        if isinstance(adapter, MemoryRepository):
            return [(event["kind"], event["data"]) for event in adapter.audit_events]
        rows = adapter.connection.execute(
            "SELECT kind,data FROM audit_events ORDER BY occurred_at,kind"
        ).fetchall()
        if isinstance(adapter, PostgresRepository):
            adapter.connection.commit()
            return rows
        return [(kind, json.loads(data)) for kind, data in rows]

    before = len(events())
    target = {**original, "status": "COMPLETED"}
    assert adapter.complete_job_with_candidates(target, [{"id": "new"}]) is True
    saved = events()
    assert len(saved) == before + 2
    assert any(kind == "job" and data["status"] == "COMPLETED" for kind, data in saved)
    assert any(kind == "candidates" and data == [{"id": "new"}] for kind, data in saved)
    assert adapter.complete_job_with_candidates(target, [{"id": "other"}]) is False
    assert events() == saved


def test_completion_missing_and_cancelled_are_false(adapter: Any) -> None:
    original = seed(adapter)
    assert adapter.transition_job_terminal({**original, "status": "CANCELLED"}) is True
    target = {**original, "status": "COMPLETED"}
    assert adapter.complete_job_with_candidates(target, [{"id": "late"}]) is False
    assert (
        adapter.complete_job_with_candidates({**target, "id": "missing"}, [{"id": "late"}]) is False
    )
    assert adapter.get_candidates("job") == [{"id": "old", "score": 40}]


def test_completion_serialization_fault_identity_and_reuse(adapter: Any) -> None:
    original = seed(adapter)
    fault = RuntimeError("serialization fault")

    class BadValue:
        def __str__(self) -> str:
            raise fault

    with pytest.raises(RuntimeError) as caught:
        adapter.complete_job_with_candidates(
            {**original, "status": "COMPLETED"}, [{"id": "bad", "evidence": BadValue()}]
        )
    assert caught.value is fault
    assert adapter.get_job("job") == original
    assert adapter.get_candidates("job") == [{"id": "old", "score": 40}]
    assert adapter.complete_job_with_candidates(
        {**original, "status": "COMPLETED", "candidate_count": 0}, []
    )


@pytest.mark.parametrize("point", ["insert", "metadata", "audit", "commit"])
def test_sql_fault_delivery_is_atomic_and_unacked(adapter: Any, point: str) -> None:
    if isinstance(adapter, MemoryRepository):
        pytest.skip("SQL fault injection")
    seed(adapter)
    delivery = Delivery()
    app = create_app(Settings(environment="test"), adapter, queue=delivery)
    connection = adapter.connection
    if isinstance(adapter, SQLiteRepository):
        if point == "commit":
            connection.executescript(
                "PRAGMA foreign_keys=ON; CREATE TABLE guard_parent(id INTEGER PRIMARY KEY);"
                "CREATE TABLE guard_child(id INTEGER REFERENCES guard_parent(id) "
                "DEFERRABLE INITIALLY DEFERRED);"
                "CREATE TEMP TRIGGER fail_write AFTER UPDATE ON objects "
                "BEGIN INSERT INTO guard_child VALUES(1); END;"
            )
        else:
            event, table = {
                "insert": ("INSERT", "candidate_records"),
                "metadata": ("UPDATE", "objects"),
                "audit": ("INSERT", "audit_events"),
            }[point]
            connection.execute(
                f"CREATE TEMP TRIGGER fail_write AFTER {event} ON {table} "
                "BEGIN SELECT RAISE(ABORT,'publication fault'); END"
            )
        error = sqlite3.IntegrityError
    else:
        import psycopg

        event, table = {
            "insert": ("INSERT", "candidate_records"),
            "metadata": ("UPDATE", "controller_objects"),
            "audit": ("INSERT", "audit_events"),
            "commit": ("INSERT", "audit_events"),
        }[point]
        connection.execute(
            "CREATE FUNCTION fail_publication() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'publication fault'; END $$"
        )
        if point == "commit":
            connection.execute(
                "CREATE CONSTRAINT TRIGGER fail_write AFTER INSERT ON audit_events "
                "DEFERRABLE INITIALLY DEFERRED "
                "FOR EACH ROW EXECUTE FUNCTION fail_publication()"
            )
        else:
            connection.execute(
                f"CREATE TRIGGER fail_write AFTER {event} ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION fail_publication()"
            )
        connection.commit()
        error = psycopg.errors.RaiseException
    with pytest.raises(error):
        app.state.process_results_once()
    assert delivery.acked == []
    # Independent SQL observation before repository reads/reopen/cleanup.
    if isinstance(adapter, SQLiteRepository):
        db = connection.execute("PRAGMA database_list").fetchone()[2]
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as reader:
            row = reader.execute(
                "SELECT data FROM objects WHERE kind='job' AND id='job'"
            ).fetchone()
            assert json.loads(row[0])["status"] == "ANALYZING"
            assert reader.execute("SELECT candidate_id FROM candidate_records").fetchall() == [
                ("old",)
            ]
        assert not connection.in_transaction
        connection.execute("DROP TRIGGER fail_write")
    else:
        import psycopg

        with psycopg.connect(adapter.database_url) as reader:
            assert reader.execute(
                "SELECT data->>'status' FROM controller_objects WHERE kind='job' AND id='job'"
            ).fetchone() == ("ANALYZING",)
            assert reader.execute("SELECT candidate_id FROM candidate_records").fetchall() == [
                ("old",)
            ]
        assert connection.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
        connection.execute(f"DROP TRIGGER fail_write ON {table}")
        connection.commit()
    assert app.state.process_results_once()
    assert delivery.acked == ["delivery-1"]
    assert adapter.get_job("job")["status"] == "COMPLETED"
    assert adapter.get_candidates("job")[0]["id"] == "new"
    app.state.wait_for_candidate_enrichment()
