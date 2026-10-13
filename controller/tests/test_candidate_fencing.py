from __future__ import annotations

from typing import Any

import pytest
from publication_fixtures import publication_adapter  # noqa: F401
from test_result_publication import seed


def test_replacement_rejects_deleted_parent_without_orphans(adapter: Any) -> None:
    seed(adapter)
    assert adapter.delete_job("job")
    with pytest.raises(ValueError, match="^candidate parent job not found$"):
        adapter.save_candidates("job", [{"id": "orphan", "score": 90}])
    assert adapter.get_candidates("job") == []
    assert adapter.get_job("job") is None
    with pytest.raises(ValueError, match="^candidate parent job not found$"):
        adapter.save_candidates("missing", [])


@pytest.mark.parametrize("updates", [{"id": "other"}, {"job_id": "other"}])
def test_candidate_identity_is_immutable(adapter: Any, updates: dict[str, Any]) -> None:
    seed(adapter)
    before = adapter.get_candidates("job")
    with pytest.raises(ValueError, match="^candidate identity is immutable$"):
        adapter.update_candidate("old", updates)
    assert adapter.get_candidates("job") == before
    assert adapter.update_candidate("missing", updates) is None
    assert adapter.delete_candidate("missing") is False


@pytest.mark.parametrize("operation", ["replace", "update", "delete"])
def test_sql_candidate_writer_fault_rolls_back_and_closes_transaction(
    adapter: Any, operation: str
) -> None:
    from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository

    if isinstance(adapter, MemoryRepository):
        pytest.skip("SQL fault injection")
    seed(adapter)
    connection = adapter.connection
    event = {"replace": "INSERT", "update": "UPDATE", "delete": "DELETE"}[operation]
    if isinstance(adapter, SQLiteRepository):
        import sqlite3

        connection.execute(
            f"CREATE TEMP TRIGGER fail_candidate AFTER {event} ON candidate_records "
            "BEGIN SELECT RAISE(ABORT,'writer fault'); END"
        )
        error = sqlite3.IntegrityError
    else:
        import psycopg

        connection.execute(
            "CREATE FUNCTION fail_candidate() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'writer fault'; END $$"
        )
        connection.execute(
            f"CREATE TRIGGER fail_candidate AFTER {event} ON candidate_records "
            "FOR EACH ROW EXECUTE FUNCTION fail_candidate()"
        )
        connection.commit()
        error = psycopg.errors.RaiseException
    actions = {
        "replace": lambda: adapter.save_candidates("job", [{"id": "new", "score": 90}]),
        "update": lambda: adapter.update_candidate("old", {"score_adjustment": 10}),
        "delete": lambda: adapter.delete_candidate("old"),
    }
    with pytest.raises(error, match="writer fault"):
        actions[operation]()
    if isinstance(adapter, SQLiteRepository):
        assert not connection.in_transaction
        connection.execute("DROP TRIGGER fail_candidate")
    else:
        assert connection.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
        connection.execute("DROP TRIGGER fail_candidate ON candidate_records")
        connection.commit()
    assert adapter.get_candidates("job") == [{"id": "old", "score": 40}]
    actions[operation]()
