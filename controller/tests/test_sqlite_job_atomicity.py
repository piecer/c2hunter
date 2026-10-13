from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from pathlib import Path
from threading import Barrier, Event
from typing import Any

import pytest

from c2hunter_controller.repositories import SQLiteRepository


def _job(generation: str, *, job_id: str = "job-1") -> dict[str, Any]:
    return {
        "id": job_id,
        "idempotency_key": "same-key",
        "status": "ANALYZING",
        "source": {"generation": generation},
        "flow_records": [{"generation": generation, "packet_count": 3}],
        "payload_signatures": [{"generation": generation, "signature": "abc"}],
    }


def _durable_state(path: Path) -> dict[str, list[tuple[Any, ...]]]:
    # A genuinely independent read-only connection: do not close/rollback the writer
    # or run repository initialization/migrations before observing durable data.
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as connection:
        return {
            "jobs": connection.execute(
                "SELECT id,data FROM objects WHERE kind='job' ORDER BY id"
            ).fetchall(),
            "flows": connection.execute(
                "SELECT job_id,data FROM job_flow_records ORDER BY job_id"
            ).fetchall(),
            "signatures": connection.execute(
                "SELECT job_id,data FROM job_payload_signatures ORDER BY job_id"
            ).fetchall(),
            "ledger": connection.execute(
                "SELECT key,job_id FROM idempotency ORDER BY key"
            ).fetchall(),
        }


def test_save_failure_after_metadata_preserves_complete_old_snapshot(tmp_path: Path) -> None:
    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        original = _job("old")
        repository.create_job(original)
        before = _durable_state(path)
        repository.connection.execute(
            "CREATE TEMP TRIGGER fail_flows BEFORE INSERT ON job_flow_records "
            "BEGIN SELECT RAISE(ABORT, 'injected flow failure'); END"
        )
        replacement = _job("new")
        unchanged = deepcopy(replacement)

        with pytest.raises(sqlite3.IntegrityError, match="injected flow failure"):
            repository.save_job(replacement)

        assert _durable_state(path) == before
        assert not repository.connection.in_transaction
        assert replacement == unchanged
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(original["id"]) == original
        repository.connection.execute("DROP TRIGGER fail_flows")
        assert repository.save_job(replacement) == replacement
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(replacement["id"]) == replacement


@pytest.mark.parametrize("timing", ["BEFORE", "AFTER"])
def test_create_ledger_failure_leaves_no_orphan_and_connection_is_reusable(
    tmp_path: Path, timing: str
) -> None:
    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        before = _durable_state(path)
        repository.connection.execute(
            f"CREATE TEMP TRIGGER fail_ledger {timing} INSERT ON idempotency "
            "BEGIN SELECT RAISE(ABORT, 'injected ledger failure'); END"
        )
        job = _job("new")

        with pytest.raises(sqlite3.IntegrityError, match="injected ledger failure"):
            repository.create_job(job)

        assert _durable_state(path) == before
        assert not repository.connection.in_transaction
        assert repository.get_job(job["id"]) is None
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(job["id"]) is None
        repository.connection.execute("DROP TRIGGER fail_ledger")
        assert repository.create_job(job) == (job, True)
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(job["id"]) == job
            assert reopened.create_job(_job("ignored", job_id="ignored")) == (job, False)
        assert _durable_state(path)["ledger"] == [("same-key", job["id"])]


@pytest.mark.parametrize("operation", ["save", "create"])
@pytest.mark.parametrize("table", ["objects", "job_flow_records", "job_payload_signatures"])
def test_sql_failure_after_each_job_part_rolls_back(
    tmp_path: Path, operation: str, table: str
) -> None:
    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        original = _job("old")
        if operation == "save":
            repository.create_job(original)
        before = _durable_state(path)
        event = "UPDATE" if operation == "save" else "INSERT"
        repository.connection.execute(
            f"CREATE TEMP TRIGGER fail_part AFTER {event} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'injected part failure'); END"
        )
        replacement = _job("new")
        write = repository.save_job if operation == "save" else repository.create_job

        with pytest.raises(sqlite3.IntegrityError, match="injected part failure"):
            write(replacement)

        assert _durable_state(path) == before
        assert not repository.connection.in_transaction
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(original["id"]) == (original if operation == "save" else None)
        repository.connection.execute("DROP TRIGGER fail_part")
        write(replacement)
        assert not repository.connection.in_transaction
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(replacement["id"]) == replacement
        assert _durable_state(path)["ledger"] == [("same-key", replacement["id"])]


@pytest.mark.parametrize("operation", ["save", "create"])
@pytest.mark.parametrize("part", ["source", "flow_records", "payload_signatures"])
def test_serialization_failure_preserves_state_and_original_error(
    tmp_path: Path, operation: str, part: str
) -> None:
    error = ValueError("injected serialization failure")

    class Unserializable:
        def __str__(self) -> str:
            raise error

    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        original = _job("old")
        if operation == "save":
            repository.create_job(original)
        before = _durable_state(path)
        replacement = _job("new")
        replacement[part] = Unserializable()
        write = repository.save_job if operation == "save" else repository.create_job

        with pytest.raises(ValueError, match="injected serialization failure") as raised:
            write(replacement)

        assert raised.value is error
        assert _durable_state(path) == before
        assert not repository.connection.in_transaction
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(original["id"]) == (original if operation == "save" else None)
        write(_job("reused"))
        assert not repository.connection.in_transaction
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(original["id"]) == _job("reused")


def test_replay_returns_original_complete_job_and_releases_transaction(tmp_path: Path) -> None:
    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        original = _job("old")
        repository.create_job(original)
        before = _durable_state(path)
        transactions: list[str] = []
        repository.connection.set_trace_callback(transactions.append)

        replay, created = repository.create_job(_job("ignored", job_id="ignored"))

        assert not created
        assert replay == original
        assert not repository.connection.in_transaction
        assert _durable_state(path) == before
        assert [sql for sql in transactions if sql.startswith(("BEGIN", "COMMIT", "ROLLBACK"))] == [
            "BEGIN IMMEDIATE",
            "COMMIT",
        ]
        replay["source"]["generation"] = "mutated"
        replay["flow_records"][0]["generation"] = "mutated"
        replay["payload_signatures"].clear()
        assert repository.get_job(original["id"]) == original
        with closing(SQLiteRepository(str(path))) as reopened:
            another = _job("another", job_id="another")
            another["idempotency_key"] = "another-key"
            assert reopened.create_job(another) == (another, True)


def test_broken_ledger_replay_rolls_back_and_preserves_error(tmp_path: Path) -> None:
    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        repository.connection.execute(
            "INSERT INTO idempotency(key,job_id) VALUES('same-key','missing')"
        )
        repository.connection.commit()
        before = _durable_state(path)

        with pytest.raises(RuntimeError, match="idempotency ledger references missing job"):
            repository.create_job(_job("new"))

        assert _durable_state(path) == before
        assert not repository.connection.in_transaction
        another = _job("another", job_id="another")
        another["idempotency_key"] = "another-key"
        assert repository.create_job(another) == (another, True)


@pytest.mark.parametrize("operation", ["save", "create"])
def test_commit_failure_rolls_back_all_parts(tmp_path: Path, operation: str) -> None:
    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        original = _job("old")
        if operation == "save":
            repository.create_job(original)
        before = _durable_state(path)
        # A real deferred FK failure occurs at COMMIT, after all public writes.
        repository.connection.executescript(
            "CREATE TEMP TABLE fault_parent(id INTEGER PRIMARY KEY);"
            "CREATE TEMP TABLE fault_child(parent_id INTEGER REFERENCES fault_parent(id) "
            "DEFERRABLE INITIALLY DEFERRED);"
            "CREATE TEMP TRIGGER fail_commit AFTER INSERT ON objects "
            "BEGIN INSERT INTO fault_child VALUES(1); END;"
            "CREATE TEMP TRIGGER fail_commit_update AFTER UPDATE ON objects "
            "BEGIN INSERT INTO fault_child VALUES(1); END;"
        )
        write = repository.save_job if operation == "save" else repository.create_job

        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
            write(_job("new"))

        assert _durable_state(path) == before
        assert not repository.connection.in_transaction
        assert repository.connection.execute("SELECT * FROM fault_child").fetchall() == []
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(original["id"]) == (original if operation == "save" else None)
        repository.connection.execute("DROP TRIGGER fail_commit")
        repository.connection.execute("DROP TRIGGER fail_commit_update")
        write(_job("reused"))
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(original["id"]) == _job("reused")


@pytest.mark.parametrize("operation", ["save", "create"])
def test_successful_write_returns_caller_independent_data(tmp_path: Path, operation: str) -> None:
    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        job = _job("new")
        expected = deepcopy(job)
        if operation == "save":
            returned = repository.save_job(job)
        else:
            returned, created = repository.create_job(job)
            assert created
        assert returned == expected
        assert not repository.connection.in_transaction
        job["source"]["generation"] = "mutated input"
        job["flow_records"].clear()
        job["payload_signatures"][0]["signature"] = "mutated input"
        assert returned == expected
        returned["source"]["generation"] = "mutated return"
        returned["flow_records"][0]["generation"] = "mutated return"
        returned["payload_signatures"].clear()
        assert repository.get_job(expected["id"]) == expected
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(expected["id"]) == expected


@pytest.mark.parametrize("clear_flows", [False, True])
@pytest.mark.parametrize("clear_signatures", [False, True])
def test_omitted_parts_are_preserved_but_explicit_empty_parts_replace(
    tmp_path: Path, clear_flows: bool, clear_signatures: bool
) -> None:
    path = tmp_path / "atomic.sqlite"
    with closing(SQLiteRepository(str(path))) as repository:
        original = _job("old")
        repository.create_job(original)
        replacement = _job("new")
        expected = deepcopy(replacement)
        for part, clear in [
            ("flow_records", clear_flows),
            ("payload_signatures", clear_signatures),
        ]:
            if clear:
                replacement[part] = []
                expected[part] = []
            else:
                del replacement[part]
                expected[part] = original[part]
        # Saving must not create/update ledger entries, even if metadata changes its key.
        replacement["idempotency_key"] = expected["idempotency_key"] = "metadata-only-key"

        assert repository.save_job(replacement) == replacement

        assert not repository.connection.in_transaction
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(original["id"]) == expected
        assert _durable_state(path)["ledger"] == [("same-key", original["id"])]


def test_two_connections_same_key_have_one_creator_and_one_complete_replay(tmp_path: Path) -> None:
    path = tmp_path / "atomic.sqlite"
    with (
        closing(SQLiteRepository(str(path))) as first,
        closing(SQLiteRepository(str(path))) as second,
    ):
        staged = Barrier(2, timeout=5)
        release = Event()
        contender_started = Event()
        statements: list[str] = []

        def hold_staged_parts() -> int:
            staged.wait()
            if not release.wait(timeout=5):
                raise TimeoutError("test did not release staged writer")
            return 0

        def trace_contender(sql: str) -> None:
            statements.append(sql)
            if sql.startswith("BEGIN"):
                contender_started.set()

        first.connection.create_function("hold_staged_parts", 0, hold_staged_parts)
        first.connection.execute(
            "CREATE TEMP TRIGGER hold_parts AFTER INSERT ON job_payload_signatures "
            "BEGIN SELECT hold_staged_parts(); END"
        )
        second.connection.set_trace_callback(trace_contender)
        original = _job("winner")
        contender = _job("loser", job_id="job-2")
        before = _durable_state(path)
        with ThreadPoolExecutor(max_workers=2) as pool:
            winner = pool.submit(first.create_job, original)
            try:
                staged.wait()
                assert _durable_state(path) == before
                replay = pool.submit(second.create_job, contender)
                assert contender_started.wait(timeout=5)
            finally:
                release.set()
            assert winner.result(timeout=5) == (original, True)
            assert replay.result(timeout=5) == (original, False)
        assert not first.connection.in_transaction
        assert not second.connection.in_transaction
        assert statements[0] == "BEGIN IMMEDIATE"
        assert [sql for sql in statements if sql.startswith(("BEGIN", "COMMIT", "ROLLBACK"))] == [
            "BEGIN IMMEDIATE",
            "COMMIT",
        ]
        state = _durable_state(path)
        assert {name: len(rows) for name, rows in state.items()} == {
            "jobs": 1,
            "flows": 1,
            "signatures": 1,
            "ledger": 1,
        }
        assert state["ledger"] == [("same-key", original["id"])]
        with closing(SQLiteRepository(str(path))) as reopened:
            assert reopened.get_job(original["id"]) == original
            assert reopened.get_job(contender["id"]) is None
