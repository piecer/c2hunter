"""Actual SQL insert/commit/readback faults and caller custody."""

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import _baseline_storage as bs
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


def test_memory_staging_error_keeps_original_state(monkeypatch: Any) -> None:
    from c2hunter_controller.repositories import MemoryRepository

    repo = MemoryRepository()
    before = repo._baseline_scopes
    error = RuntimeError("owned serialization fault")
    fired = []
    original = bs.h.canonical_json
    cfg = config()

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        fired.append(True)
        raise error

    with monkeypatch.context() as guard:
        guard.setattr(bs.h, "canonical_json", fail)
        with pytest.raises(RuntimeError) as caught:
            repo.create_baseline_scope(cfg, "admin", START)
    assert caught.value is error and fired
    assert repo._baseline_scopes is before and before == {}
    assert bs.h.canonical_json is original
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(repo.create_baseline_scope, config(), "admin", START).result(10)[1]
    receipt({"backend": "memory", "fault": "serialization", "fired": len(fired)})


@pytest.mark.parametrize("operation", ["create", "get", "page", "preview"])
def test_public_operations_refuse_autocommit(scope_repo: Any, operation: str) -> None:
    repo = scope_repo
    if hasattr(repo, "jobs"):
        pytest.skip("SQL transaction ownership")
    repo.create_baseline_scope(config(), "admin", START)
    con = repo.connection
    con.autocommit = True
    try:
        with pytest.raises(ValueError, match="^BASELINE_BUSY$"):
            if operation == "create":
                repo.create_baseline_scope(config(), "admin", START)
            elif operation == "get":
                repo.get_baseline_scope(config().scope_id)
            elif operation == "page":
                repo.page_baseline_scopes()
            else:
                repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
        assert con.autocommit is True
    finally:
        con.autocommit = (
            False if hasattr(repo, "database_url") else sqlite3.LEGACY_TRANSACTION_CONTROL
        )


def receipt(value: dict) -> None:
    """Append optional JSONL only to C2HUNTER_TEST_RECEIPT_PATH; no default output."""
    output = os.environ.get("C2HUNTER_TEST_RECEIPT_PATH")
    if not output:
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def observer(repo: Any) -> Any:
    if hasattr(repo, "database_url"):
        import psycopg

        return psycopg.connect(repo.database_url, autocommit=True)
    return sqlite3.connect("file:" + repo._path + "?mode=ro", uri=True)


@pytest.mark.parametrize("fault", ["insert", "commit", "readback"])
def test_real_create_faults_atomic_and_retryable(
    scope_repo: Any, monkeypatch: Any, fault: str
) -> None:
    repo = scope_repo
    if hasattr(repo, "jobs"):
        pytest.skip("SQL fault mechanism; Memory staging tested separately")
    con = repo.connection
    pg = hasattr(repo, "database_url")
    fired = []
    if fault == "readback":
        original = bs._SQL.execute
        selects = []

        def failing(self: Any, statement: str, values: tuple = ()) -> Any:
            if statement.startswith("SELECT config_json,"):
                selects.append(statement)
                if len(selects) == 2:
                    fired.append("postcommit-readback")
                    return original(self, "SELECT * FROM nonexistent_scope_readback_fault")
            return original(self, statement, values)

        monkeypatch.setattr(bs._SQL, "execute", failing)
    elif pg:
        con.execute("CREATE SEQUENCE scope_fault_fired")
        con.execute(
            "CREATE FUNCTION scope_fault() RETURNS trigger LANGUAGE plpgsql AS"
            " $$ BEGIN PERFORM nextval('scope_fault_fired'); RAISE EXCEPTION "
            "'owned create fault'; END $$"
        )
        con.execute(
            "CREATE "
            + ("CONSTRAINT " if fault == "commit" else "")
            + "TRIGGER scope_fail AFTER INSERT ON baseline_scopes "
            + ("DEFERRABLE INITIALLY DEFERRED " if fault == "commit" else "")
            + "FOR EACH ROW EXECUTE FUNCTION scope_fault()"
        )
        con.commit()
    else:
        con.create_function("scope_fired", 0, lambda: fired.append(fault) or 1)
        if fault == "commit":
            con.execute("CREATE TABLE scope_fault_parent(id INTEGER PRIMARY KEY)")
            con.execute(
                "CREATE TABLE scope_fault_child(id INTEGER REFERENCES "
                "scope_fault_parent(id) DEFERRABLE INITIALLY DEFERRED)"
            )
            action = "INSERT INTO scope_fault_child VALUES(1);"
        else:
            action = "SELECT RAISE(ABORT,'owned create fault');"
        con.executescript(
            "CREATE TEMP TRIGGER scope_fail AFTER INSERT ON baseline_scopes "
            "BEGIN SELECT scope_fired(); " + action + " END;"
        )
    with pytest.raises(ValueError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.create_baseline_scope(config(), "admin", START)
    # Raw independent visibility before any rescue, reopen or writer rollback.
    with observer(repo) as raw:
        count = raw.execute("SELECT count(*) FROM baseline_scopes").fetchone()[0]
        assert count == (1 if fault == "readback" else 0)
        if pg and fault != "readback":
            value, called = raw.execute(
                "SELECT last_value,is_called FROM scope_fault_fired"
            ).fetchone()
            assert called and value == 1
            fired.append(fault)
    assert len(fired) == 1
    assert (con.info.transaction_status.name == "IDLE") if pg else not con.in_transaction
    receipt(
        {
            "backend": "postgres" if pg else "sqlite",
            "fault": fault,
            "fired": len(fired),
            "durable_count": count,
            "idle": True,
        }
    )
    if fault == "readback":
        monkeypatch.setattr(bs._SQL, "execute", original)
    elif pg:
        con.execute("DROP TRIGGER scope_fail ON baseline_scopes")
        con.commit()
    else:
        con.execute("DROP TRIGGER scope_fail")
        con.commit()
    with ThreadPoolExecutor(max_workers=1) as pool:
        view, created = pool.submit(repo.create_baseline_scope, config(), "admin", START).result(
            timeout=10
        )
    assert created is (fault != "readback")
    assert repo.get_baseline_scope(config().scope_id) == view


@pytest.mark.parametrize("operation", ["create", "get", "page", "preview"])
def test_public_operations_refuse_foreign_transaction(scope_repo: Any, operation: str) -> None:
    repo = scope_repo
    if hasattr(repo, "jobs"):
        pytest.skip("SQL transaction custody")
    repo.create_baseline_scope(config(), "admin", START)
    repo.save_job(stored())
    con = repo.connection
    con.execute("CREATE TEMP TABLE scope_caller_sentinel(value INTEGER)")
    con.commit()
    con.execute("BEGIN")
    con.execute("INSERT INTO scope_caller_sentinel VALUES(17)")
    try:
        with pytest.raises(ValueError, match="^BASELINE_BUSY$"):
            if operation == "create":
                repo.create_baseline_scope(config(), "admin", START)
            elif operation == "get":
                repo.get_baseline_scope(config().scope_id)
            elif operation == "page":
                repo.page_baseline_scopes()
            else:
                repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
        assert con.execute("SELECT value FROM scope_caller_sentinel").fetchone()[0] == 17
        assert (
            con.info.transaction_status.name == "INTRANS"
            if hasattr(repo, "database_url")
            else con.in_transaction
        )
    finally:
        con.rollback()
    assert con.execute("SELECT count(*) FROM scope_caller_sentinel").fetchone()[0] == 0
    con.rollback()
