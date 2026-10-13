"""Real PostgreSQL lexical discovery, RC isolation, and lock timeout."""

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_read as r
from tests import test_baseline_approval_contract as fixtures
from tests.test_historical_read_races import pg_blocked
from tests.test_historical_source import START, config, stored

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


def test_pg_parent_change_no_chase(pg_repo: Any, monkeypatch: Any) -> None:
    import psycopg

    repo = pg_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    repo.save_job(dict(stored(), id="new-parent"))
    original = r._pg_metadata
    calls = []
    with psycopg.connect(repo.database_url, autocommit=True) as writer:

        def swap(cursor: Any, key: str) -> Any:
            value = original(cursor, key)
            calls.append(key)
            if len(calls) == 1:
                writer.execute(
                    "UPDATE controller_objects SET data=jsonb_set(data,"
                    "'{parent_job_id}','\"new-parent\"') WHERE kind='job' AND "
                    "id=%s",
                    (request.source_job_id,),
                )
            return value

        monkeypatch.setattr(r, "_pg_metadata", swap)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_SOURCE_CHANGED$"):
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert calls == [request.source_job_id, request.source_job_id]
    assert repo.get_baseline_scope(config().scope_id).control_revision == 0
    assert repo.connection.info.transaction_status.name == "IDLE"


def test_pg_explicit_rc_over_session_default(pg_repo: Any, monkeypatch: Any) -> None:
    repo = pg_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    repo.connection.execute(
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE"
    )
    repo.connection.commit()
    original = r._postgres_acquire
    observed = []

    def acquire(cursor: Any, *args: Any, **kw: Any) -> Any:
        cursor.execute("SHOW transaction_isolation")
        observed.append(cursor.fetchone()[0])
        cursor.execute("SHOW lock_timeout")
        observed.append(cursor.fetchone()[0])
        return original(cursor, *args, **kw)

    monkeypatch.setattr(r, "_postgres_acquire", acquire)
    result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert result.created and observed == ["read committed", "5s"]


@pytest.mark.parametrize("lock", ["source", "scope"])
def test_pg_real_lock_timeout(pg_repo: Any, lock: str) -> None:
    import psycopg

    repo = pg_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    pid = repo.connection.info.backend_pid
    with (
        psycopg.connect(repo.database_url) as holder,
        psycopg.connect(repo.database_url, autocommit=True) as observer,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        if lock == "source":
            holder.execute(
                "SELECT id FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                (request.source_job_id,),
            )
        else:
            holder.execute(
                "SELECT scope_id FROM baseline_scopes WHERE scope_id=%s FOR UPDATE",
                (config().scope_id,),
            )
        future = pool.submit(
            repo.publish_baseline_source, config().scope_id, request, "reviewer", START
        )
        pg_blocked(observer, pid, future)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
            future.result(15)
        holder.rollback()
    assert repo.connection.info.transaction_status.name == "IDLE"
    assert repo.publish_baseline_source(config().scope_id, request, "reviewer", START).created


def test_sqlite_real_lock_timeout(tmp_path: Any) -> None:
    from c2hunter_controller.repositories import SQLiteRepository

    with closing(SQLiteRepository(tmp_path / "busy.sqlite")) as repo:
        repo.create_baseline_scope(config(), "admin", START)
        request = fixtures.prepare(repo)
        observed = threading.Event()
        repo.connection.set_trace_callback(
            lambda sql: observed.set() if sql == "BEGIN IMMEDIATE" else None
        )
        with (
            closing(sqlite3.connect(repo._path)) as holder,
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            holder.execute("BEGIN IMMEDIATE")
            future = pool.submit(
                repo.publish_baseline_source, config().scope_id, request, "reviewer", START
            )
            assert observed.wait(10)
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
                future.result(15)
            holder.rollback()
        assert not repo.connection.in_transaction
        assert repo.publish_baseline_source(config().scope_id, request, "reviewer", START).created


@pytest.mark.parametrize("rollback", [False, True])
def test_pg_source_mutation_coherent(pg_repo: Any, rollback: bool) -> None:
    import psycopg

    repo = pg_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    pid = repo.connection.info.backend_pid
    with (
        psycopg.connect(repo.database_url) as writer,
        psycopg.connect(repo.database_url, autocommit=True) as observer,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        writer.execute(
            "SELECT id FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
            (request.source_job_id,),
        )
        writer.execute(
            "UPDATE job_flow_record_chunks SET data=jsonb_set(data,'{0,"
            "total_bytes}','200') WHERE job_id=%s",
            (request.source_job_id,),
        )
        future = pool.submit(
            repo.publish_baseline_source, config().scope_id, request, "reviewer", START
        )
        pg_blocked(observer, pid, future)
        writer.rollback() if rollback else writer.commit()
        if rollback:
            assert future.result(15).created
        else:
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_SOURCE_CHANGED$"):
                future.result(15)
    assert repo.get_baseline_scope(config().scope_id).control_revision == int(rollback)


def test_pg_operation_ddl_failure(pg_repo: Any, monkeypatch: Any) -> None:
    from uuid import uuid4

    import psycopg
    from psycopg import sql

    from c2hunter_controller.production import PostgresRepository

    repo = pg_repo
    repo.create_baseline_scope(config(), "admin", START)
    repo.save_job(stored())
    schema = repo.connection.execute("SELECT current_schema()").fetchone()[0]
    repo.connection.execute("DROP TABLE baseline_operations")
    repo.connection.commit()
    trigger = "approval_ddl_" + uuid4().hex
    with psycopg.connect(repo.database_url, autocommit=True) as admin:
        admin.execute("CREATE SEQUENCE approval_ddl_fired")
        admin.execute(
            sql.SQL(
                "CREATE FUNCTION approval_ddl_fault() RETURNS event_trigger "
                "LANGUAGE plpgsql AS $$ BEGIN IF EXISTS (SELECT 1 FROM "
                "pg_event_trigger_ddl_commands() WHERE object_identity={}) "
                "THEN PERFORM nextval('approval_ddl_fired'); RAISE EXCEPTION "
                "'owned operations DDL fault'; END IF; END $$"
            ).format(sql.Literal(schema + ".baseline_operations"))
        )
        admin.execute(
            sql.SQL(
                "CREATE EVENT TRIGGER {} ON ddl_command_end EXECUTE FUNCTION approval_ddl_fault()"
            ).format(sql.Identifier(trigger))
        )
        actual = psycopg.connect
        observed = []

        def connect(*args: Any, **kw: Any) -> Any:
            connection = actual(*args, **kw)
            observed.append(connection)
            return connection

        try:
            with monkeypatch.context() as guard:
                guard.setattr(psycopg, "connect", connect)
                failed = PostgresRepository(repo.database_url, None)
                with pytest.raises(psycopg.errors.RaiseException):
                    _ = failed.connection
                assert len(observed) == 1 and observed[0].closed
            assert admin.execute(
                "SELECT last_value,is_called FROM approval_ddl_fired"
            ).fetchone() == (1, True)
            assert admin.execute("SELECT control_revision FROM baseline_scopes").fetchone() == (0,)
            assert admin.execute("SELECT to_regclass('baseline_operations')").fetchone() == (None,)
        finally:
            admin.execute(sql.SQL("DROP EVENT TRIGGER {}").format(sql.Identifier(trigger)))
    with closing(PostgresRepository(repo.database_url, None)) as reopened:
        assert reopened.get_baseline_scope(config().scope_id).control_revision == 0
        assert reopened.get_job("root")["id"] == "root"
        assert reopened.connection.execute(
            "SELECT count(*) FROM baseline_operations"
        ).fetchone() == (0,)
        reopened.connection.rollback()
