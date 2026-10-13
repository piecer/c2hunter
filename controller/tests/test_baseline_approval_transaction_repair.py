"""Regression gates for definite SQLite refusal and committed SQL validation."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_baseline_approval_contract import pg_repo, prepare  # noqa: F401
from tests.test_historical_source import START, config


@pytest.fixture(params=["sqlite", "postgres"])
def sql_repo(request: Any, tmp_path: Any) -> Any:
    if request.param == "postgres":
        return request.getfixturevalue("pg_repo")
    repo = SQLiteRepository(tmp_path / "repair.sqlite")
    request.addfinalizer(repo.close)
    return repo


@contextmanager
def independent(repo: Any) -> Any:
    if isinstance(repo, SQLiteRepository):
        con = sqlite3.connect(repo._path, isolation_level=None)
    else:
        import psycopg

        con = psycopg.connect(repo.database_url, autocommit=True)
    try:
        yield con
    finally:
        con.close()


def test_actual_commit_busy_healthy_rollback_reuse(tmp_path: Any, monkeypatch: Any) -> None:
    repo = SQLiteRepository(tmp_path / "busy.sqlite")
    reader = sqlite3.connect(repo._path)
    try:
        repo.create_baseline_scope(config(), "admin", START)
        request = prepare(repo)
        execute = bs._SQL.execute
        before = reader.execute("SELECT * FROM baseline_scopes").fetchall()
        assert repo.connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert repo.connection.execute("PRAGMA busy_timeout").fetchone() == (5000,)
        fired = []

        def boundary(db: Any, statement: str, values: Any = ()) -> Any:
            cursor = execute(db, statement, values)
            if statement.startswith(
                "SELECT revision FROM baseline_operations WHERE scope_id=? ORDER "
            ):
                reader.execute("BEGIN")
                assert reader.execute("SELECT * FROM baseline_scopes").fetchall() == before
                fired.append(True)
            return cursor

        with monkeypatch.context() as patch:
            patch.setattr(bs._SQL, "execute", boundary)
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert fired == [True]
        reader.rollback()
        assert reader.execute("SELECT * FROM baseline_scopes").fetchall() == before
        assert reader.execute("SELECT count(*) FROM baseline_operations").fetchone() == (0,)
        assert reader.execute("SELECT count(*) FROM baseline_generations").fetchone() == (0,)
        assert not repo.connection.in_transaction
        assert not repo._baseline_publication_connection.failed
        reopened = SQLiteRepository(repo._path)
        try:
            assert reopened.get_baseline_scope(config().scope_id).control_revision == 0
        finally:
            reopened.close()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(
                repo.publish_baseline_source, config().scope_id, request, "reviewer", START
            ).result(30)
        assert result.created is True
    finally:
        reader.close()
        repo.close()


def test_postcommit_digest_mismatch_is_storage_error(sql_repo: Any, monkeypatch: Any) -> None:
    repo = sql_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = prepare(repo)
    actual = bs._publication_transaction.__exit__
    observed: list[Any] = []

    def boundary(owner: Any, kind: Any, error: Any, traceback: Any) -> Any:
        result = actual(owner, kind, error, traceback)
        if owner.write and error is None:
            with independent(repo) as con:
                row = con.execute(
                    "SELECT revision,request_sha256,receipt_json FROM baseline_operations"
                ).fetchone()
                assert row[0] == 1
                assert con.execute("SELECT control_revision FROM baseline_scopes").fetchone() == (
                    1,
                )
                observed.append(row[2])
                bad = "0" * 64 if row[1] != "0" * 64 else "1" * 64
                placeholder = "?" if isinstance(repo, SQLiteRepository) else "%s"
                con.execute(
                    "UPDATE baseline_operations SET request_sha256=" + placeholder,
                    (bad,),
                )
        return result

    monkeypatch.setattr(bs._publication_transaction, "__exit__", boundary)
    with pytest.raises(bs.BaselineStorageError) as caught:
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    with independent(repo) as con:
        assert con.execute("SELECT control_revision FROM baseline_scopes").fetchone() == (1,)
        assert con.execute("SELECT count(*) FROM baseline_operations").fetchone() == (1,)
        assert con.execute("SELECT receipt_json FROM baseline_operations").fetchone() == (
            observed[0],
        )
    assert len(observed) == 1
    if isinstance(repo, SQLiteRepository):
        assert not repo.connection.in_transaction
    else:
        assert repo.connection.info.transaction_status.name == "IDLE"
    assert caught.value.code == "BASELINE_STORAGE_UNAVAILABLE"
