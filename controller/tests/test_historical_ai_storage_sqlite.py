"""Real SQLite files and independent durable observers; no services."""

import sqlite3

import pytest

from c2hunter_controller import historical_ai_storage as custody
from c2hunter_controller.historical_ai_builder import (
    build_historical_target_snapshot,
)
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_historical_ai_storage import advance, prepared


def test_sqlite_admission_lifecycle_and_reopen(tmp_path):
    path = tmp_path / "runs.db"
    repo = SQLiteRepository(path)
    request, _, _ = prepared(repo)
    before = repo.get_job(request.analysis_job_id)
    run, created = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    assert created and custody.materialize_historical_run(run)[1]
    assert repo.get_ai_run_by_request(request.analysis_job_id, "request-1") == run
    saved = repo.save_ai_run(advance(run, "PREPARING", 10))
    assert saved["_historical_admission"] == run["_historical_admission"]
    assert repo.get_job(request.analysis_job_id) == before
    repo.close()
    reopened = SQLiteRepository(path)
    assert reopened.get_ai_run(run["id"]) == saved
    assert reopened.list_ai_runs(request.analysis_job_id) == [saved]
    replay, created = reopened.admit_historical_ai_run(request, lambda *_: pytest.fail("rebuilt"))
    assert not created and replay == saved
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as observer:
        text, original_request, original_snapshot = observer.execute(
            "SELECT data,historical_request_json,historical_snapshot_json FROM ai_analysis_runs"
        ).fetchone()
        assert "_historical_admission" not in text and "candidate_snapshots" not in text
        assert original_request == run["_historical_admission"]["request_canonical_json"]
        assert original_snapshot == run["_historical_admission"]["snapshot_canonical_json"]
    reopened.close()


@pytest.mark.parametrize("fault", ["insert", "update", "commit"])
def test_sqlite_real_fault_rolls_back_and_writer_is_reusable(tmp_path, fault):
    path = tmp_path / "fault.db"
    repo = SQLiteRepository(path)
    request, _, _ = prepared(repo)
    prior = None
    if fault == "update":
        prior, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    if fault == "commit":
        repo.connection.execute("CREATE TABLE fault_parent(id TEXT PRIMARY KEY)")
        repo.connection.execute(
            "CREATE TABLE fault_child(id TEXT REFERENCES fault_parent(id) "
            "DEFERRABLE INITIALLY DEFERRED)"
        )
        body = "INSERT INTO fault_child VALUES(NEW.run_id);"
        event = "INSERT"
    else:
        body = "SELECT RAISE(ABORT,'injected real write fault');"
        event = fault.upper()
    repo.connection.execute(
        f"CREATE TEMP TRIGGER injected AFTER {event} ON ai_analysis_runs BEGIN {body} END"
    )
    trace = []
    repo.connection.set_trace_callback(trace.append)
    with pytest.raises(ValueError, match="BASELINE_STORAGE_UNAVAILABLE"):
        if prior:
            repo.save_ai_run(advance(prior, "PREPARING", 10))
        else:
            repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    assert any(
        event + " INTO ai_analysis_runs" in sql or "UPDATE ai_analysis_runs SET data" in sql
        for sql in trace
    )
    if fault == "commit":
        assert "COMMIT" in trace  # Actual deferred-FK COMMIT refusal, not a mock.
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as observer:
        rows = observer.execute("SELECT data FROM ai_analysis_runs").fetchall()
        assert len(rows) == (1 if prior else 0)
        if prior:
            import json

            assert json.loads(rows[0][0])["status"] == "QUEUED"
    assert not repo.connection.in_transaction
    repo.connection.execute("DROP TRIGGER injected")
    if prior:
        assert repo.save_ai_run(advance(prior, "PREPARING", 10))["status"] == "PREPARING"
    else:
        assert repo.admit_historical_ai_run(request, build_historical_target_snapshot)[1]
    repo.close()
    reopened = SQLiteRepository(path)
    assert reopened.get_ai_run(request.run_id) is not None
    reopened.close()


def test_sqlite_owner_guards_and_semantic_failure_reopen(tmp_path):
    from datetime import UTC, datetime

    from c2hunter_controller import historical_ai_sql as sql

    path = tmp_path / "corrupt.db"
    repo = SQLiteRepository(path)
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    original = run["_historical_admission"]
    with pytest.raises(sqlite3.IntegrityError):
        repo.connection.execute("UPDATE ai_analysis_runs SET historical_request_json='replacement'")
    repo.connection.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        repo.connection.execute("UPDATE ai_analysis_runs SET historical_owner_version=NULL")
    repo.connection.rollback()
    # Fixture-only corruption bypasses immutable storage trigger, preserving the
    # original request, lengths and independent digest. Restore the exact guard.
    repo.connection.execute("DROP TRIGGER ai_runs_hist_owner_update")
    bad = original["snapshot_canonical_json"].replace(
        '"dataset_id":"dataset-3"', '"dataset_id":"dataset-4"'
    )
    assert (
        bad != original["snapshot_canonical_json"]
        and len(bad.encode()) == original["snapshot_byte_size"]
    )
    repo.connection.execute("UPDATE ai_analysis_runs SET historical_snapshot_json=?", (bad,))
    repo.connection.execute(sql.sqlite_guards()["ai_runs_hist_owner_update"])
    repo.connection.commit()
    corrupt = repo.get_ai_run(run["id"])
    saved = repo.save_ai_run(custody.safe_historical_failure(corrupt, datetime.now(UTC)))
    assert (
        saved["_historical_admission"]["expected_snapshot_sha256"]
        == original["expected_snapshot_sha256"]
    )
    repo.close()
    reopened = SQLiteRepository(path)
    assert reopened.get_ai_run(run["id"]) == saved
    with pytest.raises(ValueError, match="HISTORICAL_SNAPSHOT_INVALID"):
        custody.materialize_historical_run(saved)
    assert reopened.save_ai_run(saved) == saved
    reopened.close()


def test_sqlite_migration_and_reads_do_not_own_borrowed_transaction(tmp_path):
    from c2hunter_controller import historical_ai_sql as sql

    repo = SQLiteRepository(tmp_path / "borrowed.db")
    repo.connection.execute("CREATE TABLE sentinel(value TEXT)")
    repo.connection.execute("INSERT INTO sentinel VALUES('uncommitted')")
    for action in (
        lambda: sql.initialize_sqlite(repo.connection),
        lambda: repo.get_ai_run("absent"),
    ):
        with pytest.raises(ValueError, match="BASELINE_BUSY"):
            action()
        assert repo.connection.in_transaction
        assert repo.connection.execute("SELECT value FROM sentinel").fetchone() == ("uncommitted",)
    repo.connection.rollback()
    assert repo.connection.execute("SELECT count(*) FROM sentinel").fetchone() == (0,)
    repo.close()


def test_invalid_lifecycle_json_is_header_failure_not_semantic_failure(tmp_path):
    repo = SQLiteRepository(tmp_path / "header.db")
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    repo.connection.execute("UPDATE ai_analysis_runs SET data='{' WHERE run_id=?", (run["id"],))
    repo.connection.commit()
    with pytest.raises(ValueError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.get_ai_run(run["id"])
    repo.close()


def test_sqlite_digest_nul_suffix_is_rejected_before_storage(tmp_path):
    from c2hunter_controller import historical_ai_sql as sql

    repo = SQLiteRepository(tmp_path / "digest.db")
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    owner = run["_historical_admission"]
    values = [owner[key] for key in custody.OWNER_FIELDS]
    values[-1] += "\u0000not-hex"
    with pytest.raises(sqlite3.IntegrityError):
        repo.connection.execute(
            "INSERT INTO ai_analysis_runs(run_id,analysis_job_id,idempotency_key,created_at,data,"
            + ",".join(sql.COLUMNS)
            + ") VALUES('other','other','other','old','{}',?,?,?,?,?,?)",
            values,
        )
    repo.connection.rollback()
    repo.close()


def test_two_sqlite_admissions_have_one_builder_and_one_owner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    path = tmp_path / "race.db"
    first, second = SQLiteRepository(path), SQLiteRepository(path)
    request, _, _ = prepared(first)
    entered, release, contender = Event(), Event(), Event()
    calls = []

    def builder(*args):
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return build_historical_target_snapshot(*args)

    def trace(statement):
        if statement == "BEGIN IMMEDIATE":
            contender.set()

    second.connection.set_trace_callback(trace)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(first.admit_historical_ai_run, request, builder)
        assert entered.wait(5)
        b = pool.submit(second.admit_historical_ai_run, request, builder)
        try:
            assert contender.wait(5)
        finally:
            release.set()
        left, right = a.result(5), b.result(5)
    assert calls == [1] and left[0] == right[0]
    assert [left[1], right[1]] == [True, False]
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as observer:
        assert observer.execute("SELECT count(*) FROM ai_analysis_runs").fetchone() == (1,)
    first.close()
    second.close()


def test_terminal_winner_performs_no_update(tmp_path):
    repo = SQLiteRepository(tmp_path / "winner.db")
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    winner = repo.save_ai_run(advance(run, "CANCELLED", 0))
    trace = []
    repo.connection.set_trace_callback(trace.append)
    assert repo.save_ai_run(advance(run, "PREPARING", 10)) == winner
    assert not any(sql.startswith("UPDATE ai_analysis_runs") for sql in trace)
    repo.close()


def test_additive_migration_preserves_legacy_bytes_and_refuses_missing_guard(tmp_path):
    from c2hunter_controller import historical_ai_sql as sql

    path = tmp_path / "legacy.db"
    raw = '{ "id": "legacy", "analysis_job_id": "j", "idempotency_key": "k", "created_at": "old" }'
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE ai_analysis_runs(run_id TEXT PRIMARY KEY,"
            "analysis_job_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,"
            "created_at TEXT NOT NULL,data TEXT NOT NULL,"
            "UNIQUE(analysis_job_id,idempotency_key))"
        )
        connection.execute("INSERT INTO ai_analysis_runs VALUES('legacy','j','k','old',?)", (raw,))
    repo = SQLiteRepository(path)
    assert repo.get_ai_run("legacy")["created_at"] == "old"
    with sqlite3.connect(path) as observer:
        assert observer.execute("SELECT data FROM ai_analysis_runs").fetchone() == (raw,)
        assert observer.execute(
            "SELECT historical_owner_version FROM ai_analysis_runs"
        ).fetchone() == (None,)
    trace = []
    repo.connection.set_trace_callback(trace.append)
    sql.initialize_sqlite(repo.connection)
    assert not any(s.startswith(("ALTER", "CREATE", "UPDATE")) for s in trace)
    repo.connection.execute("DROP TRIGGER ai_runs_hist_owner_update")
    with pytest.raises(ValueError, match="BASELINE_STORAGE_UNAVAILABLE"):
        sql.initialize_sqlite(repo.connection)
    assert repo.connection.execute(
        "SELECT count(*) FROM sqlite_schema WHERE name='ai_runs_hist_owner_update'"
    ).fetchone() == (0,)
    assert not repo.connection.in_transaction
    repo.close()
