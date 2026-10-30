"""Shared-connection ownership regressions: no PostgreSQL server or model execution.

The PG fake models driver transaction status; SQL/custody use real SQLite
only where durable admission is explicitly exercised. No service lifecycle.
Run with sanitized environment, PYTHONDONTWRITEBYTECODE=1 and -p no:cacheprovider.
"""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event, RLock, current_thread

import psycopg
import pytest
from psycopg.pq import TransactionStatus as TS

from c2hunter_controller import _baseline_storage as baseline
from c2hunter_controller import historical_ai_sql as sql
from c2hunter_controller.production import PostgresRepository
from tests.test_historical_ai_storage_postgres import InitializerConnection


class Cursor:
    def __init__(self, connection):
        self.connection = connection
        self.query = ""
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def execute(self, query, parameters=()):
        self.query = query
        self.connection.execute(query, parameters)
        return self

    def fetchone(self):
        rows = self.fetchall()
        return rows[0] if rows else None

    def fetchall(self):
        self.connection.observe("fetch", self.query)
        if self.query == "SELECT 1":
            return [(1,)]
        for query, rows in self.connection.rows.items():
            if query in self.query:
                return rows
        return []


class StatefulConnection(InitializerConnection):
    """Extend existing repo driver model with cursor-local results and barriers."""

    def __init__(self):
        super().__init__()
        self.pause_on = None
        self.entered = Event()
        self.release = Event()
        self.failure_on = None
        self.rows = {}
        self.observe = lambda phase, query: None

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.observe("commit", "")
        super().commit()

    def execute(self, statement, parameters=()):
        if self.info.transaction_status == TS.INERROR:
            self.queries.append(statement)
            raise psycopg.errors.InFailedSqlTransaction("synthetic aborted transaction")
        super().execute(statement, parameters)
        self.observe("execute", statement)
        if self.failure_on and self.failure_on in statement:
            self.info.transaction_status = TS.INERROR
            raise psycopg.OperationalError("synthetic driver failure")
        if self.pause_on and self.pause_on in statement:
            self.pause_on = None
            self.entered.set()
            assert self.release.wait(5), "probe barrier was not released"


@pytest.fixture
def pg(monkeypatch):
    repo = PostgresRepository("postgresql://never-connect.invalid/unit", object())
    connection = StatefulConnection()
    repo._connection = connection
    # Driver model is not a PostgreSQL catalog. Retain actual RunSQL, guard,
    # transaction and repository methods; bypass only PG catalog validation.
    monkeypatch.setattr(sql, "postgres_schema", lambda *a, **k: None)
    from c2hunter_controller import postgres_schema

    monkeypatch.setattr(postgres_schema, "require_ready", lambda cursor: cursor.execute("SELECT 1"))
    yield repo, connection
    connection.release.set()
    repo.close()


def test_readiness_success_leaves_idle_and_historical_reader_usable(pg):
    repo, conn = pg
    assert repo.database_ready() is True
    # This reaches the exact deployed line rather than merely checking a flag.
    assert repo.get_ai_run("missing") is None
    assert conn.info.transaction_status == TS.IDLE


def test_readiness_failure_leaves_idle_and_historical_reader_usable(pg):
    repo, conn = pg
    conn.failure_on = "SELECT 1"
    assert repo.database_ready() is False
    conn.failure_on = None
    assert repo.get_ai_run("missing") is None
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize(
    "legacy,query",
    [
        ("get_job_summary", "SELECT data FROM controller_objects"),
        ("list_sensors", "SELECT data FROM controller_objects"),
        ("append_audit_event", "INSERT INTO audit_events"),
    ],
)
def test_legacy_owner_cannot_expose_intrans_to_historical_reader(pg, legacy, query):
    repo, conn = pg
    conn.pause_on = query
    reader_attempt = Event()
    original_context = repo._historical_connection
    reader_thread = [None]

    class ObservedLock:
        def __init__(self):
            self.lock = RLock()

        def __enter__(self):
            if current_thread() is reader_thread[0]:
                if not self.lock.acquire(blocking=False):
                    reader_attempt.set()  # Correct owner fence actually blocked us.
                    self.lock.acquire()
            else:
                self.lock.acquire()
            return self

        def __exit__(self, *_):
            self.lock.release()

    repo._lock = ObservedLock()

    @contextmanager
    def observed_context():
        reader_thread[0] = current_thread()
        try:
            with original_context() as connection:
                yield connection
        finally:
            reader_attempt.set()  # Broken owner: guard already ran before release.

    repo._historical_connection = observed_context

    def legacy_call():
        if legacy == "append_audit_event":
            return repo.append_audit_event("probe", "owned", {})
        if legacy == "list_sensors":
            return repo.list_sensors()
        return repo.get_job_summary("missing")

    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(legacy_call)
        try:
            assert conn.entered.wait(5)
            reader = pool.submit(repo.get_ai_run, "missing")
            assert reader_attempt.wait(5)
            # Release once the historical operation has attempted its lock or
            # finished, not after an arbitrary sleep. A corrected owner blocks
            # it until commit; the broken owner returns BASELINE_BUSY already.
            conn.release.set()
            owner.result(timeout=5)
            assert reader.result(timeout=5) is None
        finally:
            conn.release.set()
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize("status", [TS.INTRANS, TS.INERROR])
def test_readiness_does_not_join_or_finish_caller_owned_work(pg, status):
    repo, conn = pg
    conn.info.transaction_status = status
    before_events, before_queries = list(conn.events), list(conn.queries)
    assert repo.database_ready() is False
    assert conn.info.transaction_status == status
    assert conn.events == before_events
    assert conn.queries == before_queries


@pytest.mark.parametrize(
    "legacy,query",
    [
        ("get_job_summary", "SELECT data FROM controller_objects"),
        ("list_sensors", "SELECT data FROM controller_objects"),
        ("append_audit_event", "INSERT INTO audit_events"),
    ],
)
def test_failed_legacy_owner_rolls_back_its_own_work(pg, legacy, query):
    repo, conn = pg
    conn.failure_on = query
    with pytest.raises(psycopg.OperationalError, match="synthetic driver failure"):
        if legacy == "append_audit_event":
            repo.append_audit_event("probe", "owned", {})
        elif legacy == "list_sensors":
            repo.list_sensors()
        else:
            repo.get_job_summary("missing")
    conn.failure_on = None
    assert repo.get_ai_run("missing") is None
    assert conn.info.transaction_status == TS.IDLE


def test_completed_legacy_operation_restores_later_reads(pg):
    repo, conn = pg
    assert repo.get_job_summary("missing") is None
    assert repo.get_ai_run("missing") is None
    assert conn.info.transaction_status == TS.IDLE


def test_caller_owned_transaction_guard_is_preserved(pg):
    repo, conn = pg
    conn.info.transaction_status = TS.INTRANS
    before = list(conn.events)
    with pytest.raises(baseline.BaselineStorageError, match="^BASELINE_BUSY$"):
        repo.get_ai_run("missing")
    assert conn.events == before
    assert conn.info.transaction_status == TS.INTRANS


def test_busy_is_not_permission_context(pg):
    from c2hunter_controller.historical_ai_access import public_ai_access

    repo, conn = pg
    conn.execute("SELECT 1")
    for role in (None, 1, 2, 3):
        with public_ai_access(role):
            with pytest.raises(baseline.BaselineStorageError, match="^BASELINE_BUSY$"):
                repo.get_ai_run("missing")
    assert conn.info.transaction_status == TS.INTRANS


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/ai-runs/missing",
        "/api/v1/analysis-jobs/missing/ai-runs",
        "/api/v1/ai-runs/missing/selection",
        "/api/v1/ai-runs/missing/assessments",
        "/api/v1/ai-assessments/missing",
        "/api/v1/ai-assessments/missing/feedback",
        "/api/v1/ai-assessments/missing/evidence-bundle",
        "/api/v1/ai-assessments/missing/artifacts",
        "/api/v1/ai-artifacts/missing",
        "/api/v1/ai-runs/missing/baseline-comparisons",
        "/api/v1/ai-runs/missing/baseline-sources",
    ],
)
def test_all_saved_ai_read_routes_map_storage_busy(pg, monkeypatch, path):
    from fastapi.testclient import TestClient

    from c2hunter_controller.app import create_app
    from c2hunter_controller.repositories import MemoryRepository
    from tests.test_baseline_http_routes import headers, settings

    pg_repo, conn = pg
    repo = MemoryRepository()
    app = create_app(settings(), repo)
    for method in ("get_ai_run", "list_ai_runs", "get_ai_assessment", "get_ai_artifact"):
        monkeypatch.setattr(repo, method, getattr(pg_repo, method))
    conn.execute("SELECT 1")  # Explicit caller-owned work: independent of readiness repair.
    assert conn.info.transaction_status == TS.INTRANS
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get(path, headers=headers("analyst"))
        assert response.status_code == 503, (path, response.status_code, response.text)
        assert response.json()["error"]["code"] == "BASELINE_BUSY"
        assert conn.info.transaction_status == TS.INTRANS  # Must not borrow/rollback it.
    finally:
        repo.close()


def test_post_response_stays_successful_after_durable_admission(pg, monkeypatch, tmp_path):
    """Real ASGI+SQLite commit+queue, PG driver-boundary response reread.

    Mixed-backend seam probe, NOT real PostgreSQL acceptance. The queue hook
    injects an ordinary production readiness call between enqueue and reread.
    It never runs a worker or a gateway completion.
    """
    from c2hunter_controller.repositories import SQLiteRepository
    from tests.test_baseline_http_routes import headers
    from tests.test_historical_ai_api import api
    from tests.test_historical_ai_storage import prepared

    pg_repo, conn = pg
    path = tmp_path / "admission.db"
    repo = SQLiteRepository(path)
    request, _, _ = prepared(repo)
    client, queue = api(repo)
    real_get = repo.get_ai_run
    real_enqueue = queue.ensure_enqueued

    def response_read(run_id):
        # Actual PG wrapper reaches its idle guard before any SQL. If a future
        # correction makes that read legal, keep projection tied to real SQLite.
        pg_repo.get_ai_run(run_id)
        return real_get(run_id)

    def enqueue_then_ready(run_id):
        real_enqueue(run_id)
        assert pg_repo.database_ready()
        monkeypatch.setattr(repo, "get_ai_run", response_read)

    monkeypatch.setattr(queue, "ensure_enqueued", enqueue_then_ready)
    try:
        response = client.post(
            f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
            json=request.payload.to_mapping(),
            headers=headers("analyst"),
        )
        # Durable observer opens no repository and causes no schema migration.
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as observer:
            rows = observer.execute(
                "SELECT run_id,idempotency_key,historical_owner_version FROM ai_analysis_runs"
            ).fetchall()
        assert len(rows) == 1
        assert rows[0][1] == request.payload.idempotency_key
        assert rows[0][2] == "historical-ai-owner-v1"
        assert queue.run_ids == [rows[0][0]]
        assert not repo.connection.in_transaction
        assert response.status_code == 201, (
            f"durable rows={len(rows)}, queued={queue.depth()}, "
            f"HTTP={response.status_code} {response.text}"
        )
    finally:
        client.close()
        repo.close()
