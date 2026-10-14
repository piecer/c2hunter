"""Independent offline driver-contract probes. Expected outcomes are acceptance,
not characterization; unresolved product failures intentionally remain RED.
No implementer fixtures, external engine, network, service, or model is used.
"""

from contextlib import contextmanager
from datetime import UTC, datetime
from threading import Event, RLock, Thread, current_thread
from types import SimpleNamespace

import psycopg
import pytest
from psycopg.pq import TransactionStatus as TS

from c2hunter_controller import _baseline_storage as baseline
from c2hunter_controller import historical_ai_sql
from c2hunter_controller.historical_ai_http import transport_error
from c2hunter_controller.production import PostgresRepository


class Cursor:
    def __init__(self, connection):
        self.connection = connection
        self.rowcount = 1
        self.query = ""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, parameters=()):
        c = self.connection
        self.query = query
        c.queries.append(query)
        if c.info.transaction_status == TS.INERROR:
            raise psycopg.errors.InFailedSqlTransaction("probe aborted transaction")
        c.info.transaction_status = TS.INTRANS
        self.rowcount = c.delete_rows if query.startswith("DELETE") else 1
        if c.fail_query and c.fail_query in query:
            c.failure_fired += 1
            c.info.transaction_status = TS.INERROR
            raise c.primary
        return self

    def fetchall(self):
        q = self.query
        if q == "SELECT 1":
            return [(1,)]
        if q.startswith("INSERT INTO job_idempotency"):
            return [("job-review",)]
        if "kind='enrollment'" in q and q.startswith("SELECT"):
            return [("enrollment-review", {"expires_at": "2099-01-01T00:00:00+00:00"})]
        if "kind='sensor'" in q and q.startswith("SELECT"):
            return [({"sensor_id": "sensor-review", "config_version": 1},)]
        return []

    def fetchone(self):
        rows = self.fetchall()
        return rows[0] if rows else None


class Driver:
    """Small independent psycopg-shaped state machine, not a SQL engine.

    Successful ordinary statements begin a transaction even when rowcount=0.
    A statement failure aborts it; exiting a cursor doesn't finish a transaction.
    Only commit/rollback or a successful connection.transaction exit does so.
    """

    def __init__(self):
        self.info = SimpleNamespace(transaction_status=TS.IDLE)
        self.autocommit = False
        self.closed = False
        self.queries = []
        self.events = []
        self.delete_rows = 1
        self.fail_query = None
        self.failure_fired = 0
        self.primary = psycopg.errors.CheckViolation("synthetic primary statement failure")
        self.rollback_error = None
        self.observe = lambda phase: None

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.observe("commit")
        self.events.append("commit")
        self.info.transaction_status = TS.IDLE

    def rollback(self):
        self.observe("rollback")
        self.events.append("rollback")
        if self.rollback_error is not None:
            raise self.rollback_error
        self.info.transaction_status = TS.IDLE

    @contextmanager
    def transaction(self):
        assert self.info.transaction_status == TS.IDLE
        self.info.transaction_status = TS.INTRANS
        try:
            yield
        except BaseException:
            self.rollback()
            raise
        else:
            self.commit()

    def close(self):
        self.closed = True


@pytest.fixture
def facade(monkeypatch):
    repo = PostgresRepository("postgresql://never-connect.invalid/reviewer", object())
    conn = Driver()
    repo._connection = conn
    # Only catalog validation is unavailable in this driver model. Keep the
    # actual facade, strict historical idle guard, transaction, and RunSQL.
    monkeypatch.setattr(historical_ai_sql, "postgres_schema", lambda *a, **k: None)
    yield repo, conn
    repo.close()


def historical_observation(repo, conn):
    before = list(conn.queries)
    status = conn.info.transaction_status.name
    error = None
    try:
        result = repo.get_ai_run("missing-review")
        assert result is None
    except baseline.BaselineStorageError as exc:
        error = exc.code
    return {
        "status_before_historical": status,
        "historical_error": error,
        "historical_sql_issued": conn.queries != before,
        "events": list(conn.events),
    }


def assert_historical_available(repo, conn, record_property):
    observation = historical_observation(repo, conn)
    record_property("observation", repr(observation))
    assert observation["historical_error"] is None, observation
    assert conn.info.transaction_status == TS.IDLE


def test_zero_row_delete_releases_transaction(facade, record_property):
    repo, conn = facade
    conn.delete_rows = 0
    assert repo.delete_payload_signature("already-missing-review") is False
    assert any(q.startswith("DELETE") for q in conn.queries)
    assert_historical_available(repo, conn, record_property)


PRODUCERS = [
    "create_job",
    "save_job",
    "save_job_metadata",
    "delete_payload_signature",
    "delete_allowlist",
    "claim_enrollment",
    "update_sensor_configuration",
]


def call_producer(repo, method):
    if method in {"create_job", "save_job", "save_job_metadata"}:
        return getattr(repo, method)({"id": "job-review", "idempotency_key": "request-review"})
    if method in {"delete_payload_signature", "delete_allowlist"}:
        return getattr(repo, method)("existing-review")
    if method == "claim_enrollment":
        return repo.claim_enrollment("synthetic-token-hash", datetime(2026, 1, 1, tzinfo=UTC))
    return repo.update_sensor_configuration("sensor-review", 1, {"config_version": 2})


@pytest.mark.parametrize("method", PRODUCERS)
def test_real_nested_audit_caller_owns_failure_cleanup(facade, record_property, method):
    repo, conn = facade
    conn.fail_query = "INSERT INTO audit_events"
    with pytest.raises(psycopg.Error) as raised:
        call_producer(repo, method)
    assert raised.value is conn.primary
    assert conn.failure_fired == 1
    assert "commit" not in conn.events  # Nested helper must not publish early.
    conn.fail_query = None
    assert_historical_available(repo, conn, record_property)


@pytest.mark.parametrize(
    "method",
    ["get_posting_index_intent", "get_posting_index_task", "get_posting_index_queue_depth"],
)
def test_fenced_posting_reader_owns_failure_cleanup(facade, record_property, method):
    repo, conn = facade
    conn.fail_query = "SELECT"
    args = () if method.endswith("queue_depth") else ("SENSOR_PCAP", "source-review")
    with pytest.raises(psycopg.Error) as raised:
        getattr(repo, method)(*args)
    assert raised.value is conn.primary
    assert conn.failure_fired == 1
    conn.fail_query = None
    assert_historical_available(repo, conn, record_property)


def test_secondary_rollback_failure_preserves_original(facade, record_property):
    repo, conn = facade
    conn.fail_query = "SELECT data FROM controller_objects"
    secondary = psycopg.OperationalError("synthetic secondary rollback failure")
    conn.rollback_error = secondary
    with pytest.raises(psycopg.Error) as raised:
        repo.get_job_summary("missing-review")
    assert conn.failure_fired == 1
    assert conn.events == ["rollback"]
    record_property("caught_primary", raised.value is conn.primary)
    record_property("caught_secondary", raised.value is secondary)
    record_property("primary_retained_only_as_context", raised.value.__context__ is conn.primary)
    assert raised.value is conn.primary, "secondary rollback error replaced original exception"


def test_owned_put_control_rolls_back_nested_audit(facade, record_property):
    repo, conn = facade
    conn.fail_query = "INSERT INTO audit_events"
    with pytest.raises(psycopg.Error) as raised:
        repo.upsert_sensor({"sensor_id": "sensor-review"})
    assert raised.value is conn.primary and conn.failure_fired == 1
    assert conn.events == ["rollback"]
    conn.fail_query = None
    assert_historical_available(repo, conn, record_property)


def test_idle_readiness_and_put_control(facade):
    repo, conn = facade
    assert repo.database_ready()
    assert repo.get_ai_run("missing-review") is None
    conn.events.clear()
    assert repo.upsert_sensor({"sensor_id": "sensor-review"}) == {"sensor_id": "sensor-review"}
    assert conn.events == ["commit"]
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize("phase", ["commit", "rollback"])
def test_shared_lock_holds_through_finish_and_other_thread_reuses(facade, phase):
    repo, conn = facade
    finishing, release, blocked = Event(), Event(), Event()
    reader_thread = [None]
    results = {}

    class ObservedLock:
        def __init__(self):
            self.lock = RLock()

        def __enter__(self):
            if current_thread() is reader_thread[0]:
                if not self.lock.acquire(blocking=False):
                    blocked.set()
                    assert self.lock.acquire(timeout=5)
            else:
                assert self.lock.acquire(timeout=5)
            return self

        def __exit__(self, *args):
            self.lock.release()

    def pause(actual):
        if actual == phase and not finishing.is_set():
            finishing.set()
            assert release.wait(5)

    def owner():
        try:
            results["owner"] = repo.upsert_sensor({"sensor_id": "sensor-review"})
        except BaseException as exc:
            results["owner_error"] = exc

    def reader():
        reader_thread[0] = current_thread()
        try:
            results["reader"] = repo.get_ai_run("missing-review")
        except BaseException as exc:
            results["reader_error"] = exc

    repo._lock = ObservedLock()
    conn.observe = pause
    if phase == "rollback":
        conn.fail_query = "INSERT INTO audit_events"
    a, b = Thread(target=owner, daemon=True), Thread(target=reader, daemon=True)
    a.start()
    try:
        assert finishing.wait(5), "owner never reached its finishing boundary"
        b.start()
        assert blocked.wait(5), "reader was not fenced during finishing"
    finally:
        release.set()
        a.join(6)
        if b.ident is not None:
            b.join(6)
    assert not a.is_alive() and not b.is_alive()
    assert "reader_error" not in results, results
    assert results["reader"] is None
    if phase == "rollback":
        assert results["owner_error"] is conn.primary
    else:
        assert "owner_error" not in results
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize(
    "code,expected",
    [
        ("BASELINE_BUSY", "BASELINE_BUSY"),
        ("synthetic-private-marker", "BASELINE_STORAGE_UNAVAILABLE"),
    ],
)
def test_transport_mapping_does_not_expose_exception_text(code, expected):
    exc = baseline.BaselineStorageError(code)
    exc.args = ("synthetic-private-message-not-for-http",)
    error = transport_error(exc)
    assert error.status == 503 and error.code == expected
    assert "synthetic-private" not in error.message
