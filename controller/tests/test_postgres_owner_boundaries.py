"""Owner/nested transaction contract; driver model, not a PostgreSQL engine."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from threading import RLock

import psycopg
import pytest
from psycopg.pq import TransactionStatus as TS

from c2hunter_controller import historical_ai_sql
from c2hunter_controller.production import PostgresRepository
from tests import test_postgres_owner_regressions as original

NOW = datetime(2026, 1, 1, tzinfo=UTC)
READERS = [
    "get_posting_index_intent",
    "get_posting_index_task",
    "get_posting_index_queue_depth",
]
OWNERS = original.PRODUCERS + READERS


class CheckedLock:
    def __init__(self):
        self.lock = RLock()
        self.depth = 0

    def __enter__(self):
        self.lock.acquire()
        self.depth += 1
        return self

    def __exit__(self, *_):
        self.depth -= 1
        self.lock.release()


class Cursor(original.Cursor):
    def execute(self, query, parameters=()):
        c = self.connection
        assert c.lock.depth > 0
        result = super().execute(query, parameters)
        c.parameters.append((query, parameters))
        if query.startswith(("INSERT", "UPDATE", "DELETE")):
            c.pending.append((query, parameters))
        if c.phase == "materialize" and query.startswith("DELETE FROM controller_objects"):
            self.rowcount = c.bomb()
        return result

    def fetchall(self):
        c = self.connection
        assert c.lock.depth > 0
        if c.phase == "fetch":
            c.fire()
        q = self.query
        if q.startswith("INSERT INTO job_idempotency"):
            return [] if c.duplicate else [("job-review",)]
        if q.startswith("SELECT job_id FROM job_idempotency"):
            return [] if c.missing_ledger else [("job-review",)]
        if q.startswith("SELECT data FROM controller_objects WHERE kind=%s"):
            return (
                []
                if c.missing_job
                else [({"id": "job-review", "idempotency_key": "request-review"},)]
            )
        if "kind='enrollment'" in q and q.startswith("SELECT"):
            return [] if c.enrollment is None else [("enrollment-review", c.enrollment)]
        if "kind='sensor'" in q and q.startswith("SELECT"):
            return [] if c.sensor is None else [(c.sensor,)]
        spec = (
            "PCAP_UPLOAD",
            "source-review",
            "v1",
            100,
            "a" * 64,
            "PCAP",
            "build",
            "b" * 64,
            1,
            1,
            1,
            1,
            1,
        )
        if c.phase == "materialize":
            spec = (*spec[:3], c.bomb(), *spec[4:])
        if "FROM pcap_posting_index_intents " in q:
            return [(*spec, "PENDING", NOW, NOW, None, None)]
        if "FROM pcap_posting_index_jobs AS task " in q:
            return [(*spec, "QUEUED", 0, 3, None, None, NOW, NOW, NOW, None)]
        if q == "SELECT status,COUNT(*) FROM pcap_posting_index_jobs GROUP BY status":
            return [("QUEUED", c.bomb() if c.phase == "materialize" else 2)]
        return super().fetchall()


class Driver(original.Driver):
    def __init__(self, lock):
        super().__init__()
        self.lock = lock
        self.parameters = []
        self.pending = []
        self.published = []
        self.phase = None
        self.duplicate = False
        self.missing_ledger = False
        self.missing_job = False
        self.enrollment = {"expires_at": "2099-01-01T00:00:00+00:00"}
        self.sensor = {"sensor_id": "sensor-review", "config_version": 1}

    def cursor(self):
        assert self.lock.depth > 0
        return Cursor(self)

    def fire(self):
        assert self.lock.depth > 0
        self.failure_fired += 1
        raise self.primary

    def bomb(self):
        c = self

        class Bomb:
            def __int__(self):
                c.fire()

            def __gt__(self, other):
                c.fire()

        return Bomb()

    def copy_bomb(self, value):
        c = self

        class CopyBomb(dict):
            def __deepcopy__(self, memo):
                c.fire()

        return CopyBomb(value)

    def commit(self):
        assert self.lock.depth > 0
        if self.phase == "commit":
            self.fire()
        super().commit()
        self.published.extend(self.pending)
        self.pending.clear()

    def rollback(self):
        assert self.lock.depth > 0
        super().rollback()
        self.pending.clear()


@pytest.fixture
def boundary(monkeypatch):
    repo = PostgresRepository("postgresql://never-connect.invalid/ownership", object())
    repo._lock = CheckedLock()
    conn = Driver(repo._lock)
    repo._connection = conn
    monkeypatch.setattr(historical_ai_sql, "postgres_schema", lambda *a, **k: None)
    yield repo, conn
    repo.close()


def invoke(repo, method, job=None):
    if method in READERS:
        args = () if method.endswith("queue_depth") else ("PCAP_UPLOAD", "source-review")
        return getattr(repo, method)(*args)
    if job is not None:
        return getattr(repo, method)(job)
    return original.call_producer(repo, method)


def assert_reusable(repo, conn):
    assert conn.info.transaction_status == TS.IDLE
    assert repo._lock.depth == 0
    conn.phase = conn.fail_query = None
    before = len(conn.queries)
    assert repo.get_ai_run("missing-review") is None
    assert len(conn.queries) > before
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize("method", ["delete_payload_signature", "delete_allowlist"])
@pytest.mark.parametrize("rows", [0, 1])
@pytest.mark.parametrize("borrowed", [False, True])
def test_delete_outcomes_and_ownership(boundary, method, rows, borrowed):
    repo, conn = boundary
    conn.delete_rows = rows
    if borrowed:
        conn.info.transaction_status = TS.INTRANS
        conn.pending.append(("caller-owned", ()))
    assert invoke(repo, method) is bool(rows)
    audits = [q for q in conn.queries if q.startswith("INSERT INTO audit_events")]
    assert len(audits) == rows
    assert conn.events == ([] if borrowed else ["commit"])
    if borrowed:
        assert conn.info.transaction_status == TS.INTRANS
        assert conn.published == []
        assert ("caller-owned", ()) in conn.pending
    else:
        assert_reusable(repo, conn)


def arm(conn, method, phase):
    job = None
    if phase == "sql":
        conn.fail_query = (
            "SELECT"
            if method in READERS or method in {"claim_enrollment", "update_sensor_configuration"}
            else "DELETE"
            if method.startswith("delete_")
            else "INSERT"
        )
    elif phase == "audit":
        conn.fail_query = "INSERT INTO audit_events"
    else:
        conn.phase = phase
    if phase == "materialize":
        if method in {"create_job", "save_job", "save_job_metadata"}:
            job = {
                "id": "job-review",
                "idempotency_key": "request-review",
                "extra": conn.copy_bomb({"value": 1}),
            }
        elif method == "claim_enrollment":
            conn.enrollment = conn.copy_bomb(conn.enrollment)
        elif method == "update_sensor_configuration":
            conn.sensor = conn.copy_bomb(conn.sensor)
    return job


FAULTS = [(method, phase) for method in OWNERS for phase in ("sql", "materialize", "commit")]
FAULTS += [(method, "audit") for method in original.PRODUCERS]
FAULTS += [
    (method, "fetch")
    for method in READERS + ["create_job", "claim_enrollment", "update_sensor_configuration"]
]


@pytest.mark.parametrize("method,phase", FAULTS)
def test_owned_failure_is_atomic_and_reusable(boundary, method, phase):
    repo, conn = boundary
    job = arm(conn, method, phase)
    with pytest.raises(psycopg.Error) as raised:
        invoke(repo, method, job)
    assert conn.failure_fired == 1
    assert raised.value is conn.primary
    assert conn.published == []
    assert conn.events == ["rollback"]
    assert conn.pending == []
    assert_reusable(repo, conn)


@pytest.mark.parametrize("method", OWNERS)
@pytest.mark.parametrize("failure", [False, True])
def test_borrowed_owner_does_not_finish_callers_transaction(boundary, method, failure):
    repo, conn = boundary
    conn.info.transaction_status = TS.INTRANS
    conn.pending.append(("caller-owned", ()))
    if failure:
        arm(conn, method, "audit" if method in original.PRODUCERS else "sql")
        with pytest.raises(psycopg.Error) as raised:
            invoke(repo, method)
        assert raised.value is conn.primary
        assert conn.failure_fired == 1
        assert conn.info.transaction_status == TS.INERROR
    else:
        invoke(repo, method)
        assert conn.info.transaction_status == TS.INTRANS
    assert conn.events == []
    assert conn.published == []
    assert ("caller-owned", ()) in conn.pending
    assert repo._lock.depth == 0


@pytest.mark.parametrize("method", OWNERS)
@pytest.mark.parametrize("failure", [False, True])
def test_real_nested_owner_finishes_only_at_outer_boundary(boundary, method, failure):
    repo, conn = boundary

    def operation():
        with repo._shared_cursor() as cursor:
            cursor.execute("SELECT 1")
            try:
                invoke(repo, method)
            finally:
                assert conn.events == []
                assert conn.published == []

    if failure:
        arm(conn, method, "audit" if method in original.PRODUCERS else "sql")
        # Do not fail the outer SELECT that establishes ownership.
        if method in READERS:
            conn.fail_query = "FROM pcap_posting_index"
        with pytest.raises(psycopg.Error) as raised:
            operation()
        assert raised.value is conn.primary
        assert conn.failure_fired == 1
        assert conn.events == ["rollback"]
        assert conn.published == []
    else:
        operation()
        assert conn.events == ["commit"]
    assert_reusable(repo, conn)


@pytest.mark.parametrize("method", ["create_job", "save_job", "save_job_metadata"])
@pytest.mark.parametrize("parts", [None, [], [{"id": "part"}]])
def test_job_payload_omission_and_return_contract(boundary, method, parts):
    repo, conn = boundary
    job = {"id": "job-review", "idempotency_key": "request-review", "nested": {"a": 1}}
    if parts is not None:
        job.update(flow_records=deepcopy(parts), payload_signatures=deepcopy(parts))
    result = invoke(repo, method, job)
    if method == "create_job":
        result, created = result
        assert created is True
    metadata = {k: v for k, v in job.items() if k not in {"flow_records", "payload_signatures"}}
    assert result == (metadata if method == "save_job_metadata" else job)
    result["nested"]["a"] = 2
    assert job["nested"]["a"] == 1
    for query, args in conn.parameters:
        if "INSERT INTO controller_objects" in query:
            assert json.loads(args[1]) == metadata
        if "INSERT INTO audit_events" in query:
            assert json.loads(args[3]) == metadata
    flows = [
        (q, a) for q, a in conn.parameters if q.startswith("INSERT INTO job_flow_record_chunks")
    ]
    signatures = [
        (q, a) for q, a in conn.parameters if q.startswith("INSERT INTO job_payload_signatures")
    ]
    if method == "save_job_metadata":
        assert not flows and not signatures
        assert not any("DELETE FROM job_flow" in q for q in conn.queries)
    elif parts is None:
        assert not flows
        assert bool(signatures) is (method == "create_job")
        if signatures:
            assert json.loads(signatures[0][1][1]) == []
    else:
        assert len(flows) == len(signatures) == 1
        assert json.loads("[" + flows[0][1][2] + "]") == parts
        assert json.loads(signatures[0][1][1]) == parts
    assert conn.events == ["commit"]
    assert sum(q.startswith("INSERT INTO audit_events") for q in conn.queries) == 1
    assert_reusable(repo, conn)


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("missing", [None, "ledger", "job"])
def test_duplicate_creation_stays_in_owner_transaction(boundary, borrowed, missing):
    repo, conn = boundary
    conn.duplicate = True
    conn.missing_ledger = missing == "ledger"
    conn.missing_job = missing == "job"
    if borrowed:
        conn.info.transaction_status = TS.INTRANS
    if missing:
        with pytest.raises(RuntimeError, match="idempotency ledger"):
            invoke(repo, "create_job")
    else:
        result, created = invoke(repo, "create_job")
        assert created is False
        assert result == {
            "id": "job-review",
            "idempotency_key": "request-review",
            "flow_records": [],
            "payload_signatures": [],
        }
    assert not any(q.startswith("INSERT INTO audit_events") for q in conn.queries)
    assert not any(q.startswith("INSERT INTO controller_objects") for q in conn.queries)
    assert conn.events == ([] if borrowed else ["rollback" if missing else "commit"])
    if borrowed:
        assert conn.info.transaction_status == TS.INTRANS
    else:
        assert_reusable(repo, conn)


@pytest.mark.parametrize("method", ["create_job", "save_job"])
@pytest.mark.parametrize("borrowed", [False, True])
def test_flow_replacement_helper_never_finishes_callers_work(boundary, method, borrowed):
    repo, conn = boundary
    if borrowed:
        conn.info.transaction_status = TS.INTRANS
        conn.pending.append(("caller-owned", ()))
    conn.fail_query = "INSERT INTO job_flow_record_chunks"
    job = {"id": "job-review", "idempotency_key": "request-review", "flow_records": []}
    with pytest.raises(psycopg.Error) as raised:
        invoke(repo, method, job)
    assert raised.value is conn.primary
    assert conn.failure_fired == 1
    assert conn.published == []
    assert conn.events == ([] if borrowed else ["rollback"])
    if borrowed:
        assert ("caller-owned", ()) in conn.pending
        assert conn.info.transaction_status == TS.INERROR
    else:
        assert_reusable(repo, conn)


@pytest.mark.parametrize("outcome", ["NOT_FOUND", "REVOKED", "CLAIMED", "EXPIRED", "OK"])
@pytest.mark.parametrize("borrowed", [False, True])
def test_enrollment_early_outcomes(boundary, outcome, borrowed):
    repo, conn = boundary
    if outcome == "NOT_FOUND":
        conn.enrollment = None
    elif outcome == "REVOKED":
        conn.enrollment["revoked_at"] = NOW.isoformat()
    elif outcome == "CLAIMED":
        conn.enrollment["claimed_at"] = NOW.isoformat()
    elif outcome == "EXPIRED":
        conn.enrollment["expires_at"] = NOW.isoformat()
    expected = deepcopy(conn.enrollment)
    if outcome == "OK":
        expected["claimed_at"] = NOW.isoformat()
    if borrowed:
        conn.info.transaction_status = TS.INTRANS
    assert invoke(repo, "claim_enrollment") == (expected, outcome)
    assert sum(q.startswith("INSERT INTO audit_events") for q in conn.queries) == (outcome == "OK")
    assert sum(q.startswith("UPDATE") for q in conn.queries) == (outcome == "OK")
    assert conn.events == ([] if borrowed else ["commit"])
    if borrowed:
        assert conn.info.transaction_status == TS.INTRANS
    else:
        assert_reusable(repo, conn)


@pytest.mark.parametrize("outcome", ["NOT_FOUND", "CONFLICT", "OK"])
@pytest.mark.parametrize("borrowed", [False, True])
def test_configuration_early_outcomes(boundary, outcome, borrowed):
    repo, conn = boundary
    if outcome == "NOT_FOUND":
        conn.sensor = None
    elif outcome == "CONFLICT":
        conn.sensor["config_version"] = 0
    expected = deepcopy(conn.sensor)
    if outcome == "OK":
        expected["config_version"] = 2
    if borrowed:
        conn.info.transaction_status = TS.INTRANS
    assert invoke(repo, "update_sensor_configuration") == (expected, outcome)
    assert sum(q.startswith("INSERT INTO audit_events") for q in conn.queries) == (outcome == "OK")
    assert sum(q.startswith("UPDATE") for q in conn.queries) == (outcome == "OK")
    assert conn.events == ([] if borrowed else ["commit"])
    if borrowed:
        assert conn.info.transaction_status == TS.INTRANS
    else:
        assert_reusable(repo, conn)


@pytest.mark.parametrize("method", OWNERS)
@pytest.mark.parametrize("phase", ["sql", "commit"])
def test_secondary_cleanup_failure_does_not_replace_primary(boundary, method, phase):
    repo, conn = boundary
    arm(conn, method, phase)
    conn.rollback_error = psycopg.OperationalError("secondary cleanup failure")
    with pytest.raises(psycopg.Error) as raised:
        invoke(repo, method)
    assert conn.failure_fired == 1
    assert raised.value is conn.primary
    assert conn.events == ["rollback"]
    assert conn.published == []
    # Failed rollback is not healthy recovery and must not be represented as such.
    assert conn.info.transaction_status != TS.IDLE
    assert repo._lock.depth == 0


@pytest.mark.parametrize(
    "method,phase", [pair for pair in FAULTS if pair[1] in {"fetch", "materialize"}]
)
def test_borrowed_fetch_and_materialization_errors_do_not_finish(boundary, method, phase):
    repo, conn = boundary
    conn.info.transaction_status = TS.INTRANS
    conn.pending.append(("caller-owned", ()))
    job = arm(conn, method, phase)
    with pytest.raises(psycopg.Error) as raised:
        invoke(repo, method, job)
    assert conn.failure_fired == 1
    assert raised.value is conn.primary
    assert conn.events == []
    assert conn.published == []
    assert ("caller-owned", ()) in conn.pending


@pytest.mark.parametrize(
    "query",
    [
        "SELECT data FROM controller_objects WHERE kind=%s",
        "SELECT data FROM job_flow_record_chunks",
        "SELECT data FROM job_payload_signatures",
    ],
)
@pytest.mark.parametrize("borrowed", [False, True])
def test_duplicate_creation_nested_read_failure(boundary, query, borrowed):
    repo, conn = boundary
    conn.duplicate = True
    conn.fail_query = query
    if borrowed:
        conn.info.transaction_status = TS.INTRANS
    with pytest.raises(psycopg.Error) as raised:
        invoke(repo, "create_job")
    assert conn.failure_fired == 1
    assert raised.value is conn.primary
    assert conn.published == []
    assert conn.events == ([] if borrowed else ["rollback"])
    if not borrowed:
        assert_reusable(repo, conn)


@pytest.mark.parametrize("method", READERS)
def test_owned_populated_posting_reader_result(boundary, method):
    repo, conn = boundary
    result = invoke(repo, method)
    if method.endswith("queue_depth"):
        assert result == {"QUEUED": 2, "RUNNING": 0, "COMPLETED": 0, "FAILED": 0}
    else:
        assert result.spec.source_kind == "PCAP_UPLOAD"
        assert result.spec.source_id == "source-review"
        assert result.spec.source_size_bytes == 100
        assert result.status.value == ("PENDING" if method.endswith("intent") else "QUEUED")
    assert conn.events == ["commit"]
    assert_reusable(repo, conn)


facade = original.facade


@pytest.mark.parametrize("method", OWNERS)
@pytest.mark.parametrize("phase", ["commit", "rollback"])
def test_each_owner_fences_finish_against_historical_thread(facade, method, phase):
    from threading import Event, Thread, current_thread

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

        def __exit__(self, *_):
            self.lock.release()

    def pause(actual):
        if actual == phase and not finishing.is_set():
            finishing.set()
            assert release.wait(5)

    def owner():
        try:
            results["owner"] = invoke(repo, method)
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
        conn.fail_query = (
            "INSERT INTO audit_events"
            if method in original.PRODUCERS
            else "FROM pcap_posting_index"
        )
    a, b = Thread(target=owner, daemon=True), Thread(target=reader, daemon=True)
    a.start()
    try:
        assert finishing.wait(5)
        b.start()
        assert blocked.wait(5)
    finally:
        release.set()
        a.join(6)
        if b.ident is not None:
            b.join(6)
    assert not a.is_alive() and not b.is_alive()
    assert "reader_error" not in results
    assert results["reader"] is None
    if phase == "rollback":
        assert results["owner_error"] is conn.primary
        assert conn.failure_fired == 1
    else:
        assert "owner_error" not in results
    assert conn.info.transaction_status == TS.IDLE
