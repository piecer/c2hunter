"""Exact direct-query siblings sharing the same PostgreSQL facade connection."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event, RLock, current_thread

import pytest
from psycopg.pq import TransactionStatus as TS

from tests import test_postgres_historical_ownership as ownership

pg = ownership.pg

CASES = [
    ("get_job_summaries", (["missing"],), {}),
    ("list_active_live_jobs", (), {}),
    ("get_candidates", ("missing",), {}),
    ("get_candidate", ("missing",), {}),
    ("query_candidates", (), {}),
    (
        "query_candidate_page",
        (),
        dict(
            minimum_score=0,
            severity=None,
            include_suppressed=False,
            sort="-score",
            page=1,
            page_size=10,
        ),
    ),
    ("query_candidate_refs", (), dict(minimum_score=0, severity=None, include_suppressed=False)),
    (
        "candidate_workflow_counts",
        (),
        dict(minimum_score=0, severity=None, include_suppressed=False),
    ),
    ("list_candidate_sets", (), {}),
    ("list_candidate_workflow_records", (["missing"],), {}),
    ("list_flow_labels", ("missing",), {}),
    ("list_sensor_pcaps_for_job", ("missing",), {}),
]


@pytest.mark.parametrize("name,args,kwargs", CASES, ids=[c[0] for c in CASES])
def test_direct_query_sibling_does_not_interrupt_historical_owner(pg, name, args, kwargs):
    repo, conn = pg
    conn.pause_on = "SELECT"
    observed = Event()
    reader_thread = [None]
    actual_context = repo._historical_connection

    class Lock:
        def __init__(self):
            self.lock = RLock()

        def __enter__(self):
            if current_thread() is reader_thread[0] and not self.lock.acquire(blocking=False):
                observed.set()
                self.lock.acquire()
            elif current_thread() is not reader_thread[0]:
                self.lock.acquire()
            return self

        def __exit__(self, *_):
            self.lock.release()

    @contextmanager
    def context():
        reader_thread[0] = current_thread()
        try:
            with actual_context() as connection:
                yield connection
        finally:
            observed.set()

    repo._lock = Lock()
    repo._historical_connection = context
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(getattr(repo, name), *args, **kwargs)
        try:
            assert conn.entered.wait(5), name
            reader = pool.submit(repo.get_ai_run, "missing")
            assert observed.wait(5), name
            conn.release.set()
            owner.result(timeout=5)
            assert reader.result(timeout=5) is None
        finally:
            conn.release.set()
    assert conn.info.transaction_status == TS.IDLE


def test_nonempty_job_summary_read_closes_implicit_transaction(pg):
    repo, conn = pg
    assert repo.get_job_summaries(["missing"]) == {}
    assert repo.get_ai_run("missing") is None
    assert conn.info.transaction_status == TS.IDLE


def test_empty_job_summary_read_does_not_acquire_database(pg):
    repo, conn = pg
    assert repo.get_job_summaries([]) == {}
    assert conn.queries == []
    assert conn.info.transaction_status == TS.IDLE


def assert_fenced(repo, conn, operation):
    """Release the owner only after a real blocked acquire or reader exit."""
    observed, blocked = Event(), Event()
    reader_thread = [None]
    actual_context = repo._historical_connection

    class Lock:
        def __init__(self):
            self.lock = RLock()

        def __enter__(self):
            if current_thread() is reader_thread[0]:
                if not self.lock.acquire(blocking=False):
                    blocked.set()
                    observed.set()
                    self.lock.acquire()
            else:
                self.lock.acquire()
            return self

        def __exit__(self, *_):
            self.lock.release()

    @contextmanager
    def context():
        reader_thread[0] = current_thread()
        try:
            with actual_context() as connection:
                yield connection
        finally:
            observed.set()

    repo._lock = Lock()
    repo._historical_connection = context
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(operation)
        try:
            assert conn.entered.wait(5), "owner never reached selected phase"
            reader = pool.submit(repo.get_ai_run, "missing")
            assert observed.wait(5), "reader never attempted fence"
            conn.release.set()
            result = owner.result(timeout=5)
            assert reader.result(timeout=5) is None
            assert blocked.is_set(), "owner released its fence before materialization/commit"
            return result
        finally:
            conn.release.set()


def populated(conn, monkeypatch, name):
    import json

    payload = '{"id":"owned","created_at":"2026-01-01"}'
    value = json.loads(payload)
    loads = json.loads

    def observed_loads(raw, *args, **kwargs):
        if raw == payload:
            conn.observe("materialize", "")
        return loads(raw, *args, **kwargs)

    monkeypatch.setattr(json, "loads", observed_loads)

    class Identifier:
        def __str__(self):
            conn.observe("materialize", "")
            return "owned"

    class Count:
        def __int__(self):
            conn.observe("materialize", "")
            return 1

    if name == "get_job_summaries":
        conn.rows = {"SELECT id,data": [("owned", payload)]}
        return {"owned": value}
    if name == "query_candidate_refs":
        conn.rows = {"SELECT candidate_id,excluded": [(Identifier(), False)]}
        return [("owned", False)]
    if name == "candidate_workflow_counts":
        conn.rows = {"COUNT(*) FILTER": [(Count(), 0, 0, 0, 0, 0, 0)]}
        return dict(
            needs_review=1,
            in_review=0,
            action_required=0,
            action_in_progress=0,
            action_completed=0,
            false_positive=0,
            done=0,
        )
    if name == "query_candidate_page":
        conn.rows = {"SELECT COUNT": [(1,)], "WITH filtered": [("owned", payload, 2)]}
        return [("owned", {**value, "occurrence_count": 2, "duplicate_count": 1})], 1
    if name == "list_candidate_workflow_records":
        conn.rows = {"SELECT kind,data": [("candidate-decision", payload)]}
        return dict(decisions=[value], actions=[], lookups=[], misp_actions=[])
    if name in {"get_candidate", "query_candidates", "list_candidate_sets"}:
        conn.rows = {"SELECT job_id,data": [("owned", payload)]}
        if name == "get_candidate":
            return "owned", value
        if name == "list_candidate_sets":
            return {"owned": [value]}
        return [("owned", value)]
    conn.rows = {"SELECT data": [(payload,)]}
    return [value]


@pytest.mark.parametrize("name,args,kwargs", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("phase", ["fetch", "materialize", "commit"])
def test_populated_reader_holds_fence_until_result_and_commit(
    pg, monkeypatch, name, args, kwargs, phase
):
    repo, conn = pg
    expected = populated(conn, monkeypatch, name)
    fired = False

    def pause(actual, query):
        nonlocal fired
        if actual == phase and not fired:
            fired = True
            conn.entered.set()
            assert conn.release.wait(5)

    conn.observe = pause
    result = assert_fenced(repo, conn, lambda: getattr(repo, name)(*args, **kwargs))
    assert result == expected
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize("name,args,kwargs", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("phase", ["execute", "fetch", "materialize", "commit"])
def test_reader_failure_rolls_back_and_preserves_error(pg, monkeypatch, name, args, kwargs, phase):
    repo, conn = pg
    populated(conn, monkeypatch, name)
    failure = RuntimeError("owned reader failure")
    fired = False

    def fail(actual, query):
        nonlocal fired
        if actual == phase:
            fired = True
            raise failure

    conn.observe = fail
    with pytest.raises(RuntimeError) as raised:
        getattr(repo, name)(*args, **kwargs)
    assert fired and raised.value is failure
    assert [event[0] for event in conn.events] == ["rollback"]
    assert conn.info.transaction_status == TS.IDLE
    conn.observe = lambda *args: None
    conn.rows = {}
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(repo.get_ai_run, "missing").result(timeout=5) is None


@pytest.mark.parametrize("name,args,kwargs", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("failed", [False, True])
def test_reader_preserves_borrowed_transaction(pg, name, args, kwargs, failed):
    import psycopg

    repo, conn = pg
    conn.execute("SELECT caller_work")
    before = list(conn.events)
    if failed:
        conn.failure_on = "SELECT"
        with pytest.raises(psycopg.OperationalError):
            getattr(repo, name)(*args, **kwargs)
        assert conn.info.transaction_status == TS.INERROR
    else:
        getattr(repo, name)(*args, **kwargs)
        assert conn.info.transaction_status == TS.INTRANS
    assert conn.events == before


JOB_QUERIES = ["job_flow_record_chunks", "job_flow_records WHERE", "job_payload_signatures"]


def populated_job(conn, query):
    conn.rows = {
        "SELECT data FROM controller_objects": [('{"id":"owned"}',)],
        "job_payload_signatures": [('[{"id":"signature"}]',)],
    }
    conn.rows[
        "job_flow_records WHERE" if query == "job_flow_records WHERE" else "job_flow_record_chunks"
    ] = [('[{"id":"flow"}]',)]


@pytest.mark.parametrize("query", JOB_QUERIES)
def test_populated_get_job_direct_sections_are_fenced(pg, query):
    repo, conn = pg
    populated_job(conn, query)
    conn.pause_on = query
    result = assert_fenced(repo, conn, lambda: repo.get_job("owned"))
    assert result == dict(
        id="owned", flow_records=[{"id": "flow"}], payload_signatures=[{"id": "signature"}]
    )
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize("query", JOB_QUERIES)
@pytest.mark.parametrize("phase", ["execute", "fetch"])
def test_populated_get_job_direct_failures_release_owned_transaction(pg, query, phase):
    repo, conn = pg
    populated_job(conn, query)
    failure = RuntimeError("job detail failure")
    fired = False

    def fail(actual, statement):
        nonlocal fired
        if actual == phase and query in statement:
            fired = True
            raise failure

    conn.observe = fail
    with pytest.raises(RuntimeError) as raised:
        repo.get_job("owned")
    assert fired and raised.value is failure
    assert conn.events[-1][0] == "rollback"
    assert conn.info.transaction_status == TS.IDLE
    conn.observe = lambda *args: None
    assert repo.get_ai_run("missing") is None


@pytest.mark.parametrize("query", JOB_QUERIES)
def test_populated_get_job_invalid_json_rolls_back(pg, query):
    import json

    repo, conn = pg
    populated_job(conn, query)
    conn.rows[query] = [("{invalid-json",)]
    with pytest.raises(json.JSONDecodeError):
        repo.get_job("owned")
    assert conn.events[-1][0] == "rollback"
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize("failed", [False, True])
def test_populated_get_job_preserves_caller_transaction(pg, failed):
    import psycopg

    repo, conn = pg
    populated_job(conn, "job_flow_record_chunks")
    conn.execute("SELECT caller_work")
    before = list(conn.events)
    if failed:
        conn.failure_on = "job_payload_signatures"
        with pytest.raises(psycopg.OperationalError):
            repo.get_job("owned")
        assert conn.info.transaction_status == TS.INERROR
    else:
        assert repo.get_job("owned")["payload_signatures"] == [{"id": "signature"}]
        assert conn.info.transaction_status == TS.INTRANS
    assert conn.events == before
