"""Legacy ownership contracts at the PostgreSQL driver boundary, not a PG server."""

import psycopg
import pytest
from psycopg.pq import TransactionStatus as TS

from tests import test_postgres_historical_ownership as ownership

pg = ownership.pg


def legacy_call(repo, name):
    if name == "audit":
        return repo.append_audit_event("probe", "owned", {})
    if name == "put":
        return repo.upsert_sensor({"sensor_id": "owned"})
    if name == "get":
        return repo.get_job_summary("missing")
    return repo.list_sensors()


@pytest.mark.parametrize("name", ["get", "list", "audit", "put"])
@pytest.mark.parametrize("failed", [False, True])
def test_borrowed_legacy_work_does_not_finish_caller_transaction(pg, name, failed):
    repo, conn = pg
    conn.execute("SELECT caller_work")
    before = list(conn.events)
    if failed:
        conn.failure_on = "SELECT" if name in {"get", "list"} else "INSERT"
        with pytest.raises(psycopg.OperationalError, match="synthetic driver failure"):
            legacy_call(repo, name)
        assert conn.info.transaction_status == TS.INERROR
    else:
        legacy_call(repo, name)
        assert conn.info.transaction_status == TS.INTRANS
    assert conn.events == before
    # The caller, not the nested helper, decides whether to roll back its work.
    conn.rollback()
    conn.failure_on = None
    assert repo.get_ai_run("missing") is None


@pytest.mark.parametrize("query", ["INSERT INTO controller_objects", "INSERT INTO audit_events"])
def test_put_rolls_back_both_object_and_audit_on_sql_failure(pg, query):
    repo, conn = pg
    conn.failure_on = query
    with pytest.raises(psycopg.OperationalError, match="synthetic driver failure"):
        repo.upsert_sensor({"sensor_id": "owned"})
    assert conn.info.transaction_status == TS.IDLE
    assert [event[0] for event in conn.events] == ["rollback"]
    conn.failure_on = None
    assert repo.upsert_sensor({"sensor_id": "owned"}) == {"sensor_id": "owned"}
    assert repo.get_ai_run("missing") is None


def test_nested_audit_does_not_commit_before_put_return_materialization(pg):
    repo, conn = pg
    failure = RuntimeError("copy failed after audit")

    class Uncopyable(dict):
        def __deepcopy__(self, memo):
            raise failure

    with pytest.raises(RuntimeError) as raised:
        repo.upsert_sensor(Uncopyable(sensor_id="owned"))
    assert raised.value is failure
    assert any("INSERT INTO audit_events" in query for query in conn.queries)
    assert [event[0] for event in conn.events] == ["rollback"]
    assert conn.info.transaction_status == TS.IDLE
    assert repo.get_ai_run("missing") is None


def test_put_commits_once_after_nested_audit(pg):
    repo, conn = pg
    original = {"sensor_id": "owned", "nested": {"version": 1}}
    saved = repo.upsert_sensor(original)
    assert saved == original and saved is not original
    assert saved["nested"] is not original["nested"]
    assert [event[0] for event in conn.events] == ["commit"]
    assert conn.info.transaction_status == TS.IDLE


@pytest.mark.parametrize("name", ["get", "list", "audit", "put"])
def test_owned_commit_failure_rolls_back_and_releases_for_other_thread(pg, monkeypatch, name):
    from concurrent.futures import ThreadPoolExecutor

    repo, conn = pg
    failure = psycopg.OperationalError("commit refused")
    commit = conn.commit

    def refuse():
        conn.info.transaction_status = TS.INERROR
        raise failure

    monkeypatch.setattr(conn, "commit", refuse)
    with pytest.raises(psycopg.OperationalError) as raised:
        legacy_call(repo, name)
    assert raised.value is failure
    assert conn.info.transaction_status == TS.IDLE
    assert [event[0] for event in conn.events] == ["rollback"]
    monkeypatch.setattr(conn, "commit", commit)
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(repo.get_ai_run, "missing").result(timeout=5) is None


@pytest.mark.parametrize("name", ["get", "list"])
@pytest.mark.parametrize("phase", ["fetch", "materialize"])
def test_helper_result_failure_is_inside_owned_transaction(pg, name, phase):
    import json

    repo, conn = pg
    failure = RuntimeError("fetch failed")
    if phase == "materialize":
        conn.rows = {"SELECT data": [("{invalid-json",)]}
        error = json.JSONDecodeError
    else:

        def fail(actual, query):
            if actual == "fetch":
                raise failure

        conn.observe = fail
        error = RuntimeError
    with pytest.raises(error) as raised:
        legacy_call(repo, name)
    if phase == "fetch":
        assert raised.value is failure
    assert [event[0] for event in conn.events] == ["rollback"]
    assert conn.info.transaction_status == TS.IDLE
