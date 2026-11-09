"""Independent schedules. Reuse source/gateway setup only, not author oracles."""

import hashlib
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller import ai_investigation_store as custody
from c2hunter_controller import ai_job_investigation as broker
from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_contract import InvestigationError
from c2hunter_controller.ai_job_investigation_store import (
    initialize_job_investigation_store,
)
from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_ai_investigation_http_runtime import HEADERS, configured, settings
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted, service_for
from tests.test_ai_job_investigation_source import flow, job

OBSERVATIONS = {}
BASE = "/api/v1/analysis-jobs/job/ai-job-investigations"
CAPS = "/api/v1/ai-job-investigations/capabilities"


@pytest.fixture(params=["memory", "sqlite"])
def repo(request, tmp_path):
    r = (
        MemoryRepository()
        if request.param == "memory"
        else SQLiteRepository(tmp_path / "custody.db")
    )
    r.save_job(job([flow(domain="updates.example.test")]))
    custody.initialize_investigation_store(r)
    initialize_job_investigation_store(r)
    yield r
    r.close()


def key(repo, label):
    return type(repo).__name__ + ":" + label


def wait_for(fn, seconds=4):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.01)
    raise AssertionError("bounded owner wait expired")


@pytest.mark.parametrize("boundary", ["broker_encode", "store_document", "state_write"])
@pytest.mark.parametrize("late", [False, True])
def test_original_monotonic_deadline_at_final_publication(repo, monkeypatch, boundary, late):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        svc = service_for(repo, gateway)
        run, _ = svc.admit("alice", "job", request_for())
        claim = svc.store.claim("worker")
        deadline = time.monotonic() + 2
        fired = []

        def pause():
            assert time.monotonic() < deadline, "setup: target was not reached before deadline"
            fired.append(time.monotonic())
            if late:
                time.sleep(max(0, deadline - time.monotonic()) + 0.03)

        if boundary == "broker_encode":
            old = broker._wire

            def encode(v):
                raw = old(v)
                if getattr(v, "kind", None) == "RESULT" and v.reason is None:
                    pause()
                return raw

            monkeypatch.setattr(broker, "_wire", encode)
        elif boundary == "store_document":
            old = custody._document

            def document(raw, limit):
                value = old(raw, limit)
                obj = json.loads(raw)
                if obj.get("kind") == "RESULT" and obj.get("reason") is None:
                    pause()
                return value

            monkeypatch.setattr(custody, "_document", document)
        else:
            old = svc.store._write

            def write(tx, kind_, identifier, value):
                if kind_ == "ai_job_investigation_state_v1" and value.get("status") == "COMPLETED":
                    pause()
                return old(tx, kind_, identifier, value)

            monkeypatch.setattr(svc.store, "_write", write)
        outcome = svc.execute_claim(claim, deadline_monotonic=deadline)
        saved = svc.get("alice", "job", run.id)
        OBSERVATIONS[key(repo, f"deadline:{boundary}:{late}")] = dict(
            fired=fired,
            deadline=deadline,
            exit_time=time.monotonic(),
            status=saved.status,
            reason=getattr(saved.result, "reason", None),
            outcome=outcome.code,
            ack=outcome.acknowledge_exit,
            model_calls=len(calls),
        )
        assert len(fired) == 1
        assert len(calls) == 3
        if late:
            assert saved.status != "COMPLETED", (
                "late synchronous publication persisted COMPLETED after original deadline"
            )
        else:
            assert saved.status == "COMPLETED" and outcome.acknowledge_exit


@pytest.mark.parametrize("fault", ["rollback", "ambiguous", "late_commit", "on_time_commit"])
def test_actual_sqlite_final_transaction(tmp_path, monkeypatch, fault):
    repo = SQLiteRepository(tmp_path / "transaction.db")
    repo.save_job(job([flow(domain="updates.example.test")]))
    custody.initialize_investigation_store(repo)
    initialize_job_investigation_store(repo)
    connection = repo.connection
    fired = []
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        svc = service_for(repo, gateway)
        run, _ = svc.admit("alice", "job", request_for())
        claim = svc.store.claim("worker")
        deadline = time.monotonic() + 2
        if fault == "rollback":
            connection.create_function("fault_fired", 0, lambda: fired.append("trigger") or 1)
            connection.executescript(
                "CREATE TEMP TRIGGER fail_final BEFORE UPDATE ON objects "
                "WHEN NEW.kind='ai_job_investigation_state_v1' "
                "AND json_extract(NEW.data,'$.status')='COMPLETED' "
                "BEGIN SELECT fault_fired(); "
                "SELECT RAISE(ABORT,'independent final refusal'); END;"
            )
        else:

            class Connection:
                def __getattr__(self, name):
                    return getattr(connection, name)

                def commit(self):
                    row = connection.execute(
                        "SELECT data FROM objects WHERE kind=? AND id=?",
                        ("ai_job_investigation_state_v1", run.id),
                    ).fetchone()
                    final = row and json.loads(row[0])["status"] == "COMPLETED" and not fired
                    if final:
                        assert time.monotonic() < deadline
                        fired.append(fault)
                        if fault == "late_commit":
                            time.sleep(max(0, deadline - time.monotonic()) + 0.03)
                    connection.commit()
                    if final and fault == "ambiguous":
                        raise sqlite3.OperationalError("commit reply lost")

            repo.connection = Connection()
        try:
            outcome = svc.execute_claim(claim, deadline_monotonic=deadline)
            with sqlite3.connect("file:" + repo._path + "?mode=ro", uri=True) as reader:
                durable = json.loads(
                    reader.execute(
                        "SELECT data FROM objects WHERE kind=? AND id=?",
                        ("ai_job_investigation_state_v1", run.id),
                    ).fetchone()[0]
                )
            OBSERVATIONS["sqlite:" + fault] = dict(
                status=durable["status"],
                slot=durable["slot"],
                outcome=outcome.code,
                ack=outcome.acknowledge_exit,
                fired=fired,
                calls=len(calls),
                deadline=deadline,
                exit_time=time.monotonic(),
                in_transaction=connection.in_transaction,
            )
            assert len(fired) == 1 and len(calls) == 3 and not connection.in_transaction
            if fault == "rollback":
                assert durable["status"] == "VALIDATING" and "result" not in durable
                assert not outcome.acknowledge_exit and outcome.code == "STORAGE_UNAVAILABLE"
                assert svc.store.get("alice", "job", run.id)["status"] == "VALIDATING"
            elif fault == "ambiguous":
                assert durable["status"] == "COMPLETED" and durable["slot"] == "HELD"
                assert not outcome.acknowledge_exit and outcome.code == "STORAGE_OUTCOME_UNKNOWN"
                with pytest.raises(custody.InvestigationOutcomeUnknown):
                    custody.InvestigationRunStore(repo).page("alice", "job")
                reopened = SQLiteRepository(repo._path)
                try:
                    restored = service_for(reopened, None)
                    replay, created = restored.admit("alice", "job", request_for())
                    assert not created and replay.status == "COMPLETED" and len(calls) == 3
                finally:
                    reopened.close()
            elif fault == "late_commit":
                # User-approved ACK/quarantine boundary, NOT the old durable-row guarantee.
                assert durable["status"] == "COMPLETED" and durable["slot"] == "HELD"
                assert not outcome.acknowledge_exit and outcome.code == "STORAGE_OUTCOME_UNKNOWN"
                assert time.monotonic() > deadline
                with pytest.raises(custody.InvestigationOutcomeUnknown):
                    svc.get("alice", "job", run.id)
                with pytest.raises(custody.InvestigationOutcomeUnknown):
                    svc.admit("alice", "job", request_for())
                with pytest.raises(custody.InvestigationOutcomeUnknown):
                    svc.store.claim("no-automatic-retry")
                reopened = SQLiteRepository(repo._path)
                try:
                    restored = service_for(reopened, None)
                    replay, created = restored.admit("alice", "job", request_for())
                    assert not created and replay.status == "COMPLETED"
                    assert restored.store.claim("no-inference-replay") is None
                    held = json.loads(
                        reopened.connection.execute(
                            "SELECT data FROM objects WHERE kind=? AND id=?",
                            ("ai_job_investigation_state_v1", run.id),
                        ).fetchone()[0]
                    )
                    assert held["slot"] == "HELD" and len(calls) == 3
                finally:
                    reopened.close()
            else:
                assert durable["status"] == "COMPLETED" and outcome.acknowledge_exit
        finally:
            repo.connection = connection
            repo.close()


@pytest.mark.parametrize("disappeared", [False, True])
def test_two_threads_same_null_intent_saved_winner(repo, monkeypatch, disappeared):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        svc = service_for(repo, gateway)
        entered, release = threading.Event(), threading.Event()
        original = repo.read_job_investigation_source
        first = [True]

        def read(*a, **kw):
            if first[0]:
                first[0] = False
                snapshot = original(*a, **kw)
                entered.set()
                assert release.wait(4)
                return original(*a, **kw) if disappeared else snapshot
            return original(*a, **kw)

        monkeypatch.setattr(repo, "read_job_investigation_source", read)
        with ThreadPoolExecutor(max_workers=1) as executor:
            contender = executor.submit(svc.admit, "alice", "job", request_for())
            try:
                assert entered.wait(3)
                repo.save_job(job([flow(domain="changed.example.test")]))
                winner, created = svc.admit("alice", "job", request_for())
                if disappeared:
                    repo.delete_job("job")
            finally:
                release.set()
            replay, replay_created = contender.result(timeout=4)
        assert created and not replay_created and replay == winner
        assert len(svc.page("alice", "job")) == 1 and not calls
        OBSERVATIONS[key(repo, "concurrent-null:" + str(disappeared))] = dict(
            same_id=replay.id == winner.id,
            source=replay.source.source_sha256,
            created=[created, replay_created],
        )


def test_source_preparation_gate_shared_across_ip_job(repo, monkeypatch):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        job_svc = service_for(repo, gateway)
        ip = InvestigationService(repo, custody.InvestigationRunStore(repo), gateway)
        snapshot = repo.read_investigation_source("job")
        ip_request = dict(
            target_ip="2001:db8::1",
            question="inspect",
            idempotency_key="ip",
            expected_source_sha256=snapshot.binding.source_sha256,
        )
        ready = [threading.Event(), threading.Event()]
        release = threading.Event()
        for index, name in enumerate(
            ["read_investigation_source", "read_job_investigation_source"]
        ):
            original = getattr(repo, name)

            def parked(*a, _index=index, _original=original, **kw):
                value = _original(*a, **kw)
                ready[_index].set()
                assert release.wait(4)
                return value

            monkeypatch.setattr(repo, name, parked)
        with ThreadPoolExecutor(max_workers=2) as ex:
            a = ex.submit(ip.admit, "ip-owner", "job", ip_request)
            b = ex.submit(job_svc.admit, "job-owner", "job", request_for("job"))
            try:
                assert all(e.wait(3) for e in ready)
                with pytest.raises(InvestigationError, match="SOURCE_BUSY"):
                    job_svc.admit("third", "job", request_for("third"))
            finally:
                release.set()
            assert a.result(timeout=4)[1] and b.result(timeout=4)[1]
        assert calls == []
        OBSERVATIONS[key(repo, "preparation-gate")] = dict(
            held_ip=ready[0].is_set(), held_job=ready[1].is_set(), third="SOURCE_BUSY"
        )


@pytest.mark.parametrize("callback", ["guard_read", "transport_reserve"])
def test_callback_storage_fault_does_not_repair_or_replay(repo, monkeypatch, callback):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        svc = service_for(repo, gateway)
        run, _ = svc.admit("alice", "job", request_for())
        claim = svc.store.claim("worker")
        fired = []
        original = svc.store.get if callback == "guard_read" else svc.store.reserve
        if callback == "guard_read":

            def failed(*a, **kw):
                # Only the provider callback context, not initial execution guard.
                import inspect

                if any(f.function == "should_cancel" for f in inspect.stack()):
                    fired.append("callback")
                    raise custody.InvestigationStorageError("closed internal canary")
                return original(*a, **kw)

            monkeypatch.setattr(svc.store, "get", failed)
        else:

            def failed(*a, **kw):
                if kw.get("transport_attempts"):
                    fired.append("callback")
                    raise custody.InvestigationStorageError("closed internal canary")
                return original(*a, **kw)

            monkeypatch.setattr(svc.store, "reserve", failed)
        outcome = svc.execute_claim(claim, deadline_monotonic=time.monotonic() + 10)
        row = svc.get("alice", "job", run.id)
        OBSERVATIONS[key(repo, callback)] = dict(
            fired=fired,
            outcome=outcome.code,
            ack=outcome.acknowledge_exit,
            status=row.status,
            calls=len(calls),
        )
        assert fired and outcome.code == "STORAGE_UNAVAILABLE" and not outcome.acknowledge_exit
        assert calls == [] and svc.store.claim("other") is None


def test_every_http_descendant_auth_owner_version_and_no_autopost(repo, monkeypatch):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        config = settings(
            ai_job_investigation_enabled=True,
            ai_investigation_inline_enabled=True,
            admin_token_sha256=hashlib.sha256(b"admin").hexdigest(),
        )
        config.api_auth_required = False
        app = create_app(config, repo, ai_gateway=configured(gateway))
        with TestClient(app) as client:
            assert (
                client.get(CAPS, headers=HEADERS).json()["dispatch_scope"]
                == "OWNED_CAPABLE_RUNTIME"
            )
            assert not calls and client.get(BASE, headers=HEADERS).json()["items"] == []
            response = client.post(BASE, headers=HEADERS, json=request_for())
            assert response.status_code == 202, response.text
            run = response.json()
            path = BASE + "/" + run["id"]
            wait_for(lambda: client.get(path, headers=HEADERS).json()["status"] == "COMPLETED")
            steps = client.get(path + "/steps", headers=HEADERS).json()["items"]
            evidence = next(s["evidence_id"] for s in steps if s["evidence_id"])
            routes = [
                ("GET", CAPS),
                ("GET", BASE),
                ("POST", BASE),
                ("GET", path),
                ("GET", path + "/steps"),
                ("GET", path + "/evidence/" + evidence),
                ("POST", path + "/cancel"),
                ("GET", path + "/unknown"),
            ]
            observed = []
            for method, url in routes:
                for token, expected in [(None, 401), ("viewer", 403)]:
                    headers = {} if token is None else {"Authorization": "Bearer " + token}
                    denied = client.request(method, url, headers=headers)
                    observed.append([method, url, token, denied.status_code])
                    assert denied.status_code == expected
            for suffix in ("", "/steps", "/evidence/" + evidence):
                assert (
                    client.get(path + suffix, headers={"Authorization": "Bearer admin"}).status_code
                    == 404
                )
                assert (
                    client.get(
                        (path + suffix).replace("/job/", "/foreign/"), headers=HEADERS
                    ).status_code
                    == 404
                )
            assert (
                client.post(path + "/cancel", headers={"Authorization": "Bearer admin"}).status_code
                == 404
            )
            assert (
                client.post(
                    BASE, headers=HEADERS, json=request_for("wrong", version="ip-investigation-v1")
                ).status_code
                == 422
            )
            assert (
                client.post(
                    BASE.replace("ai-job-investigations", "ai-investigations"),
                    headers=HEADERS,
                    json=request_for("wrong"),
                ).status_code
                == 422
            )
            assert client.get(path + "/unknown", headers=HEADERS).status_code == 404
            assert len(calls) == 3
            OBSERVATIONS[key(repo, "http-descendants")] = dict(
                checks=observed, model_calls=len(calls), source_before=run["source"]
            )
        assert app.state.investigation_drained


def pg_double():
    from c2hunter_controller.production import PostgresRepository
    from tests.test_ai_investigation_store import PostgresConnectionModel

    repo = PostgresRepository("not-used", None)
    conn = PostgresConnectionModel()
    conn.database.close()
    conn.database = sqlite3.connect(":memory:", check_same_thread=False)
    conn.database.execute(
        "CREATE TABLE controller_objects(kind TEXT,id TEXT,data TEXT,PRIMARY KEY(kind,id))"
    )
    repo._connection = conn
    return repo, conn


def pg_inline_contract(monkeypatch):
    repo, conn = pg_double()
    custody.initialize_investigation_store(repo)
    initialize_job_investigation_store(repo)
    monkeypatch.setattr(repo, "get_integration_settings", lambda: {})
    try:
        with scripted(monkeypatch, adaptive) as (gateway, calls):
            app = create_app(
                settings(
                    ai_job_investigation_enabled=True,
                    ai_investigation_inline_enabled=True,
                    redis_url="memory://",
                ),
                repo,
                ai_gateway=configured(gateway),
            )
            with TestClient(app) as client:
                runtime = app.state.investigation_runtime
                assert runtime.running and runtime.accepting
                assert app.state.job_investigation_service is not None
                caps = client.get(CAPS, headers=HEADERS)
                posted = client.post(BASE, headers=HEADERS, json=request_for())
                OBSERVATIONS["pg-inline-sql-double"] = dict(
                    caps=caps.json(),
                    post_status=posted.status_code,
                    post=posted.json(),
                    runtime_running=runtime.running,
                    attached_job_service=runtime.job_service is not None,
                    provider_calls=len(calls),
                    proof="actual app with SQL double; NOT live PostgreSQL",
                )
                assert caps.json()["dispatch_scope"] == "OWNED_CAPABLE_RUNTIME", (
                    "initialized PostgreSQL is excluded solely by repository class"
                )
    finally:
        conn.database.close()


def test_explicit_migration_initializes_job_marker(monkeypatch):
    from c2hunter_controller import migrate

    repo, conn = pg_double()
    monkeypatch.setattr(repo, "initialize_schema", lambda **kw: None)
    monkeypatch.setattr(migrate, "PostgresRepository", lambda *a, **kw: repo)
    monkeypatch.setenv("C2HUNTER_DATABASE_URL", "postgresql://offline/not-used")
    try:
        result = migrate.main([])
        kinds = [
            r[0] for r in conn.database.execute("SELECT kind FROM controller_objects ORDER BY kind")
        ]
        OBSERVATIONS["pg-migration-sql-double"] = dict(
            exit=result,
            markers=kinds,
            proof="real migrate.main; base schema setup stubbed; SQL double, no live PG",
        )
        assert result == 0
        assert "ai_job_investigation_schema" in kinds, (
            "successful explicit migration initializes only IP profile"
        )
    finally:
        conn.database.close()


def test_pg_inline_app_configuration_after_unrelated_queue_setup(monkeypatch):
    from c2hunter_controller.production import PostgresRepository

    monkeypatch.setattr(
        PostgresRepository,
        "count_pcap_export_jobs_by_status",
        lambda self: {"QUEUED": 0, "RUNNING": 0},
    )
    pg_inline_contract(monkeypatch)
