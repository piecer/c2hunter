"""Real PostgreSQL lifecycle regressions; opt in only with an owned test DSN."""

import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg.sql import SQL, Identifier

from c2hunter_controller.production import PostgresRepository


@pytest.fixture
def database():
    dsn = os.environ.get("C2H_TEST_OWNED_POSTGRES_DSN")
    if not dsn:
        pytest.skip("requires explicitly owned disposable PostgreSQL")
    schema = "lifecycle_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(SQL("CREATE SCHEMA {}").format(Identifier(schema)))
        scoped = make_conninfo(dsn, options=f"-csearch_path={schema},public")
        try:
            with psycopg.connect(scoped, autocommit=True) as control:
                yield scoped, control
        finally:
            admin.execute(SQL("DROP SCHEMA {} CASCADE").format(Identifier(schema)))


def repository(dsn):
    return PostgresRepository(dsn, SimpleNamespace(ready=lambda: True))


def test_explicit_initializer_is_idempotent_and_runtime_reconnect_is_readonly(database):
    dsn, control = database
    repo = repository(dsn)
    assert callable(getattr(repo, "initialize_schema", None)), "explicit initializer missing"
    repo.initialize_schema()
    assert repo._connection is None  # Migration owns a separate, closed connection.
    tables = control.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename"
    ).fetchall()
    repo.initialize_schema()
    assert (
        control.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename"
        ).fetchall()
        == tables
    )
    readonly = repository(
        make_conninfo(dsn, options=control.info.options + " -cdefault_transaction_read_only=on")
    )
    try:
        for _ in range(3):
            assert readonly.ready()
            assert readonly.connection.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
            readonly.close()
    finally:
        readonly.close()


@pytest.mark.parametrize("initial_state", ["fresh", "indexed", "legacy"])
def test_simultaneous_initializers_serialize_across_bootstrap_commit(
    database, monkeypatch, initial_state
):
    dsn, control = database
    if initial_state == "indexed":
        repository(dsn).initialize_schema()  # Already indexed and empty: original 40P01 case.
    elif initial_state == "legacy":
        seed_legacy(control)
    paused, release, second_try = threading.Event(), threading.Event(), threading.Event()
    outcomes, pids = {}, {}
    original = psycopg.connect

    class ScheduledCursor(psycopg.Cursor):
        def execute(self, query, *args, **kwargs):
            name = threading.current_thread().name
            if (
                name == "migration-A"
                and isinstance(query, str)
                and query.startswith("INSERT INTO candidate_records(")
            ):
                paused.set()
                assert release.wait(8)
            if name == "migration-B" and "pg_try_advisory_lock" in str(query):
                second_try.set()
            return super().execute(query, *args, **kwargs)

    def connect(*args, **kwargs):
        conn = original(*args, cursor_factory=ScheduledCursor, **kwargs)
        pids[threading.current_thread().name] = conn.info.backend_pid
        return conn

    def migrate():
        try:
            repository(dsn).initialize_schema()
            outcomes[threading.current_thread().name] = "success"
        except Exception as exc:
            outcomes[threading.current_thread().name] = getattr(exc, "sqlstate", repr(exc))

    monkeypatch.setattr(psycopg, "connect", connect)
    a = threading.Thread(target=migrate, name="migration-A")
    b = threading.Thread(target=migrate, name="migration-B")
    try:
        a.start()
        assert paused.wait(8)
        b.start()
        deadline = time.monotonic() + 5
        while not second_try.is_set():
            if control.execute(
                "SELECT 1 FROM pg_locks WHERE pid=%s AND NOT granted",
                (pids.get("migration-B", 0),),
            ).fetchone():
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
    finally:
        release.set()
        a.join(15)
        if b.ident is not None:
            b.join(15)
    assert not a.is_alive() and not b.is_alive()
    assert outcomes == {"migration-A": "success", "migration-B": "success"}
    check = repository(dsn)
    try:
        assert check.database_ready()
    finally:
        check.close()
    if initial_state == "legacy":
        assert control.execute("SELECT candidate_id,score FROM candidate_records").fetchall() == [
            ("legacy-candidate", 42)
        ]
        assert control.execute("SELECT count(*) FROM job_candidates").fetchone() == (0,)


@pytest.mark.parametrize(
    "damage",
    [
        "DELETE FROM controller_schema_version",
        "UPDATE controller_schema_version SET version=999",
        "INSERT INTO controller_schema_version VALUES (1)",
        "ALTER TABLE controller_schema_version RENAME COLUMN version TO broken",
        "DROP TABLE job_idempotency",
        "ALTER TABLE candidate_records ALTER COLUMN score TYPE bigint",
        "ALTER TABLE candidate_records ALTER COLUMN score SET DEFAULT 999",
        "ALTER TABLE job_idempotency DROP CONSTRAINT job_idempotency_pkey",
        "ALTER TABLE ai_analysis_runs DISABLE TRIGGER ai_runs_hist_owner_update",
    ],
)
def test_schema_damage_is_refused_on_cached_and_new_health(database, damage):
    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    try:
        assert repo.ready()
        control.execute(damage)
        assert repo.ready() is False
        repo.close()
        assert repo.ready() is False
        assert repo._connection is None
        from c2hunter_controller.api_errors import ApiError
        from c2hunter_controller.historical_ai_http import domain_errors

        with pytest.raises(ApiError) as raised, domain_errors():
            repo.get_ai_run("missing")
        assert raised.value.status == 503
        assert raised.value.code == "BASELINE_STORAGE_UNAVAILABLE"
    finally:
        repo.close()


def test_initializer_lock_timeout_is_bounded_and_does_not_publish(database):
    dsn, control = database
    control.execute("SELECT pg_advisory_lock(2026081301)")
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="migration lock timed out"):
            repository(dsn).initialize_schema(lock_timeout_seconds=0.1)
        assert time.monotonic() - started < 2
        assert control.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname=current_schema()"
        ).fetchone() == (0,)
    finally:
        control.execute("SELECT pg_advisory_unlock(2026081301)")
    repository(dsn).initialize_schema(lock_timeout_seconds=1)


def test_migration_refuses_unknown_version_without_erasing_it(database):
    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    control.execute("UPDATE controller_schema_version SET version=999")
    from c2hunter_controller.postgres_schema import SchemaNotReady

    with pytest.raises(SchemaNotReady, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.initialize_schema()
    assert control.execute("SELECT version FROM controller_schema_version").fetchall() == [(999,)]


def test_migration_cli_and_compose_prerequisite(database):
    dsn, _ = database
    env = dict(os.environ, C2HUNTER_DATABASE_URL=dsn)
    run = subprocess.run(
        [sys.executable, "-B", "-m", "c2hunter_controller.migrate", "--lock-timeout", "1"],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert run.returncode == 0, run.stderr
    assert "schema ready" in run.stdout
    assert dsn not in run.stdout + run.stderr
    text = (Path(__file__).parents[2] / "docker-compose.yml").read_text()
    migration = text.split("  postgres-migrate:\n", 1)[1].split("\n  controller:", 1)[0]
    assert "command: [python, -m, c2hunter_controller.migrate]" in migration
    assert 'restart: "no"' in migration
    for name in (
        "controller",
        "worker",
        "pcap-export-worker",
        "pcap-offset-index-worker",
        "ai-worker",
    ):
        # Service fields are four-space indented; split on next top-level service.
        import re

        section = re.split(r"\n  [a-z][a-z-]*:", text.split(f"  {name}:\n", 1)[1])[0]
        assert "postgres-migrate: { condition: service_completed_successfully }" in section


def seed_legacy(control):
    control.execute(
        "CREATE TABLE IF NOT EXISTS controller_objects(kind text NOT NULL,id text NOT NULL,"
        "data jsonb NOT NULL,PRIMARY KEY(kind,id));"
        "CREATE TABLE IF NOT EXISTS job_candidates(job_id text PRIMARY KEY,data jsonb NOT NULL)"
    )
    job = {
        "id": "legacy-job",
        "flow_records": [{"flow": "preserve"}],
        "payload_signatures": [{"signature": "preserve"}],
        "status": "COMPLETED",
    }
    candidates = [{"id": "legacy-candidate", "score": 42, "severity": "HIGH"}]
    from psycopg.types.json import Jsonb

    control.execute("INSERT INTO controller_objects VALUES ('job',%s,%s)", (job["id"], Jsonb(job)))
    control.execute("INSERT INTO job_candidates VALUES (%s,%s)", (job["id"], Jsonb(candidates)))
    return job, candidates


def test_nonempty_legacy_data_preserved_and_repeat_migration_is_idempotent(database):
    dsn, control = database
    job, candidates = seed_legacy(control)
    repo = repository(dsn)
    for _ in range(2):
        repo.initialize_schema()
        assert control.execute(
            "SELECT data FROM controller_objects WHERE kind='job'"
        ).fetchone() == ({"id": job["id"], "status": "COMPLETED"},)
        assert control.execute("SELECT data FROM job_flow_record_chunks").fetchall() == [
            (job["flow_records"],)
        ]
        assert control.execute("SELECT data FROM job_payload_signatures").fetchall() == [
            (job["payload_signatures"],)
        ]
        assert control.execute("SELECT data FROM candidate_records").fetchall() == [
            (candidates[0],)
        ]
        assert control.execute("SELECT count(*) FROM job_candidates").fetchone() == (0,)
        assert control.execute("SELECT count(*) FROM audit_events").fetchone() == (0,)


@pytest.mark.parametrize("phase", ["legacy", "historical"])
def test_failure_rolls_back_owned_phase_and_never_publishes_readiness(database, monkeypatch, phase):
    from c2hunter_controller import historical_ai_sql

    dsn, control = database
    job, candidates = seed_legacy(control)
    repo = repository(dsn)
    failure = RuntimeError("injected migration refusal")
    fired = []
    if phase == "legacy":
        target, name = PostgresRepository, "_migrate_legacy_candidates"
    else:
        target, name = historical_ai_sql, "initialize_postgres"
    original = getattr(target, name)

    def fail(*args):
        fired.append(True)
        raise failure

    with monkeypatch.context() as m:
        m.setattr(target, name, staticmethod(fail) if phase == "legacy" else fail)
        with pytest.raises(RuntimeError) as raised:
            repo.initialize_schema()
        assert raised.value is failure and fired == [True]
    assert control.execute("SELECT version FROM controller_schema_version").fetchall() == []
    assert repo.database_ready() is False and repo._connection is None
    if phase == "legacy":
        assert control.execute("SELECT data FROM controller_objects").fetchone() == (job,)
        assert control.execute("SELECT data FROM job_candidates").fetchone() == (candidates,)
        assert control.execute("SELECT count(*) FROM job_flow_record_chunks").fetchone() == (0,)
    assert getattr(target, name) is original
    repo.initialize_schema(lock_timeout_seconds=1)  # Failed owner released its session lock.
    assert repo.database_ready()
    repo.close()


def test_readonly_unprivileged_health_and_worker_cli_during_writer_transaction(
    database, monkeypatch
):
    from urllib.parse import quote, urlencode

    from psycopg.conninfo import conninfo_to_dict

    from c2hunter_controller import pcap_export_worker, pcap_offset_index_worker

    dsn, control = database
    repository(dsn).initialize_schema()
    job, candidates = seed_legacy(control)
    role = "reader_" + uuid.uuid4().hex
    schema = control.execute("SELECT current_schema()").fetchone()[0]
    control.execute(SQL("CREATE ROLE {} LOGIN").format(Identifier(role)))
    try:
        control.execute(
            SQL("GRANT USAGE ON SCHEMA {} TO {}").format(Identifier(schema), Identifier(role))
        )
        control.execute(
            SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}").format(
                Identifier(schema), Identifier(role)
            )
        )
        params = conninfo_to_dict(dsn)
        params.update(user=role, options=params["options"] + " -cdefault_transaction_read_only=on")
        readonly_dsn = "postgresql:///?" + urlencode(params, quote_via=quote)
        reader = repository(readonly_dsn)
        with psycopg.connect(dsn) as writer:
            writer.execute("INSERT INTO controller_objects VALUES ('probe','write','{}')")
            try:
                for _ in range(3):
                    assert reader.ready()
                    borrowed = reader.for_background_worker()
                    assert borrowed.ready()
                    borrowed.close()
                    reader.close()
                with psycopg.connect(readonly_dsn) as denied:
                    assert denied.execute("SHOW transaction_read_only").fetchone() == ("on",)
                    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
                        denied.execute("CREATE TABLE forbidden_ddl(id integer)")
                with psycopg.connect(make_conninfo(dsn, user=role)) as denied:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        denied.execute("CREATE TABLE forbidden_ddl(id integer)")
                for module in (pcap_export_worker, pcap_offset_index_worker):
                    settings = SimpleNamespace(
                        database_url=readonly_dsn,
                        s3_endpoint="unused",
                        s3_access_key="",
                        s3_secret_key="",
                        s3_bucket="unused",
                    )
                    monkeypatch.setattr(module, "Settings", lambda settings=settings: settings)
                    monkeypatch.setattr(
                        module, "MinioBlobStore", lambda *args: SimpleNamespace(ready=lambda: True)
                    )
                    assert module.main(["healthcheck"]) == 0
            finally:
                reader.close()
            writer.rollback()
        assert control.execute(
            "SELECT data FROM controller_objects WHERE kind='job'"
        ).fetchone() == (job,)
        assert control.execute("SELECT data FROM job_candidates").fetchone() == (candidates,)
        assert control.execute("SELECT count(*) FROM job_flow_record_chunks").fetchone() == (0,)
    finally:
        control.execute(SQL("DROP OWNED BY {}").format(Identifier(role)))
        control.execute(SQL("DROP ROLE {}").format(Identifier(role)))


@pytest.mark.parametrize("parent_action", ["delete", "replace"])
def test_initializer_releases_ddl_before_parent_fence_and_rereads_legacy(
    database, monkeypatch, parent_action
):
    from psycopg.types.json import Jsonb

    dsn, control = database
    repository(dsn).initialize_schema()
    seed_legacy(control)
    paused, release = threading.Event(), threading.Event()
    original = psycopg.connect
    pids, outcome = [], []
    replacement = [{"id": "replacement-candidate", "score": 73}]

    class FenceCursor(psycopg.Cursor):
        def execute(self, query, *args, **kwargs):
            if threading.current_thread().name == "parent-migration" and str(query).startswith(
                "SELECT id FROM controller_objects WHERE kind='job'"
            ):
                paused.set()
                assert release.wait(8)
            return super().execute(query, *args, **kwargs)

    def connect(*args, **kwargs):
        connection = original(*args, cursor_factory=FenceCursor, **kwargs)
        pids.append(connection.info.backend_pid)
        return connection

    def migrate():
        try:
            repository(dsn).initialize_schema()
            outcome.append("success")
        except Exception as exc:
            outcome.append(repr(exc))

    with original(dsn) as parent:
        monkeypatch.setattr(psycopg, "connect", connect)
        thread = threading.Thread(target=migrate, name="parent-migration")
        try:
            thread.start()
            assert paused.wait(8)
            parent.execute("SELECT id FROM controller_objects WHERE kind='job' FOR UPDATE")
            release.set()
            deadline = time.monotonic() + 5
            while not control.execute(
                "SELECT 1 FROM pg_locks WHERE pid=%s AND NOT granted", (pids[0],)
            ).fetchone():
                assert time.monotonic() < deadline
                time.sleep(0.01)
            if parent_action == "delete":
                parent.execute("DELETE FROM job_candidates")
                parent.execute("DELETE FROM controller_objects WHERE kind='job'")
            else:
                parent.execute("UPDATE job_candidates SET data=%s", (Jsonb(replacement),))
            parent.commit()
        finally:
            parent.rollback()
            release.set()
            thread.join(15)
        assert not thread.is_alive() and outcome == ["success"]
    assert control.execute("SELECT data FROM candidate_records").fetchall() == (
        [] if parent_action == "delete" else [(replacement[0],)]
    )
    if parent_action == "delete":
        assert control.execute("SELECT count(*) FROM job_flow_record_chunks").fetchone() == (0,)


def test_readiness_never_finishes_borrowed_transaction(database):
    dsn, _ = database
    repo = repository(dsn)
    repo.initialize_schema()
    conn = repo.connection
    conn.execute("INSERT INTO controller_objects VALUES ('probe','borrowed','{}')")
    assert repo.database_ready() is False
    assert conn.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS
    conn.rollback()
    assert repo.database_ready()
    repo.close()


def test_runtime_refuses_uninitialized_database_without_creating_schema(database):
    dsn, control = database
    repo = repository(dsn)
    try:
        assert repo.database_ready() is False
        assert control.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname=current_schema()"
        ).fetchone() == (0,)
        assert repo._connection is None
    finally:
        repo.close()
