from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest

from c2hunter_controller.pcap_export_queue import (
    ExportPrincipalLimitError,
    ExportQueueFullError,
    ExportQueueStorageError,
    ExportSourceChangedError,
)
from c2hunter_controller.production import MinioBlobStore, PostgresRepository
from c2hunter_controller.repositories import ArtifactStorageError


@dataclass
class Step:
    sql: str
    rows: list[Any] | None = None
    rowcount: int = 1
    error: Exception | None = None


class MatrixCursor:
    def __init__(self, connection: MatrixConnection) -> None:
        self.connection = connection
        self.rows: list[Any] = []
        self.rowcount = 0

    def __enter__(self) -> MatrixCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: Any = None) -> None:
        self.connection.calls.append((query, params))
        assert self.connection.steps, f"unexpected SQL: {query}"
        step = self.connection.steps.pop(0)
        assert step.sql in " ".join(query.split()), query
        if step.error is not None:
            raise step.error
        self.rows = list(step.rows or [])
        self.rowcount = step.rowcount

    def fetchone(self) -> Any:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[Any]:
        rows, self.rows = self.rows, []
        return rows


class MatrixConnection:
    def __init__(
        self, *steps: Step, fail_commit: bool = False, fail_rollback: bool = False
    ) -> None:
        self.steps = list(steps)
        self.calls: list[tuple[str, Any]] = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self.autocommit = False
        self.fail_commit = fail_commit
        self.fail_rollback = fail_rollback

    def cursor(self) -> MatrixCursor:
        return MatrixCursor(self)

    def commit(self) -> None:
        self.commits += 1
        if self.fail_commit:
            raise RuntimeError("private commit outage")

    def rollback(self) -> None:
        self.rollbacks += 1
        if self.fail_rollback:
            raise RuntimeError("private rollback outage")

    def close(self) -> None:
        self.closed = True


def repository(
    connection: MatrixConnection, deleted: list[str] | None = None
) -> PostgresRepository:
    removed = deleted if deleted is not None else []
    result = PostgresRepository(
        "postgresql://matrix.invalid/controller",
        cast(MinioBlobStore, SimpleNamespace(delete=removed.append)),
    )
    result._connection = connection
    return result


def job(
    export_id: str = "export-1", *, key: str | None = "key", fingerprint: str = "fp"
) -> dict[str, Any]:
    now = datetime(2026, 8, 24, tzinfo=UTC).isoformat()
    return {
        "id": export_id,
        "principal_scope": "analyst",
        "idempotency_key": key,
        "request_fingerprint": fingerprint,
        "coalesce_fingerprint": fingerprint,
        "job_id": "analysis-1",
        "source_job_id": "source-1",
        "source_generation": "a" * 64,
        "status": "QUEUED",
        "attempt": 0,
        "max_attempts": 3,
        "queued_at": now,
        "next_attempt_at": now,
        "progress": {"phase": "QUEUED", "percent": 0},
    }


def row(value: dict[str, Any]) -> tuple[str]:
    return (json.dumps(value),)


def test_postgres_migration_creates_durable_queue_and_indexes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = MatrixConnection(Step("CREATE TABLE IF NOT EXISTS controller_objects"))
    repo = PostgresRepository(
        "postgresql://matrix.invalid/controller", cast(MinioBlobStore, SimpleNamespace())
    )
    monkeypatch.setattr("psycopg.connect", lambda *_args, **_kwargs: connection)
    monkeypatch.setattr(repo, "_ensure_candidate_query_indexes", lambda _connection: None)

    assert repo.connection is connection
    migration = connection.calls[0][0]
    assert "CREATE TABLE IF NOT EXISTS pcap_export_jobs" in migration
    assert "pcap_export_jobs_principal_idempotency" in migration
    assert "pcap_export_jobs_reusable_coalesce" in migration
    assert "pcap_export_jobs_claim" in migration
    assert connection.commits == 1


def test_postgres_enqueue_replay_conflict_and_coalesce_precede_full_capacity() -> None:
    original = job()
    replay_connection = MatrixConnection(
        Step("pg_advisory_xact_lock"),
        Step("idempotency_key=%s FOR UPDATE", [row(original)]),
    )
    replay, created = repository(replay_connection).enqueue_pcap_export_job(
        job("replay"), capacity=0, per_principal_limit=0
    )
    assert replay["id"] == "export-1" and created is False

    conflict_connection = MatrixConnection(
        Step("pg_advisory_xact_lock"),
        Step("idempotency_key=%s FOR UPDATE", [row(original)]),
    )
    with pytest.raises(ValueError, match="idempotency_conflict"):
        repository(conflict_connection).enqueue_pcap_export_job(
            job("conflict", fingerprint="different"), capacity=0, per_principal_limit=0
        )
    assert conflict_connection.rollbacks == 1

    coalesce_connection = MatrixConnection(
        Step("pg_advisory_xact_lock"),
        Step("idempotency_key=%s FOR UPDATE"),
        Step("coalesce_fingerprint=%s", [row(original)]),
    )
    coalesced, created = repository(coalesce_connection).enqueue_pcap_export_job(
        job("coalesce"), capacity=0, per_principal_limit=0
    )
    assert coalesced["id"] == "export-1" and created is False


@pytest.mark.parametrize(
    ("counts", "capacity", "principal_limit", "error"),
    [
        ((2, 0), 2, 2, ExportQueueFullError),
        ((1, 1), 2, 1, ExportPrincipalLimitError),
    ],
)
def test_postgres_enqueue_applies_global_and_principal_caps(
    counts: tuple[int, int], capacity: int, principal_limit: int, error: type[Exception]
) -> None:
    connection = MatrixConnection(
        Step("pg_advisory_xact_lock"),
        Step("coalesce_fingerprint=%s"),
        Step("SELECT COUNT(*)", [counts]),
    )
    with pytest.raises(error):
        repository(connection).enqueue_pcap_export_job(
            job(key=None), capacity=capacity, per_principal_limit=principal_limit
        )
    assert connection.rollbacks == 1


def test_postgres_enqueue_serializes_admission_without_locking_aggregate() -> None:
    connection = MatrixConnection(
        Step("pg_advisory_xact_lock"),
        Step("coalesce_fingerprint=%s"),
        Step("SELECT COUNT(*)", [(0, 0)]),
        Step("INSERT INTO pcap_export_jobs", rowcount=1),
    )
    stored, created = repository(connection).enqueue_pcap_export_job(
        job(key=None), capacity=1, per_principal_limit=1
    )
    assert created is True and stored["id"] == "export-1"
    assert "FOR UPDATE" not in connection.calls[2][0]


def test_postgres_enqueue_revalidates_and_locks_source_before_insert() -> None:
    source = {"id": "analysis-1", "status": "COMPLETED"}
    generation_document = {
        "source_job_id": "analysis-1",
        "provenance_job_ids": ["analysis-1"],
        "source_manifest": [],
        "source_total_bytes": None,
        "source_packet_count": None,
    }
    generation = hashlib.sha256(
        json.dumps(generation_document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    queued = {
        **job(key=None),
        "source_job_id": "analysis-1",
        "source_generation": generation,
        "source_manifest": [],
        "canonical_request": {"job_id": "analysis-1"},
        "effective_limits": {},
        "status": "RUNNING",
        "attempt": 1,
        "lease_token": "sync:export-1",
        "lease_expires_at": "2026-08-24T00:30:00+00:00",
    }
    connection = MatrixConnection(
        Step("pg_advisory_xact_lock"),
        Step("coalesce_fingerprint=%s"),
        Step("SELECT COUNT(*)", [(0, 0)]),
        Step("kind='job' AND id=%s FOR UPDATE", [row(source)]),
        Step("kind='sensor_pcap'", []),
        Step("INSERT INTO pcap_export_jobs", rowcount=1),
    )

    stored, created = repository(connection).enqueue_pcap_export_job(
        queued, capacity=1, per_principal_limit=1
    )

    assert created is True and stored["source_generation"] == generation
    assert "FOR UPDATE" in connection.calls[3][0]
    insert_sql, insert_params = connection.calls[5]
    assert "lease_token,lease_expires_at" in insert_sql
    assert insert_params[9] == 1
    assert insert_params[10:12] == (
        "sync:export-1",
        "2026-08-24T00:30:00+00:00",
    )

    deleted_connection = MatrixConnection(
        Step("pg_advisory_xact_lock"),
        Step("coalesce_fingerprint=%s"),
        Step("SELECT COUNT(*)", [(0, 0)]),
        Step("kind='job' AND id=%s FOR UPDATE", []),
    )
    with pytest.raises(ExportSourceChangedError):
        repository(deleted_connection).enqueue_pcap_export_job(
            queued, capacity=1, per_principal_limit=1
        )
    assert deleted_connection.rollbacks == 1


def test_postgres_claim_uses_skip_locked_and_attempt_token_cas_updates() -> None:
    queued = job()
    claim_connection = MatrixConnection(
        Step("FOR UPDATE SKIP LOCKED LIMIT 1", [(queued["id"], json.dumps(queued))]),
        Step("WHERE export_id=%s AND status='QUEUED'", rowcount=1),
    )
    claimed = repository(claim_connection).claim_pcap_export_job(
        now=datetime(2026, 8, 24, tzinfo=UTC), lease_seconds=120
    )
    assert claimed is not None and claimed["status"] == "RUNNING" and claimed["attempt"] == 1
    assert isinstance(claimed["lease_token"], str) and claimed["lease_token"]

    running = dict(claimed)
    progress_connection = MatrixConnection(
        Step("WHERE export_id=%s FOR UPDATE", [row(running)]),
        Step("AND attempt=%s AND lease_token=%s", rowcount=1),
    )
    assert repository(progress_connection).progress_pcap_export_job(
        queued["id"],
        attempt=1,
        lease_token=claimed["lease_token"],
        progress={"percent": 140, "scanned_packet_count": 7, "unbounded": 99},
    )
    saved = json.loads(progress_connection.calls[1][1][6])
    assert saved["progress"]["percent"] == 99
    assert saved["progress"]["scanned_packet_count"] == 7
    assert "unbounded" not in saved["progress"]

    stale_connection = MatrixConnection(Step("WHERE export_id=%s FOR UPDATE", [row(running)]))
    assert not repository(stale_connection).heartbeat_pcap_export_job(
        queued["id"], attempt=1, lease_token="stale", lease_seconds=120
    )
    assert stale_connection.commits == 1


def test_postgres_cancellation_completion_race_keeps_cancelled_winner_sticky() -> None:
    running = {**job(), "status": "RUNNING", "attempt": 1, "lease_token": "token"}
    cancel_connection = MatrixConnection(
        Step("WHERE export_id=%s FOR UPDATE", [row(running)]),
        Step("status IN ('QUEUED','RUNNING')", rowcount=1),
    )
    cancelled = repository(cancel_connection).cancel_pcap_export_job("export-1", reason="operator")
    assert cancelled["status"] == "RUNNING" and cancelled["cancellation_requested"] is True

    completion_connection = MatrixConnection(
        Step("WHERE export_id=%s FOR UPDATE", [row(cancelled)]),
        Step("AND attempt=%s AND lease_token=%s", rowcount=1),
    )
    assert not repository(completion_connection).complete_pcap_export_job(
        "export-1", attempt=1, lease_token="token", artifact={"sha256": "b" * 64}
    )
    saved = json.loads(completion_connection.calls[1][1][6])
    assert saved["status"] == "CANCELLED"
    assert "sha256" not in saved


def test_postgres_completion_consumes_staged_cleanup_intent_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running = {
        **job(),
        "status": "RUNNING",
        "attempt": 1,
        "lease_token": "token",
        "source_generation": "generation",
        "source_manifest": [{"id": "source"}],
    }
    object_key = "exports/export-1/winner.pcap"
    artifact = {
        "id": "export-1",
        "status": "COMPLETED",
        "published": False,
        "attempt": 1,
        "lease_token": "token",
        "object_key": object_key,
        "size_bytes": 3,
        "sha256": hashlib.sha256(b"abc").hexdigest(),
    }
    cleanup_id = PostgresRepository._pcap_cleanup_id("publication:export-1", object_key)
    monkeypatch.setattr(
        "c2hunter_controller.production._pcap_export_snapshot",
        lambda *_args, **_kwargs: {
            "source_generation": "generation",
            "source_manifest": [{"id": "source"}],
        },
    )
    connection = MatrixConnection(
        Step("WHERE export_id=%s FOR UPDATE", [row(running)]),
        Step("kind='job' AND id=%s FOR UPDATE", [(1,)]),
        Step("kind='export' AND id=%s FOR UPDATE", [(json.dumps(artifact),)]),
        Step(
            "kind='pcap_export_cleanup' AND data->>'object_key'=%s FOR UPDATE",
            [(cleanup_id, json.dumps({"object_key": object_key, "state": "STAGED"}))],
        ),
        Step("UPDATE controller_objects SET data=%s::jsonb", rowcount=1),
        Step("data->>'state'='STAGED'", rowcount=1),
        Step("AND attempt=%s AND lease_token=%s", rowcount=1),
    )

    assert repository(connection).complete_pcap_export_job(
        "export-1", attempt=1, lease_token="token", artifact=dict(artifact)
    )
    assert connection.calls[3][1] == (object_key,)
    assert connection.calls[5][1] == (cleanup_id, object_key)
    assert connection.commits == 1

    duplicate_connection = MatrixConnection(
        Step("WHERE export_id=%s FOR UPDATE", [row(running)]),
        Step("kind='job' AND id=%s FOR UPDATE", [(1,)]),
        Step("kind='export' AND id=%s FOR UPDATE", [(json.dumps(artifact),)]),
        Step(
            "kind='pcap_export_cleanup' AND data->>'object_key'=%s FOR UPDATE",
            [
                (cleanup_id, json.dumps({"object_key": object_key, "state": "STAGED"})),
                ("duplicate", json.dumps({"object_key": object_key, "state": "DELETING"})),
            ],
        ),
    )
    assert not repository(duplicate_connection).complete_pcap_export_job(
        "export-1", attempt=1, lease_token="token", artifact=dict(artifact)
    )
    assert duplicate_connection.commits == 1


def test_postgres_unsuccessful_completion_preserves_artifact_failure() -> None:
    running = {**job(), "status": "RUNNING", "attempt": 1, "lease_token": "token"}
    connection = MatrixConnection(
        Step("WHERE export_id=%s FOR UPDATE", [row(running)]),
        Step("AND attempt=%s AND lease_token=%s", rowcount=1),
    )
    assert repository(connection).complete_pcap_export_job(
        "export-1",
        attempt=1,
        lease_token="token",
        artifact={
            "status": "FAILED",
            "error_code": "PCAP_NO_MATCH",
            "error": "No packets matched",
            "matched_packet_count": 0,
            "published": True,
        },
    )
    saved = json.loads(connection.calls[1][1][6])
    assert saved["status"] == "FAILED"
    assert saved["error_code"] == "PCAP_NO_MATCH"
    assert saved["progress"]["percent"] < 100


def test_postgres_shared_facade_serializes_complete_transactions() -> None:
    class ConcurrentConnection(MatrixConnection):
        def __init__(self) -> None:
            super().__init__(
                Step("SELECT data FROM pcap_export_jobs", [row(job())]),
                Step("SELECT status,COUNT(*)", [("QUEUED", 1)]),
            )
            self.owner: int | None = None
            self.interleaved = False
            self.first_cursor = threading.Event()
            self.release_first = threading.Event()
            self.cursor_count = 0

        def cursor(self) -> MatrixCursor:
            ident = threading.get_ident()
            if self.owner not in {None, ident}:
                self.interleaved = True
            self.owner = ident
            self.cursor_count += 1
            if self.cursor_count == 1:
                self.first_cursor.set()
                assert self.release_first.wait(5)
            return super().cursor()

        def commit(self) -> None:
            super().commit()
            self.owner = None

        def rollback(self) -> None:
            super().rollback()
            self.owner = None

    connection = ConcurrentConnection()
    repo = repository(connection)
    errors: list[BaseException] = []

    def invoke(operation: Any) -> None:
        try:
            operation()
        except BaseException as exc:
            errors.append(exc)

    first = threading.Thread(target=invoke, args=(lambda: repo.get_pcap_export_job("export-1"),))
    second = threading.Thread(target=invoke, args=(repo.count_pcap_export_jobs_by_status,))
    first.start()
    assert connection.first_cursor.wait(5)
    second.start()
    connection.release_first.set()
    threads = [first, second]
    for thread in threads:
        thread.join()
    assert errors == []
    assert connection.interleaved is False


def test_postgres_retry_recovery_source_generation_and_parent_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running = {**job(), "status": "RUNNING", "attempt": 1, "lease_token": "token"}
    retry_connection = MatrixConnection(
        Step("WHERE export_id=%s FOR UPDATE", [row(running)]),
        Step("AND attempt=%s AND lease_token=%s", rowcount=1),
    )
    assert repository(retry_connection).retry_pcap_export_job(
        "export-1",
        attempt=1,
        lease_token="token",
        transient=True,
        error_code="PCAP_EXPORT_STORAGE_ERROR",
        error="temporary",
        retry_base_seconds=5,
    )
    assert json.loads(retry_connection.calls[1][1][6])["status"] == "QUEUED"

    expired = {
        **running,
        "attempt": 3,
        "max_attempts": 3,
        "lease_expires_at": "2026-08-23T00:00:00+00:00",
    }
    recovery_connection = MatrixConnection(
        Step("lease_expires_at<=%s FOR UPDATE SKIP LOCKED", [("export-1", json.dumps(expired))]),
        Step("WHERE export_id=%s AND status='RUNNING'", rowcount=1),
    )
    assert (
        repository(recovery_connection).recover_pcap_export_jobs(
            now=datetime(2026, 8, 24, tzinfo=UTC)
        )
        == 1
    )
    assert json.loads(recovery_connection.calls[1][1][3])["status"] == "FAILED"

    active_connection = MatrixConnection(Step("parent_job_id=%s", [(1,)]))
    assert repository(active_connection).has_active_pcap_exports("analysis-1") is True

    validation_repo = repository(MatrixConnection())
    snapshot = {
        "source_generation": "a" * 64,
        "source_manifest": [{"id": "s", "sha256": "b" * 64}],
    }
    monkeypatch.setattr(validation_repo, "snapshot_pcap_export_source", lambda *_args: snapshot)
    assert validation_repo.validate_pcap_export_source(
        {
            **job(),
            "canonical_request": {"job_id": "analysis-1"},
            "effective_limits": {},
            **snapshot,
        }
    )
    assert not validation_repo.validate_pcap_export_source(
        {
            **job(),
            "canonical_request": {"job_id": "analysis-1"},
            "effective_limits": {},
            "source_generation": "c" * 64,
            "source_manifest": snapshot["source_manifest"],
        }
    )


def test_postgres_guarded_compensation_and_bounded_orphan_cleanup() -> None:
    deleted: list[str] = []
    winner_connection = MatrixConnection(
        Step("data->>'object_key' FROM pcap_export_jobs", [("exports/winner.pcap",)]),
        Step("kind='pcap_export_cleanup' AND data->>'object_key'=%s", [("stale",)]),
        Step("kind='pcap_export_cleanup' AND data->>'object_key'=%s"),
    )
    repository(winner_connection, deleted).compensate_pcap_export_artifact(
        "export-1",
        attempt=1,
        lease_token="token",
        artifact={"object_key": "exports/winner.pcap"},
    )
    assert deleted == []
    assert winner_connection.calls[2][1] == ("exports/winner.pcap",)

    loser_connection = MatrixConnection(
        Step("data->>'object_key' FROM pcap_export_jobs"),
        Step("kind='pcap_export_cleanup' AND data->>'object_key'=%s", [("canonical",)]),
        Step("DELETE FROM controller_objects", rowcount=1),
        Step("kind='pcap_export_cleanup' AND data->>'object_key'=%s AND id<>%s"),
        Step("VALUES('pcap_export_cleanup'"),
        Step("kind='pcap_export_cleanup' AND id=%s", rowcount=1),
    )
    repository(loser_connection, deleted).compensate_pcap_export_artifact(
        "export-1",
        attempt=1,
        lease_token="token",
        artifact={"object_key": "exports/attempt-loser.pcap"},
    )
    assert deleted == ["exports/attempt-loser.pcap"]
    assert loser_connection.commits == 2
    publication_cleanup_id = PostgresRepository._pcap_cleanup_id(
        "publication:export-1", "exports/attempt-loser.pcap"
    )
    assert loser_connection.calls[1][1] == ("exports/attempt-loser.pcap",)
    assert loser_connection.calls[3][1] == (
        "exports/attempt-loser.pcap",
        publication_cleanup_id,
    )
    assert loser_connection.calls[5][1] == (
        publication_cleanup_id,
        "exports/attempt-loser.pcap",
    )

    def fail_delete(object_key: str) -> None:
        assert object_key == "exports/failed-compensation.pcap"
        raise RuntimeError("forced compensation delete outage")

    failed_connection = MatrixConnection(
        Step("data->>'object_key' FROM pcap_export_jobs"),
        Step("kind='pcap_export_cleanup' AND data->>'object_key'=%s", [("canonical",)]),
        Step("DELETE FROM controller_objects", rowcount=1),
        Step("kind='pcap_export_cleanup' AND data->>'object_key'=%s AND id<>%s"),
        Step("VALUES('pcap_export_cleanup'"),
    )
    failed_repository = PostgresRepository(
        "postgresql://matrix.invalid/controller",
        cast(MinioBlobStore, SimpleNamespace(delete=fail_delete)),
    )
    failed_repository._connection = failed_connection
    with pytest.raises(ExportQueueStorageError, match="compensation failed"):
        failed_repository.compensate_pcap_export_artifact(
            "export-1",
            attempt=1,
            lease_token="token",
            artifact={"object_key": "exports/failed-compensation.pcap"},
        )
    failed_cleanup_id = PostgresRepository._pcap_cleanup_id(
        "publication:export-1", "exports/failed-compensation.pcap"
    )
    assert failed_connection.calls[3][1] == (
        "exports/failed-compensation.pcap",
        failed_cleanup_id,
    )
    assert failed_connection.calls[4][1][0] == failed_cleanup_id
    assert json.loads(failed_connection.calls[4][1][1])["state"] == "READY"
    assert failed_connection.commits == 1

    duplicate_only_connection = MatrixConnection(
        Step("data->>'object_key' FROM pcap_export_jobs"),
        Step("kind='pcap_export_cleanup' AND data->>'object_key'=%s", [("attempt-cleanup",)]),
        Step("DELETE FROM controller_objects", rowcount=0),
        Step("kind='pcap_export_cleanup' AND data->>'object_key'=%s AND id<>%s"),
        Step("VALUES('pcap_export_cleanup'"),
        Step("kind='pcap_export_cleanup' AND id=%s", rowcount=1),
    )
    repository(duplicate_only_connection, deleted).compensate_pcap_export_artifact(
        "export-1",
        attempt=1,
        lease_token="token",
        artifact={"object_key": "exports/duplicate-only.pcap"},
    )
    duplicate_cleanup_id = PostgresRepository._pcap_cleanup_id(
        "publication:export-1", "exports/duplicate-only.pcap"
    )
    assert deleted[-1] == "exports/duplicate-only.pcap"
    assert duplicate_only_connection.calls[3][1] == (
        "exports/duplicate-only.pcap",
        duplicate_cleanup_id,
    )
    assert duplicate_only_connection.calls[5][1] == (
        duplicate_cleanup_id,
        "exports/duplicate-only.pcap",
    )

    orphan_connection = MatrixConnection(
        Step("kind='pcap_export_cleanup'"),
        Step("FOR UPDATE SKIP LOCKED LIMIT %s", [("loser", "exports/loser.pcap")]),
        Step("VALUES('pcap_export_cleanup'"),
        Step("data->>'published'='false'", rowcount=1),
        Step("kind='pcap_export_cleanup' AND id=%s", rowcount=1),
    )
    removed = repository(orphan_connection, deleted).cleanup_pcap_export_orphans(
        now=datetime(2026, 8, 24, tzinfo=UTC), max_age_seconds=60, limit=1
    )
    assert removed == ["exports/loser.pcap"]
    assert deleted == [
        "exports/attempt-loser.pcap",
        "exports/duplicate-only.pcap",
        "exports/loser.pcap",
    ]
    assert orphan_connection.calls[1][1][1] == 1
    assert "active.status='RUNNING'" in orphan_connection.calls[0][0]
    assert "published.status='COMPLETED'" in orphan_connection.calls[0][0]


def test_postgres_cleanup_ids_and_acknowledgements_are_bound_to_object_keys() -> None:
    stale_key = "exports/export-1/stale-attempt.pcap"
    completed_key = "exports/export-1/completed.pcap"

    def fail_stale_delete(object_key: str) -> None:
        assert object_key == stale_key
        raise RuntimeError("forced stale-attempt cleanup outage")

    stale_connection = MatrixConnection(
        Step("kind='pcap_export_cleanup'", [("export-1", stale_key)]),
        Step("SET data=jsonb_set", rowcount=1),
    )
    stale_repository = PostgresRepository(
        "postgresql://matrix.invalid/controller",
        cast(MinioBlobStore, SimpleNamespace(delete=fail_stale_delete)),
    )
    stale_repository._connection = stale_connection
    assert (
        stale_repository.cleanup_pcap_export_orphans(
            now=datetime(2026, 8, 24, tzinfo=UTC), max_age_seconds=60, limit=1
        )
        == []
    )

    completed = {
        **job("export-1"),
        "status": "COMPLETED",
        "completed_at": datetime(2026, 8, 22, tzinfo=UTC).isoformat(),
        "size_bytes": 4,
        "object_key": completed_key,
    }
    retention_connection = MatrixConnection(
        Step("ORDER BY completed_at,export_id FOR UPDATE", [("export-1", json.dumps(completed))]),
        Step("VALUES('pcap_export_cleanup'"),
        Step("DELETE FROM controller_objects", rowcount=1),
        Step("DELETE FROM pcap_export_jobs", rowcount=1),
        Step("kind='pcap_export_cleanup' AND id=%s", rowcount=1),
    )
    deleted: list[str] = []
    assert repository(retention_connection, deleted).retain_pcap_export_jobs(
        now=datetime(2026, 8, 24, tzinfo=UTC),
        max_age_seconds=60,
        max_count=10,
        max_artifact_bytes=100,
    ) == ["export-1"]

    insert_params = retention_connection.calls[1][1]
    acknowledge_params = retention_connection.calls[4][1]
    assert insert_params[0] != "export-1"
    assert stale_key not in str(insert_params)
    assert completed_key in str(insert_params)
    assert acknowledge_params == (insert_params[0], completed_key)
    assert deleted == [completed_key]


def test_postgres_publication_persists_cleanup_intent_before_upload_and_retries_failure() -> None:
    events: list[str] = []

    class OrderedCursor(MatrixCursor):
        def execute(self, query: str, params: Any = None) -> None:
            label = "cleanup" if "VALUES('pcap_export_cleanup'" in query else "other"
            events.append(f"sql:{label}")
            super().execute(query, params)

    class OrderedConnection(MatrixConnection):
        def cursor(self) -> MatrixCursor:
            return OrderedCursor(self)

    class FailingBlobStore:
        object_key = ""

        def put_stream(
            self,
            key: str,
            _chunks: Any,
            *,
            size_hint: int,
            content_type: str,
        ) -> Any:
            assert size_hint == 3
            assert content_type == "application/vnd.tcpdump.pcap"
            self.object_key = key
            events.append("upload")
            return SimpleNamespace(size_bytes=3, sha256=hashlib.sha256(b"abc").hexdigest())

        def delete(self, key: str) -> None:
            assert key == self.object_key
            events.append("delete-failed")
            raise RuntimeError("forced publication cleanup outage")

    connection = OrderedConnection(
        Step("kind='export' AND id=%s FOR UPDATE"),
        Step("VALUES('pcap_export_cleanup'"),
        Step("kind='job' AND id=%s FOR UPDATE", error=RuntimeError("forced publication outage")),
        Step("SET data=jsonb_set", rowcount=1),
    )
    blob_store = FailingBlobStore()
    publication_repository = PostgresRepository(
        "postgresql://matrix.invalid/controller", cast(MinioBlobStore, blob_store)
    )
    publication_repository._connection = connection

    with pytest.raises(ArtifactStorageError, match="publication failed"):
        publication_repository.save_export_stream(
            {"id": "export-1", "job_id": "analysis-1", "capture_format": "PCAP"},
            iter((b"abc",)),
            size_hint=3,
        )

    cleanup_params = connection.calls[1][1]
    cleanup_id, cleanup_payload = cleanup_params
    assert events[:3] == ["sql:other", "sql:cleanup", "upload"]
    assert blob_store.object_key in str(cleanup_payload)
    decoded_cleanup = json.loads(str(cleanup_payload))
    assert decoded_cleanup["export_id"] == "export-1"
    assert decoded_cleanup["attempt"] == -1
    assert "lease_token" in decoded_cleanup
    assert not any(
        query.startswith("DELETE") and "kind='pcap_export_cleanup'" in query
        for query, _params in connection.calls
    )

    retry_connection = MatrixConnection(
        Step("kind='pcap_export_cleanup'", [(cleanup_id, blob_store.object_key)]),
        Step("SET data=jsonb_set", rowcount=1),
        Step("kind='pcap_export_cleanup' AND id=%s", rowcount=1),
    )
    retried: list[str] = []
    removed = repository(retry_connection, retried).cleanup_pcap_export_orphans(
        now=datetime(2026, 8, 24, tzinfo=UTC), max_age_seconds=60, limit=1
    )
    assert removed == [blob_store.object_key]
    assert retried == [blob_store.object_key]
    assert retry_connection.calls[2][1] == (cleanup_id, blob_store.object_key)


def test_postgres_cleanup_claim_blocks_late_artifact_publication() -> None:
    deleted: list[str] = []

    class BlobStore:
        def put_stream(self, key: str, chunks: Any, **_kwargs: Any) -> Any:
            content = b"".join(chunks)
            return SimpleNamespace(
                size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest()
            )

        def delete(self, key: str) -> None:
            deleted.append(key)

    connection = MatrixConnection(
        Step("kind='export' AND id=%s FOR UPDATE"),
        Step("VALUES('pcap_export_cleanup'"),
        Step("kind='job' AND id=%s FOR UPDATE", [(1,)]),
        Step("kind='export' AND id=%s FOR UPDATE"),
        Step("VALUES('export'"),
        Step("INSERT INTO audit_events"),
        Step("SET data=jsonb_set", rowcount=0),
        Step("SET data=jsonb_set", rowcount=0),
        Step("kind='pcap_export_cleanup' AND id=%s", rowcount=1),
    )
    repo = PostgresRepository(
        "postgresql://matrix.invalid/controller", cast(MinioBlobStore, BlobStore())
    )
    repo._connection = connection

    with pytest.raises(ArtifactStorageError, match="publication failed"):
        repo.save_export_stream(
            {
                "id": "export-1",
                "job_id": "analysis-1",
                "capture_format": "PCAP",
                "published": False,
                "attempt": 1,
                "lease_token": "token",
            },
            iter((b"abc",)),
            size_hint=3,
        )

    assert len(deleted) == 1


def test_postgres_retry_reconciles_crashed_unpublished_attempt_before_upload() -> None:
    old_key = "exports/export-1/old-attempt.pcap"
    old = {
        "id": "export-1",
        "job_id": "analysis-1",
        "capture_format": "PCAP",
        "published": False,
        "attempt": 1,
        "lease_token": "old-token",
        "object_key": old_key,
    }
    events: list[str] = []

    class BlobStore:
        def put_stream(self, key: str, chunks: Any, **_kwargs: Any) -> Any:
            events.append("upload")
            content = b"".join(chunks)
            return SimpleNamespace(
                size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest()
            )

        def delete(self, _key: str) -> None:
            raise AssertionError("retry must leave prior object to durable cleanup")

    connection = MatrixConnection(
        Step("kind='export' AND id=%s FOR UPDATE", [(json.dumps(old),)]),
        Step("VALUES('pcap_export_cleanup'"),
        Step("kind='export' AND id=%s", rowcount=1),
        Step("VALUES('pcap_export_cleanup'"),
        Step("kind='job' AND id=%s FOR UPDATE", [(1,)]),
        Step("kind='export' AND id=%s FOR UPDATE"),
        Step("VALUES('export'"),
        Step("INSERT INTO audit_events"),
        Step("SET data=jsonb_set", rowcount=1),
    )
    repo = PostgresRepository(
        "postgresql://matrix.invalid/controller", cast(MinioBlobStore, BlobStore())
    )
    repo._connection = connection

    stored = repo.save_export_stream(
        {
            "id": "export-1",
            "job_id": "analysis-1",
            "capture_format": "PCAP",
            "published": False,
            "attempt": 2,
            "lease_token": "new-token",
        },
        iter((b"abc",)),
        size_hint=3,
    )

    assert stored is not None and stored["attempt"] == 2
    assert events == ["upload"]
    old_cleanup_params = connection.calls[1][1]
    new_cleanup_params = connection.calls[3][1]
    assert old_cleanup_params[0] != new_cleanup_params[0]
    assert old_key in str(old_cleanup_params[1])


def test_postgres_delete_uses_admission_export_then_source_lock_order() -> None:
    connection = MatrixConnection(
        Step("pg_advisory_xact_lock"),
        Step("status IN ('QUEUED','RUNNING') FOR UPDATE", [(1,)]),
    )

    assert repository(connection).delete_job("source-1") is False
    assert "pcap_export_jobs" in connection.calls[1][0]
    assert "source_job_id=%s" in connection.calls[1][0]
    assert "provenance_job_ids" in connection.calls[1][0]
    assert all("kind='job'" not in query for query, _params in connection.calls)


def test_postgres_retention_applies_age_count_bytes_and_deletes_artifacts() -> None:
    now = datetime(2026, 8, 24, tzinfo=UTC)
    jobs = [
        {
            **job("old"),
            "status": "COMPLETED",
            "completed_at": (now - timedelta(days=2)).isoformat(),
            "size_bytes": 4,
            "object_key": "exports/old.pcap",
        },
        {
            **job("middle"),
            "status": "COMPLETED",
            "completed_at": (now - timedelta(minutes=2)).isoformat(),
            "size_bytes": 6,
            "object_key": "exports/middle.pcap",
        },
        {
            **job("new"),
            "status": "COMPLETED",
            "completed_at": (now - timedelta(minutes=1)).isoformat(),
            "size_bytes": 6,
            "object_key": "exports/new.pcap",
        },
    ]
    connection = MatrixConnection(
        Step(
            "ORDER BY completed_at,export_id FOR UPDATE",
            [(item["id"], json.dumps(item)) for item in jobs],
        ),
        Step("VALUES('pcap_export_cleanup'"),
        Step("VALUES('pcap_export_cleanup'"),
        Step("DELETE FROM controller_objects", rowcount=2),
        Step("DELETE FROM pcap_export_jobs", rowcount=2),
        Step("kind='pcap_export_cleanup' AND id=%s", rowcount=1),
        Step("kind='pcap_export_cleanup' AND id=%s", rowcount=1),
    )
    deleted: list[str] = []
    removed = repository(connection, deleted).retain_pcap_export_jobs(
        now=now, max_age_seconds=3600, max_count=2, max_artifact_bytes=6
    )
    assert removed == ["old", "middle"]
    assert deleted == ["exports/old.pcap", "exports/middle.pcap"]


def test_postgres_outages_rollback_and_raise_typed_storage_errors() -> None:
    connection = MatrixConnection(Step("WHERE export_id=%s", error=RuntimeError("private outage")))
    with pytest.raises(ExportQueueStorageError, match="storage unavailable") as caught:
        repository(connection).get_pcap_export_job("secret-export-id")
    assert "secret-export-id" not in str(caught.value)
    assert connection.rollbacks == 1

    commit_connection = MatrixConnection(
        Step("WHERE export_id=%s", [row(job())]), fail_commit=True, fail_rollback=True
    )
    with pytest.raises(ExportQueueStorageError):
        repository(commit_connection).get_pcap_export_job("export-1")


def test_postgres_matrix_uses_parameterized_sql_for_runtime_values() -> None:
    connection = MatrixConnection(Step("WHERE export_id=%s", [row(job())]))
    repository(connection).get_pcap_export_job("literal-secret-id")
    query, params = connection.calls[0]
    assert "literal-secret-id" not in query
    assert params == ("literal-secret-id",)
