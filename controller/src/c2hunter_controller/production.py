from __future__ import annotations

import io
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

_AI_TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELLED"}


class MinioBlobStore:
    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
    ) -> None:
        from minio import Minio

        secure = endpoint.startswith("https://")
        address = endpoint.removeprefix("https://").removeprefix("http://")
        self.client = Minio(address, access_key=access_key, secret_key=secret_key, secure=secure)
        self.bucket = bucket

    def ready(self) -> bool:
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
            return bool(self.client.bucket_exists(self.bucket))
        except Exception:
            return False

    def put(self, key: str, content: bytes) -> None:
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)
        self.client.put_object(
            self.bucket,
            key,
            io.BytesIO(content),
            len(content),
            content_type="application/vnd.tcpdump.pcap",
        )

    def get(self, key: str) -> bytes:
        response = self.client.get_object(self.bucket, key)
        try:
            return bytes(response.read())
        finally:
            response.close()
            response.release_conn()

    def delete(self, key: str) -> None:
        self.client.remove_object(self.bucket, key)


class PostgresRepository:
    """PostgreSQL JSONB control-plane repository with MinIO export blobs and audit rows."""

    _DETECTOR_PRESET_ADVISORY_LOCK = 112737
    _FLOW_RECORD_CHUNK_TARGET_BYTES = 8 * 1024 * 1024

    def __init__(self, database_url: str, blob_store: MinioBlobStore) -> None:
        self.database_url = database_url
        self._connection: Any = None
        self.blob_store = blob_store
        self._lock = threading.RLock()

    @contextmanager
    def _rollback_on_error(self) -> Iterator[None]:
        try:
            yield
        except Exception:
            self.connection.rollback()
            raise

    @property
    def connection(self) -> Any:
        with self._lock:
            if self._connection is not None and not self._connection.closed:
                return self._connection
            import psycopg

            connection = psycopg.connect(self.database_url, autocommit=False)
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS controller_objects (
                          kind text NOT NULL, id text NOT NULL, data jsonb NOT NULL,
                          PRIMARY KEY(kind,id)
                        );
                        CREATE TABLE IF NOT EXISTS job_idempotency (
                          idempotency_key text PRIMARY KEY, job_id text NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS job_candidates (
                          job_id text PRIMARY KEY, data jsonb NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS candidate_records (
                          candidate_id text PRIMARY KEY,
                          job_id text NOT NULL,
                          position integer NOT NULL,
                          score integer NOT NULL DEFAULT 0,
                          severity text NOT NULL DEFAULT '',
                          excluded boolean NOT NULL DEFAULT false,
                          data jsonb NOT NULL,
                          UNIQUE(job_id,position)
                        );
                        CREATE INDEX IF NOT EXISTS candidate_records_job_position
                          ON candidate_records(job_id,position);
                        CREATE INDEX IF NOT EXISTS candidate_records_triage
                          ON candidate_records(excluded,severity,score DESC,candidate_id);
                        CREATE TABLE IF NOT EXISTS ai_analysis_runs (
                          run_id text PRIMARY KEY,
                          analysis_job_id text NOT NULL,
                          idempotency_key text NOT NULL,
                          created_at timestamptz NOT NULL,
                          data jsonb NOT NULL,
                          UNIQUE(analysis_job_id,idempotency_key)
                        );
                        CREATE INDEX IF NOT EXISTS ai_analysis_runs_job_created
                          ON ai_analysis_runs(analysis_job_id,created_at DESC);
                        CREATE TABLE IF NOT EXISTS ai_candidate_assessments (
                          assessment_id text PRIMARY KEY,
                          ai_run_id text NOT NULL REFERENCES ai_analysis_runs(run_id),
                          created_at timestamptz NOT NULL,
                          data jsonb NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS ai_candidate_assessments_run_created
                          ON ai_candidate_assessments(ai_run_id,created_at);
                        CREATE TABLE IF NOT EXISTS ai_generated_artifacts (
                          artifact_id text PRIMARY KEY,
                          assessment_id text NOT NULL
                            REFERENCES ai_candidate_assessments(assessment_id),
                          created_at timestamptz NOT NULL,
                          data jsonb NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS ai_generated_artifacts_assessment_created
                          ON ai_generated_artifacts(assessment_id,created_at);
                        CREATE TABLE IF NOT EXISTS ai_feedback (
                          feedback_id text PRIMARY KEY,
                          assessment_id text NOT NULL
                            REFERENCES ai_candidate_assessments(assessment_id),
                          created_at timestamptz NOT NULL,
                          data jsonb NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS ai_feedback_assessment_created
                          ON ai_feedback(assessment_id,created_at);
                        CREATE TABLE IF NOT EXISTS job_flow_records (
                          job_id text PRIMARY KEY, data jsonb NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS job_flow_record_chunks (
                          job_id text NOT NULL, chunk_no integer NOT NULL,
                          data jsonb NOT NULL,
                          PRIMARY KEY(job_id,chunk_no)
                        );
                        CREATE TABLE IF NOT EXISTS job_payload_signatures (
                          job_id text PRIMARY KEY, data jsonb NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS audit_events (
                          sequence bigserial PRIMARY KEY, kind text NOT NULL,
                          object_id text NOT NULL,
                          occurred_at timestamptz NOT NULL, data jsonb NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS controller_objects_active_live_jobs
                          ON controller_objects ((data->>'status'))
                          WHERE kind='job' AND data->>'mode'='LIVE';

                        INSERT INTO job_flow_records(job_id,data)
                          SELECT id,data->'flow_records'
                          FROM controller_objects
                          WHERE kind='job' AND data ? 'flow_records'
                          ON CONFLICT(job_id) DO NOTHING;
                        UPDATE controller_objects
                          SET data=data-'flow_records'
                          WHERE kind='job' AND data ? 'flow_records';
                        INSERT INTO job_flow_record_chunks(job_id,chunk_no,data)
                          SELECT job_id,0,data
                          FROM job_flow_records
                          ON CONFLICT(job_id,chunk_no) DO NOTHING;
                        DELETE FROM job_flow_records AS legacy
                          WHERE EXISTS (
                            SELECT 1
                            FROM job_flow_record_chunks AS chunk
                            WHERE chunk.job_id=legacy.job_id
                          );
                        CREATE INDEX IF NOT EXISTS job_flow_record_chunks_job_id
                          ON job_flow_record_chunks(job_id,chunk_no);
                        INSERT INTO job_payload_signatures(job_id,data)
                          SELECT id,data->'payload_signatures'
                          FROM controller_objects
                          WHERE kind='job' AND data ? 'payload_signatures'
                          ON CONFLICT(job_id) DO NOTHING;
                        UPDATE controller_objects
                          SET data=data-'payload_signatures'
                          WHERE kind='job' AND data ? 'payload_signatures';
                        INSERT INTO candidate_records(
                          candidate_id,job_id,position,score,severity,excluded,data
                        )
                          SELECT candidate->>'id',legacy.job_id,entry.ordinality-1,
                                 COALESCE((candidate->>'score')::integer,0),
                                 COALESCE(candidate->>'severity',''),
                                 COALESCE((candidate->>'excluded')::boolean,false),candidate
                          FROM job_candidates AS legacy
                          CROSS JOIN LATERAL jsonb_array_elements(legacy.data)
                            WITH ORDINALITY AS entry(candidate,ordinality)
                          WHERE candidate ? 'id'
                          ON CONFLICT(candidate_id) DO NOTHING;
                        DELETE FROM job_candidates AS legacy
                          WHERE jsonb_array_length(legacy.data)=(
                            SELECT COUNT(*)
                            FROM candidate_records AS record
                            WHERE record.job_id=legacy.job_id
                          );
                        """
                    )
                connection.commit()
                self._ensure_candidate_query_indexes(connection)
            except Exception:
                connection.close()
                raise
            self._connection = connection
            return connection

    @staticmethod
    def _ensure_candidate_query_indexes(connection: Any) -> None:
        indexes = (
            (
                "candidate_records_score",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_score "
                "ON candidate_records (score DESC,candidate_id) WHERE excluded=false",
            ),
            (
                "candidate_records_last_seen",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_last_seen "
                "ON candidate_records ((data->>'last_seen') DESC,candidate_id) "
                "WHERE excluded=false",
            ),
            (
                "candidate_records_first_seen",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_first_seen "
                "ON candidate_records ((data->>'first_seen') DESC,candidate_id) "
                "WHERE excluded=false",
            ),
            (
                "candidate_records_ip",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_ip "
                "ON candidate_records ((data->>'candidate_ip'),candidate_id) "
                "WHERE excluded=false",
            ),
            (
                "controller_objects_candidate_workflow",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS controller_objects_candidate_workflow "
                "ON controller_objects "
                "(kind,(data->>'candidate_id'),(data->>'created_at') DESC) "
                "WHERE kind IN "
                "('candidate-decision','candidate-action','candidate-ti-lookup',"
                "'candidate-misp-action')",
            ),
        )
        index_names = tuple(name for name, _ in indexes)
        connection.autocommit = True
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(2026081301)")
                try:
                    cursor.execute(
                        "SELECT indexrelid::regclass::text FROM pg_index "
                        "WHERE NOT indisvalid AND indexrelid::regclass::text=ANY(%s)",
                        (list(index_names),),
                    )
                    invalid_indexes = {str(row[0]) for row in cursor.fetchall()}
                    for index_name in index_names:
                        if index_name in invalid_indexes:
                            cursor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {index_name}")
                    for _, statement in indexes:
                        cursor.execute(statement)
                finally:
                    cursor.execute("SELECT pg_advisory_unlock(2026081301)")
        finally:
            connection.autocommit = False

    def close(self) -> None:
        with self._lock:
            if self._connection is not None and not self._connection.closed:
                self._connection.close()
            self._connection = None

    def for_background_worker(self) -> PostgresRepository:
        return PostgresRepository(self.database_url, self.blob_store)

    @staticmethod
    def _sanitize_json_value(value: Any) -> Any:
        """Make arbitrary control-plane values safe for PostgreSQL text/jsonb."""
        if isinstance(value, str):
            # PostgreSQL text/jsonb cannot represent U+0000. Preserve its
            # presence as a visible escaped marker instead of dropping data.
            return value.replace("\x00", "\\x00")
        if isinstance(value, dict):
            return {
                key: PostgresRepository._sanitize_json_value(item) for key, item in value.items()
            }
        if isinstance(value, list | tuple):
            return [PostgresRepository._sanitize_json_value(item) for item in value]
        return value

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(
            PostgresRepository._sanitize_json_value(value),
            separators=(",", ":"),
            default=str,
            ensure_ascii=False,
        )

    @classmethod
    def _json_array_chunks(cls, values: list[Any]) -> list[str]:
        """Serialize a JSON array into independently storable bounded chunks."""
        target = cls._FLOW_RECORD_CHUNK_TARGET_BYTES
        chunks: list[str] = []
        current: list[str] = []
        current_size = 2  # opening and closing brackets

        for value in values:
            serialized = cls._json(value)
            serialized_size = len(serialized.encode("utf-8"))
            separator_size = 1 if current else 0
            if current and current_size + separator_size + serialized_size > target:
                chunks.append(",".join(current))
                current = []
                current_size = 2
                separator_size = 0
            current.append(serialized)
            current_size += separator_size + serialized_size

        if current:
            chunks.append(",".join(current))
        return chunks

    @classmethod
    def _replace_job_flow_records(cls, cursor: Any, job_id: str, records: list[Any]) -> None:
        try:
            cursor.execute("DELETE FROM job_flow_record_chunks WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_flow_records WHERE job_id=%s", (job_id,))
            for chunk_no, chunk in enumerate(cls._json_array_chunks(records)):
                cursor.execute(
                    "INSERT INTO job_flow_record_chunks(job_id,chunk_no,data) "
                    "VALUES(%s,%s,('[' || %s || ']')::jsonb)",
                    (job_id, chunk_no, chunk),
                )
        except Exception:
            # A failed statement leaves a PostgreSQL transaction aborted until rollback.
            # Roll back here because both create_job() and save_job() call this helper.
            cursor.connection.rollback()
            raise

    @staticmethod
    def _load_job_flow_records(cursor: Any, job_id: str) -> list[Any]:
        cursor.execute(
            "SELECT data FROM job_flow_record_chunks WHERE job_id=%s ORDER BY chunk_no",
            (job_id,),
        )
        rows = cursor.fetchall()
        if rows:
            records: list[Any] = []
            for row in rows:
                value = row[0]
                chunk = value if isinstance(value, list) else json.loads(value)
                if not isinstance(chunk, list):
                    raise RuntimeError("stored flow-record chunk is not a JSON array")
                records.extend(chunk)
            return records

        # Compatibility fallback for a database that has not yet been migrated.
        cursor.execute("SELECT data FROM job_flow_records WHERE job_id=%s", (job_id,))
        row = cursor.fetchone()
        if row is None:
            return []
        value = row[0]
        records = value if isinstance(value, list) else json.loads(value)
        if not isinstance(records, list):
            raise RuntimeError("stored flow records are not a JSON array")
        return records

    def ready(self) -> bool:
        return self.database_ready() and self.blob_store.ready()

    def database_ready(self) -> bool:
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return bool(cursor.fetchone() == (1,))
        except Exception:
            return False

    def _audit(self, kind: str, object_id: str, value: Any) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                "VALUES(%s,%s,%s,%s::jsonb)",
                (kind, object_id, datetime.now(UTC), self._json(value)),
            )
            self.connection.commit()

    def _put(self, kind: str, object_id: str, value: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO controller_objects(kind,id,data) VALUES(%s,%s,%s::jsonb) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (kind, object_id, self._json(value)),
            )
            self._audit(kind, object_id, value)
            self.connection.commit()
        return deepcopy(value)

    def _get(self, kind: str, object_id: str) -> dict[str, Any] | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind=%s AND id=%s", (kind, object_id)
            )
            row = cursor.fetchone()
            self.connection.commit()
        if not row:
            return None
        value = row[0]
        return value if isinstance(value, dict) else json.loads(value)

    def _list(self, kind: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data FROM controller_objects WHERE kind=%s ORDER BY id", (kind,))
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor", sensor["sensor_id"], sensor)

    def update_sensor_heartbeat(
        self, sensor_id: str, fields: dict[str, Any]
    ) -> dict[str, Any] | None:
        with self._lock:
            connection = self.connection
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT data FROM controller_objects "
                        "WHERE kind='sensor' AND id=%s FOR UPDATE",
                        (sensor_id,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        connection.commit()
                        return None
                    value = row[0]
                    sensor = value if isinstance(value, dict) else json.loads(value)
                    sensor.update(fields)
                    cursor.execute(
                        "UPDATE controller_objects SET data=%s::jsonb "
                        "WHERE kind='sensor' AND id=%s",
                        (self._json(sensor), sensor_id),
                    )
                self._audit("sensor-heartbeat", sensor_id, fields)
                connection.commit()
                return deepcopy(sensor)
            except Exception:
                connection.rollback()
                raise

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor", sensor_id)

    def save_detector_weight_preset(self, preset: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    if preset.get("is_default"):
                        cursor.execute(
                            "SELECT pg_advisory_xact_lock(%s)",
                            (self._DETECTOR_PRESET_ADVISORY_LOCK,),
                        )
                        cursor.execute(
                            "SELECT id,data FROM controller_objects "
                            "WHERE kind='detector-weight-preset' FOR UPDATE"
                        )
                        for object_id, value in cursor.fetchall():
                            item = value if isinstance(value, dict) else json.loads(value)
                            item["is_default"] = False
                            cursor.execute(
                                "UPDATE controller_objects SET data=%s::jsonb "
                                "WHERE kind='detector-weight-preset' AND id=%s",
                                (self._json(item), object_id),
                            )
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) VALUES(%s,%s,%s::jsonb) "
                        "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                        ("detector-weight-preset", preset["id"], self._json(preset)),
                    )
                self._audit("detector-weight-preset", preset["id"], preset)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return deepcopy(preset)

    def get_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        return self._get("detector-weight-preset", preset_id)

    def update_detector_weight_preset(
        self, preset_id: str, updates: dict[str, Any], *, set_as_default: bool = False
    ) -> dict[str, Any] | None:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    if set_as_default:
                        cursor.execute(
                            "SELECT pg_advisory_xact_lock(%s)",
                            (self._DETECTOR_PRESET_ADVISORY_LOCK,),
                        )
                    cursor.execute(
                        "SELECT id,data FROM controller_objects "
                        "WHERE kind='detector-weight-preset' FOR UPDATE"
                    )
                    rows = cursor.fetchall()
                    if not any(str(object_id) == preset_id for object_id, _ in rows):
                        connection.commit()
                        return None
                    selected: dict[str, Any] | None = None
                    for object_id, value in rows:
                        preset = value if isinstance(value, dict) else json.loads(value)
                        if str(object_id) == preset_id:
                            preset.update(updates)
                            selected = preset
                        if set_as_default:
                            preset["is_default"] = str(object_id) == preset_id
                        cursor.execute(
                            "UPDATE controller_objects SET data=%s::jsonb "
                            "WHERE kind='detector-weight-preset' AND id=%s",
                            (self._json(preset), object_id),
                        )
                if selected is None:
                    raise RuntimeError("locked preset disappeared during update")
                self._audit("detector-weight-preset", preset_id, selected)
                connection.commit()
                return deepcopy(selected)
            except Exception:
                connection.rollback()
                raise

    def list_detector_weight_presets(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._list("detector-weight-preset")

    def delete_detector_weight_preset(self, preset_id: str) -> bool:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM controller_objects "
                        "WHERE kind='detector-weight-preset' AND id=%s",
                        (preset_id,),
                    )
                    deleted = cursor.rowcount > 0
                connection.commit()
                return deleted
            except Exception:
                connection.rollback()
                raise

    def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(%s)",
                        (self._DETECTOR_PRESET_ADVISORY_LOCK,),
                    )
                    cursor.execute(
                        "SELECT id,data FROM controller_objects "
                        "WHERE kind='detector-weight-preset' FOR UPDATE"
                    )
                    rows = cursor.fetchall()
                    if not any(str(object_id) == preset_id for object_id, _ in rows):
                        connection.commit()
                        return None
                    presets: list[dict[str, Any]] = []
                    for object_id, value in rows:
                        preset = value if isinstance(value, dict) else json.loads(value)
                        preset["is_default"] = str(object_id) == preset_id
                        presets.append(preset)
                        cursor.execute(
                            "UPDATE controller_objects SET data=%s::jsonb "
                            "WHERE kind='detector-weight-preset' AND id=%s",
                            (self._json(preset), object_id),
                        )
                selected = next((preset for preset in presets if preset["id"] == preset_id), None)
                connection.commit()
                return deepcopy(selected) if selected is not None else None
            except Exception:
                connection.rollback()
                raise

    def list_sensors(self) -> list[dict[str, Any]]:
        return self._list("sensor")

    def create_group(self, group: dict[str, Any]) -> dict[str, Any]:
        return self._put("group", group["id"], group)

    def list_groups(self) -> list[dict[str, Any]]:
        return self._list("group")

    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO job_idempotency(idempotency_key,job_id) VALUES(%s,%s) "
                "ON CONFLICT(idempotency_key) DO NOTHING RETURNING job_id",
                (job["idempotency_key"], job["id"]),
            )
            created = cursor.fetchone() is not None
            if not created:
                cursor.execute(
                    "SELECT job_id FROM job_idempotency WHERE idempotency_key=%s",
                    (job["idempotency_key"],),
                )
                row = cursor.fetchone()
                self.connection.commit()
                if row is None:
                    raise RuntimeError("idempotency ledger row disappeared")
                existing = self.get_job(str(row[0]))
                if existing is None:
                    raise RuntimeError("idempotency ledger references missing job")
                return existing, False
            cursor.execute(
                "INSERT INTO controller_objects(kind,id,data) VALUES('job',%s,%s::jsonb)",
                (job["id"], self._json(metadata)),
            )
            self._replace_job_flow_records(cursor, job["id"], list(job.get("flow_records", [])))
            cursor.execute(
                "INSERT INTO job_payload_signatures(job_id,data) VALUES(%s,%s::jsonb)",
                (job["id"], self._json(job.get("payload_signatures", []))),
            )
            self._audit("job", job["id"], metadata)
            self.connection.commit()
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO controller_objects(kind,id,data) VALUES('job',%s,%s::jsonb) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (job["id"], self._json(metadata)),
            )
            if "flow_records" in job:
                self._replace_job_flow_records(cursor, job["id"], list(job["flow_records"]))
            if "payload_signatures" in job:
                cursor.execute(
                    "INSERT INTO job_payload_signatures(job_id,data) VALUES(%s,%s::jsonb) "
                    "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                    (job["id"], self._json(job["payload_signatures"])),
                )
            self._audit("job", job["id"], metadata)
            self.connection.commit()
        return deepcopy(job)

    def save_job_metadata(self, job: dict[str, Any]) -> dict[str, Any]:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO controller_objects(kind,id,data) VALUES('job',%s,%s::jsonb) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (job["id"], self._json(metadata)),
            )
            self._audit("job", job["id"], metadata)
            self.connection.commit()
        return deepcopy(metadata)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        job = self.get_job_summary(job_id)
        if job is None:
            return None
        with self.connection.cursor() as cursor:
            job["flow_records"] = self._load_job_flow_records(cursor, job_id)
            self.connection.commit()
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data FROM job_payload_signatures WHERE job_id=%s", (job_id,))
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            job["payload_signatures"] = []
        else:
            value = row[0]
            job["payload_signatures"] = value if isinstance(value, list) else json.loads(value)
        return job

    def get_job_summary(self, job_id: str) -> dict[str, Any] | None:
        return self._get("job", job_id)

    def get_job_summaries(self, job_ids: list[str]) -> dict[str, dict[str, Any]]:
        selected = list(dict.fromkeys(job_ids))
        if not selected:
            return {}
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT id,data FROM controller_objects WHERE kind='job' AND id=ANY(%s)",
                (selected,),
            )
            rows = cursor.fetchall()
        return {
            str(row[0]): row[1] if isinstance(row[1], dict) else json.loads(row[1]) for row in rows
        }

    def list_jobs(self) -> list[dict[str, Any]]:
        return self._list("job")

    def list_active_live_jobs(self) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects "
                "WHERE kind='job' AND data->>'mode'='LIVE' "
                "AND data->>'status' IN ('CAPTURING','UPLOADING') ORDER BY id"
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def delete_job(self, job_id: str) -> bool:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                (job_id,),
            )
            row = cursor.fetchone()
            if row is None:
                self.connection.commit()
                return False
            cursor.execute(
                "SELECT data->>'status' FROM ai_analysis_runs WHERE analysis_job_id=%s FOR UPDATE",
                (job_id,),
            )
            if any(str(item[0]) not in _AI_TERMINAL_STATUSES for item in cursor.fetchall()):
                self.connection.commit()
                return False
            cursor.execute(
                "SELECT data->>'object_key' FROM controller_objects "
                "WHERE kind='export' AND data->>'job_id'=%s",
                (job_id,),
            )
            object_keys = [str(item[0]) for item in cursor.fetchall() if item[0]]
            cursor.execute(
                "DELETE FROM ai_feedback WHERE assessment_id IN "
                "(SELECT assessment_id FROM ai_candidate_assessments "
                "WHERE ai_run_id IN "
                "(SELECT run_id FROM ai_analysis_runs WHERE analysis_job_id=%s))",
                (job_id,),
            )
            cursor.execute(
                "DELETE FROM ai_generated_artifacts WHERE assessment_id IN "
                "(SELECT assessment_id FROM ai_candidate_assessments "
                "WHERE ai_run_id IN "
                "(SELECT run_id FROM ai_analysis_runs WHERE analysis_job_id=%s))",
                (job_id,),
            )
            cursor.execute(
                "DELETE FROM ai_candidate_assessments WHERE ai_run_id IN "
                "(SELECT run_id FROM ai_analysis_runs WHERE analysis_job_id=%s)",
                (job_id,),
            )
            cursor.execute("DELETE FROM ai_analysis_runs WHERE analysis_job_id=%s", (job_id,))
            cursor.execute(
                "DELETE FROM controller_objects WHERE kind='export' AND data->>'job_id'=%s",
                (job_id,),
            )
            cursor.execute("DELETE FROM job_candidates WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM candidate_records WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_flow_record_chunks WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_flow_records WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_payload_signatures WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_idempotency WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM controller_objects WHERE kind='job' AND id=%s", (job_id,))
            self._audit("job-delete", job_id, {"id": job_id})
            self.connection.commit()
        for object_key in object_keys:
            try:
                self.blob_store.delete(object_key)
            except Exception:
                # Metadata deletion remains authoritative; object-store lifecycle policies
                # provide a second cleanup path if the immediate removal is unavailable.
                pass
        try:
            self.blob_store.delete(self._capture_key(job_id))
        except Exception:
            pass
        return True

    @staticmethod
    def _capture_key(job_id: str) -> str:
        return f"captures/{job_id}.pcap"

    def save_job_capture(self, job_id: str, content: bytes) -> None:
        self.blob_store.put(self._capture_key(job_id), content)

    def get_job_capture(self, job_id: str) -> bytes | None:
        try:
            return self.blob_store.get(self._capture_key(job_id))
        except Exception:
            return None

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("DELETE FROM candidate_records WHERE job_id=%s", (job_id,))
                    cursor.executemany(
                        "INSERT INTO candidate_records("
                        "candidate_id,job_id,position,score,severity,excluded,data"
                        ") VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb)",
                        [
                            (
                                str(candidate["id"]),
                                job_id,
                                position,
                                int(candidate.get("score", 0)),
                                str(candidate.get("severity", "")),
                                bool(candidate.get("excluded", False)),
                                self._json(candidate),
                            )
                            for position, candidate in enumerate(candidates)
                        ],
                    )
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('candidates',%s,%s,%s::jsonb)",
                        (job_id, datetime.now(UTC), self._json(candidates)),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM candidate_records WHERE job_id=%s ORDER BY position", (job_id,)
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def get_candidate(self, candidate_id: str) -> tuple[str, dict[str, Any]] | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT job_id,data FROM candidate_records WHERE candidate_id=%s", (candidate_id,)
            )
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        data = row[1] if isinstance(row[1], dict) else json.loads(row[1])
        return str(row[0]), data

    def query_candidates(
        self,
        *,
        minimum_score: int = 0,
        severity: str | None = None,
        include_suppressed: bool = False,
    ) -> list[tuple[str, dict[str, Any]]]:
        clauses = ["score >= %s"]
        parameters: list[Any] = [minimum_score]
        if severity is not None:
            clauses.append("severity = %s")
            parameters.append(severity)
        if not include_suppressed:
            clauses.append("excluded = false")
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT job_id,data FROM candidate_records WHERE " + " AND ".join(clauses),
                parameters,
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [
            (str(row[0]), row[1] if isinstance(row[1], dict) else json.loads(row[1]))
            for row in rows
        ]

    @staticmethod
    def _candidate_query_parts(
        minimum_score: int, severity: str | None, include_suppressed: bool
    ) -> tuple[list[str], list[Any]]:
        clauses = ["score >= %s"]
        parameters: list[Any] = [minimum_score]
        if severity is not None:
            clauses.append("severity = %s")
            parameters.append(severity)
        if not include_suppressed:
            clauses.append("excluded = false")
        return clauses, parameters

    def query_candidate_page(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
        sort: str,
        page: int,
        page_size: int,
    ) -> tuple[list[tuple[str, dict[str, Any]]], int]:
        clauses, parameters = self._candidate_query_parts(
            minimum_score, severity, include_suppressed
        )
        field = sort.removeprefix("-")
        direction = "DESC" if sort.startswith("-") else "ASC"
        columns = {
            "score": "score",
            "severity": "severity",
            "candidate_ip": "data->>'candidate_ip'",
            "first_seen": "data->>'first_seen'",
            "last_seen": "data->>'last_seen'",
        }
        order_column = columns[field]
        where = " AND ".join(clauses)
        with self.connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM candidate_records WHERE {where}", parameters)
            total_row = cursor.fetchone()
            cursor.execute(
                f"SELECT job_id,data FROM candidate_records WHERE {where} "
                f"ORDER BY {order_column} {direction},candidate_id ASC LIMIT %s OFFSET %s",
                [*parameters, page_size, (page - 1) * page_size],
            )
            rows = cursor.fetchall()
            self.connection.commit()
        total = int(total_row[0]) if total_row is not None else 0
        return [
            (str(row[0]), row[1] if isinstance(row[1], dict) else json.loads(row[1]))
            for row in rows
        ], total

    def query_candidate_refs(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> list[tuple[str, bool]]:
        clauses, parameters = self._candidate_query_parts(
            minimum_score, severity, include_suppressed
        )
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT candidate_id,excluded FROM candidate_records WHERE "
                + " AND ".join(clauses),
                parameters,
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [(str(row[0]), bool(row[1])) for row in rows]

    def candidate_workflow_counts(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> dict[str, int]:
        clauses, parameters = self._candidate_query_parts(
            minimum_score, severity, include_suppressed
        )
        where = " AND ".join(f"c.{clause}" for clause in clauses)
        query = f"""
            WITH selected AS (
              SELECT c.candidate_id FROM candidate_records c WHERE {where}
            ), current_decision AS (
              SELECT DISTINCT ON (o.data->>'candidate_id')
                o.data->>'candidate_id' AS candidate_id,
                o.data->>'id' AS verdict_id,
                o.data->>'verdict' AS verdict
              FROM controller_objects o JOIN selected s
                ON s.candidate_id=o.data->>'candidate_id'
              WHERE o.kind='candidate-decision'
                AND o.data->>'verdict' IN ('CONFIRMED_C2','FALSE_POSITIVE','UNDER_REVIEW')
                AND o.data->>'confidence' IN ('CONFIRMED','HIGH','MEDIUM','LOW')
                AND COALESCE(o.data->>'id','')<>''
                AND COALESCE(o.data->>'candidate_id','')<>''
                AND COALESCE(o.data->>'note','')<>''
                AND COALESCE(o.data->>'created_by','')<>''
                AND o.data->>'created_at' ~
                  '^\\d{{4}}-\\d{{2}}-\\d{{2}}T\\d{{2}}:\\d{{2}}:\\d{{2}}.*(Z|[+-]\\d{{2}}:\\d{{2}})$'
              ORDER BY o.data->>'candidate_id',o.data->>'created_at' DESC
            ), current_action AS (
              SELECT DISTINCT ON (o.data->>'candidate_id')
                o.data->>'candidate_id' AS candidate_id,o.data->>'status' AS status
              FROM controller_objects o JOIN current_decision d
                ON d.candidate_id=o.data->>'candidate_id'
                AND d.verdict_id=o.data->>'verdict_id'
              WHERE o.kind='candidate-action'
              ORDER BY o.data->>'candidate_id',o.data->>'created_at' DESC
            )
            SELECT
              COUNT(*) FILTER (WHERE d.verdict IS NULL),
              COUNT(*) FILTER (WHERE d.verdict='UNDER_REVIEW'),
              COUNT(*) FILTER (WHERE d.verdict='CONFIRMED_C2'
                AND COALESCE(a.status,'PENDING') NOT IN ('IN_PROGRESS','COMPLETED')),
              COUNT(*) FILTER (WHERE d.verdict='CONFIRMED_C2' AND a.status='IN_PROGRESS'),
              COUNT(*) FILTER (WHERE d.verdict='CONFIRMED_C2' AND a.status='COMPLETED'),
              COUNT(*) FILTER (WHERE d.verdict='FALSE_POSITIVE'),
              COUNT(*) FILTER (WHERE d.verdict='FALSE_POSITIVE'
                OR (d.verdict='CONFIRMED_C2' AND a.status='COMPLETED'))
            FROM selected s
            LEFT JOIN current_decision d USING(candidate_id)
            LEFT JOIN current_action a USING(candidate_id)
        """
        with self.connection.cursor() as cursor:
            cursor.execute(query, parameters)
            row = cursor.fetchone()
            self.connection.commit()
        values = row or (0, 0, 0, 0, 0, 0, 0)
        return dict(
            zip(
                (
                    "needs_review",
                    "in_review",
                    "action_required",
                    "action_in_progress",
                    "action_completed",
                    "false_positive",
                    "done",
                ),
                (int(value) for value in values),
                strict=True,
            )
        )

    def create_ai_run(self, run: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO ai_analysis_runs"
                        "(run_id,analysis_job_id,idempotency_key,created_at,data) "
                        "VALUES(%s,%s,%s,%s,%s::jsonb) "
                        "ON CONFLICT(analysis_job_id,idempotency_key) DO NOTHING "
                        "RETURNING data",
                        (
                            run["id"],
                            run["analysis_job_id"],
                            run["idempotency_key"],
                            run["created_at"],
                            self._json(run),
                        ),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        cursor.execute(
                            "SELECT data FROM ai_analysis_runs "
                            "WHERE analysis_job_id=%s AND idempotency_key=%s",
                            (run["analysis_job_id"], run["idempotency_key"]),
                        )
                        existing_row = cursor.fetchone()
                        if existing_row is None:
                            raise RuntimeError("AI run idempotency conflict could not be read")
                        connection.commit()
                        value = existing_row[0]
                        return (value if isinstance(value, dict) else json.loads(value)), False
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('ai-run',%s,%s,%s::jsonb)",
                        (run["id"], datetime.now(UTC), self._json(run)),
                    )
                connection.commit()
                return deepcopy(run), True
            except Exception:
                connection.rollback()
                raise

    def save_ai_run(self, run: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT data FROM ai_analysis_runs WHERE run_id=%s FOR UPDATE",
                        (run["id"],),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        connection.commit()
                        raise KeyError(f"AI run not found: {run['id']}")
                    value = row[0]
                    existing = value if isinstance(value, dict) else json.loads(value)
                    if existing.get("status") in {"COMPLETED", "FAILED", "CANCELLED"}:
                        connection.commit()
                        return existing
                    cursor.execute(
                        "UPDATE ai_analysis_runs SET data=%s::jsonb WHERE run_id=%s",
                        (self._json(run), run["id"]),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('ai-run',%s,%s,%s::jsonb)",
                        (run["id"], datetime.now(UTC), self._json(run)),
                    )
                connection.commit()
                return deepcopy(run)
            except Exception:
                connection.rollback()
                raise

    def get_ai_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data FROM ai_analysis_runs WHERE run_id=%s", (run_id,))
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        value = row[0]
        return value if isinstance(value, dict) else json.loads(value)

    def list_ai_runs(self, job_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_analysis_runs "
                "WHERE analysis_job_id=%s ORDER BY created_at DESC",
                (job_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def save_ai_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO ai_candidate_assessments"
                        "(assessment_id,ai_run_id,created_at,data) VALUES(%s,%s,%s,%s::jsonb) "
                        "ON CONFLICT(assessment_id) DO NOTHING",
                        (
                            assessment["id"],
                            assessment["ai_run_id"],
                            assessment["created_at"],
                            self._json(assessment),
                        ),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('ai-assessment',%s,%s,%s::jsonb)",
                        (assessment["id"], datetime.now(UTC), self._json(assessment)),
                    )
                connection.commit()
                return deepcopy(assessment)
            except Exception:
                connection.rollback()
                raise

    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_candidate_assessments WHERE assessment_id=%s",
                (assessment_id,),
            )
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        value = row[0]
        return value if isinstance(value, dict) else json.loads(value)

    def list_ai_assessments(self, run_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_candidate_assessments WHERE ai_run_id=%s ORDER BY created_at",
                (run_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO ai_generated_artifacts"
                        "(artifact_id,assessment_id,created_at,data) VALUES(%s,%s,%s,%s::jsonb) "
                        "ON CONFLICT(artifact_id) DO UPDATE SET data=excluded.data",
                        (
                            artifact["id"],
                            artifact["assessment_id"],
                            artifact["created_at"],
                            self._json(artifact),
                        ),
                    )
                connection.commit()
                return deepcopy(artifact)
            except Exception:
                connection.rollback()
                raise

    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_generated_artifacts WHERE artifact_id=%s", (artifact_id,)
            )
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        return row[0] if isinstance(row[0], dict) else json.loads(row[0])

    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_generated_artifacts "
                "WHERE assessment_id=%s ORDER BY created_at,artifact_id",
                (assessment_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO ai_feedback"
                        "(feedback_id,assessment_id,created_at,data) VALUES(%s,%s,%s,%s::jsonb) "
                        "ON CONFLICT(feedback_id) DO NOTHING",
                        (
                            feedback["id"],
                            feedback["assessment_id"],
                            feedback["created_at"],
                            self._json(feedback),
                        ),
                    )
                connection.commit()
                return deepcopy(feedback)
            except Exception:
                connection.rollback()
                raise

    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_feedback "
                "WHERE assessment_id=%s ORDER BY created_at,feedback_id",
                (assessment_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def append_audit_event(self, kind: str, object_id: str, data: dict[str, Any]) -> None:
        self._audit(kind, object_id, data)

    def list_candidate_sets(self) -> dict[str, list[dict[str, Any]]]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT job_id,data FROM candidate_records ORDER BY job_id,position")
            rows = cursor.fetchall()
            self.connection.commit()
        result: dict[str, list[dict[str, Any]]] = {}
        for job_id, data in rows:
            result.setdefault(str(job_id), []).append(
                data if isinstance(data, dict) else json.loads(data)
            )
        return result

    def get_integration_settings(self) -> dict[str, Any] | None:
        return self._get("integration_settings", "global")

    def save_integration_settings(
        self, settings: dict[str, Any], expected_version: int
    ) -> tuple[dict[str, Any] | None, str]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT data FROM controller_objects "
                        "WHERE kind='integration_settings' AND id='global' FOR UPDATE"
                    )
                    row = cursor.fetchone()
                    value = row[0] if row else None
                    current = (
                        value if isinstance(value, dict) else json.loads(value) if value else None
                    )
                    if int((current or {}).get("version", 0)) != expected_version:
                        connection.commit()
                        return current, "CONFLICT"
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) "
                        "VALUES('integration_settings','global',%s::jsonb) "
                        "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                        (self._json(settings),),
                    )
                connection.commit()
                return deepcopy(settings), "OK"
            except Exception:
                connection.rollback()
                raise

    def save_candidate_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-decision", decision["id"], decision)

    def list_candidate_decisions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-decision")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def save_candidate_action(self, action: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-action", action["id"], action)

    def list_candidate_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-action")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def save_candidate_ti_lookup(self, lookup: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-ti-lookup", lookup["id"], lookup)

    def list_candidate_ti_lookups(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-ti-lookup")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def save_candidate_misp_action(self, action: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-misp-action", action["id"], action)

    def claim_candidate_misp_action(self, action: dict[str, Any]) -> bool:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) "
                        "VALUES('candidate-misp-action',%s,%s::jsonb) "
                        "ON CONFLICT(kind,id) DO NOTHING",
                        (action["id"], self._json(action)),
                    )
                    claimed = cursor.rowcount > 0
                connection.commit()
                return claimed
            except Exception:
                connection.rollback()
                raise

    def list_candidate_misp_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-misp-action")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def list_candidate_workflow_records(
        self, candidate_ids: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        records: dict[str, list[dict[str, Any]]] = {
            "decisions": [],
            "actions": [],
            "lookups": [],
            "misp_actions": [],
        }
        selected = list(dict.fromkeys(candidate_ids))
        if not selected:
            return records
        kinds = {
            "candidate-decision": "decisions",
            "candidate-action": "actions",
            "candidate-ti-lookup": "lookups",
            "candidate-misp-action": "misp_actions",
        }
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT kind,data FROM controller_objects "
                "WHERE kind=ANY(%s) AND data->>'candidate_id'=ANY(%s)",
                (list(kinds), selected),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        for kind, value in rows:
            records[kinds[str(kind)]].append(
                value if isinstance(value, dict) else json.loads(value)
            )
        return records

    def update_candidate(self, candidate_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Update a candidate by ID across all jobs."""
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT data FROM candidate_records WHERE candidate_id=%s FOR UPDATE",
                        (candidate_id,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        connection.commit()
                        return None
                    value = row[0]
                    updated = value if isinstance(value, dict) else json.loads(value)
                    updated = deepcopy(updated)
                    updates_copy = deepcopy(updates)
                    if "score_adjustment" in updates_copy:
                        adjustment = updates_copy.pop("score_adjustment")
                        updated["score"] = max(
                            0, min(100, int(updated.get("score", 0)) + int(adjustment))
                        )
                    if "exclude_reason" in updates_copy:
                        updated["excluded"] = True
                        updated["exclude_reason"] = updates_copy.pop("exclude_reason")
                    updated.update(updates_copy)
                    updated["updated_at"] = datetime.now(UTC).isoformat()
                    cursor.execute(
                        "UPDATE candidate_records SET "
                        "score=%s,severity=%s,excluded=%s,data=%s::jsonb "
                        "WHERE candidate_id=%s",
                        (
                            int(updated.get("score", 0)),
                            str(updated.get("severity", "")),
                            bool(updated.get("excluded", False)),
                            self._json(updated),
                            candidate_id,
                        ),
                    )
                connection.commit()
                return deepcopy(updated)
            except Exception:
                connection.rollback()
                raise

    def delete_candidate(self, candidate_id: str) -> bool:
        """Delete a candidate by ID across all jobs."""
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM candidate_records WHERE candidate_id=%s "
                        "RETURNING candidate_id",
                        (candidate_id,),
                    )
                    deleted = cursor.fetchone() is not None
                connection.commit()
                return deleted
            except Exception:
                connection.rollback()
                raise

    def save_flow_label(self, label: dict[str, Any]) -> dict[str, Any]:
        return self._put("flow_label", label["id"], label)

    def list_flow_labels(self, job_id: str | None = None) -> list[dict[str, Any]]:
        if job_id is None:
            labels = self._list("flow_label")
        else:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT data FROM controller_objects "
                    "WHERE kind='flow_label' AND data->>'job_id'=%s ORDER BY id",
                    (job_id,),
                )
                rows = cursor.fetchall()
                self.connection.commit()
            labels = [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]
        return sorted(labels, key=lambda item: str(item["created_at"]))

    def save_payload_signature(self, signature: dict[str, Any]) -> dict[str, Any]:
        return self._put("payload_signature", signature["id"], signature)

    def get_payload_signature(self, signature_id: str) -> dict[str, Any] | None:
        return self._get("payload_signature", signature_id)

    def list_payload_signatures(self) -> list[dict[str, Any]]:
        return sorted(
            self._list("payload_signature"),
            key=lambda item: str(item["created_at"]),
        )

    def delete_payload_signature(self, signature_id: str) -> bool:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM controller_objects WHERE kind='payload_signature' AND id=%s",
                (signature_id,),
            )
            deleted = cursor.rowcount > 0
            if deleted:
                self._audit("payload_signature-delete", signature_id, {"id": signature_id})
                self.connection.commit()
        return deleted

    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]:
        return self._put("allowlist", entry["id"], entry)

    def list_allowlist(self) -> list[dict[str, Any]]:
        return self._list("allowlist")

    def delete_allowlist(self, entry_id: str) -> bool:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM controller_objects WHERE kind='allowlist' AND id=%s", (entry_id,)
            )
            deleted = cursor.rowcount > 0
            if deleted:
                self._audit("allowlist-delete", entry_id, {"id": entry_id})
            self.connection.commit()
            return bool(deleted)

    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any]:
        key = f"exports/{export['id']}.pcap"
        self.blob_store.put(key, content)
        stored = {**export, "object_key": key}
        return self._put("export", export["id"], stored)

    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None:
        metadata = self._get("export", export_id)
        if metadata is None:
            return None
        return metadata, self.blob_store.get(str(metadata["object_key"]))

    def save_sensor_pcap(self, segment: dict[str, Any], content: bytes) -> dict[str, Any]:
        stored, status = self.save_sensor_pcap_limited(segment, content, None)
        if stored is None or status not in {"OK", "EXISTS"}:
            raise RuntimeError(f"sensor PCAP save failed: {status}")
        return stored

    def save_sensor_pcap_limited(
        self, segment: dict[str, Any], content: bytes, max_total_bytes: int | None
    ) -> tuple[dict[str, Any] | None, str]:
        connection = self.connection
        analysis_job_id = segment.get("analysis_job_id")
        lock_key = f"sensor-pcap:{analysis_job_id or segment['id']}"
        object_key = f"sensor-pcaps/{segment['sensor_id']}/{segment['id']}.pcap"
        uploaded = False
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                        (lock_key,),
                    )
                    cursor.execute(
                        "SELECT data FROM controller_objects "
                        "WHERE kind='sensor_pcap' AND id=%s FOR UPDATE",
                        (segment["id"],),
                    )
                    row = cursor.fetchone()
                    if row is not None:
                        value = row[0]
                        existing = value if isinstance(value, dict) else json.loads(value)
                        matches = all(
                            existing.get(field) == segment.get(field)
                            for field in ("sensor_id", "analysis_job_id", "sha256")
                        )
                        connection.commit()
                        return (deepcopy(existing), "EXISTS") if matches else (None, "CONFLICT")
                    if max_total_bytes is not None and analysis_job_id is not None:
                        cursor.execute(
                            "SELECT COALESCE(SUM((data->>'size_bytes')::bigint),0) "
                            "FROM controller_objects WHERE kind='sensor_pcap' "
                            "AND data->>'analysis_job_id'=%s",
                            (analysis_job_id,),
                        )
                        used = int(cursor.fetchone()[0])
                        if used + len(content) > max_total_bytes:
                            connection.commit()
                            return None, "LIMIT"
                    self.blob_store.put(object_key, content)
                    uploaded = True
                    stored = {**segment, "object_key": object_key}
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) "
                        "VALUES('sensor_pcap',%s,%s::jsonb)",
                        (segment["id"], self._json(stored)),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('sensor_pcap',%s,%s,%s::jsonb)",
                        (segment["id"], datetime.now(UTC), self._json(stored)),
                    )
                connection.commit()
                return deepcopy(stored), "OK"
            except Exception:
                connection.rollback()
                if uploaded:
                    try:
                        self.blob_store.delete(object_key)
                    except Exception:
                        pass
                raise

    def get_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], bytes] | None:
        metadata = self._get("sensor_pcap", segment_id)
        if metadata is None:
            return None
        return metadata, self.blob_store.get(str(metadata["object_key"]))

    def list_sensor_pcaps(self) -> list[dict[str, Any]]:
        return self._list("sensor_pcap")

    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self._put("enrollment", enrollment["enrollment_id"], enrollment)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        return self._get("enrollment", enrollment_id)

    def list_enrollments(self) -> list[dict[str, Any]]:
        return self._list("enrollment")

    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self.create_enrollment(enrollment)

    def claim_enrollment(self, token_hash: str, now: datetime) -> tuple[dict[str, Any] | None, str]:
        """Claim inside one row lock/transaction so a token can succeed only once."""
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT id,data FROM controller_objects "
                "WHERE kind='enrollment' AND data->>'token_hash'=%s FOR UPDATE",
                (token_hash,),
            )
            row = cursor.fetchone()
            if row is None:
                self.connection.commit()
                return None, "NOT_FOUND"
            value = row[1]
            enrollment = value if isinstance(value, dict) else json.loads(value)
            if enrollment.get("revoked_at") is not None:
                self.connection.commit()
                return enrollment, "REVOKED"
            if enrollment.get("claimed_at") is not None:
                self.connection.commit()
                return enrollment, "CLAIMED"
            if datetime.fromisoformat(enrollment["expires_at"]) <= now:
                self.connection.commit()
                return enrollment, "EXPIRED"
            enrollment["claimed_at"] = now.isoformat()
            cursor.execute(
                "UPDATE controller_objects SET data=%s::jsonb WHERE kind='enrollment' AND id=%s",
                (self._json(enrollment), row[0]),
            )
            self._audit("enrollment-claim", str(row[0]), {"claimed_at": now.isoformat()})
            self.connection.commit()
            return deepcopy(enrollment), "OK"

    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor_credential", credential["sensor_id"], credential)

    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor_credential", sensor_id)

    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor' AND id=%s FOR UPDATE",
                (sensor_id,),
            )
            row = cursor.fetchone()
            if row is None:
                self.connection.commit()
                return None, "NOT_FOUND"
            value = row[0]
            sensor = value if isinstance(value, dict) else json.loads(value)
            if sensor.get("config_version") != expected_version:
                self.connection.commit()
                return sensor, "CONFLICT"
            sensor.update(configuration)
            sensor["config_version"] = expected_version + 1
            cursor.execute(
                "UPDATE controller_objects SET data=%s::jsonb WHERE kind='sensor' AND id=%s",
                (self._json(sensor), sensor_id),
            )
            self._audit("sensor-configuration", sensor_id, configuration)
            self.connection.commit()
            return deepcopy(sensor), "OK"
