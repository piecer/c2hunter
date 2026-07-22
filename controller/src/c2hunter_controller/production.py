from __future__ import annotations

import io
import json
import threading
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any


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

    def __init__(self, database_url: str, blob_store: MinioBlobStore) -> None:
        self.database_url = database_url
        self._connection: Any = None
        self.blob_store = blob_store
        self._lock = threading.RLock()

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
                        CREATE TABLE IF NOT EXISTS audit_events (
                          sequence bigserial PRIMARY KEY, kind text NOT NULL,
                          object_id text NOT NULL,
                          occurred_at timestamptz NOT NULL, data jsonb NOT NULL
                        );
                        """
                    )
                connection.commit()
            except Exception:
                connection.close()
                raise
            self._connection = connection
            return connection

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"), default=str)

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
        if not row:
            return None
        value = row[0]
        return value if isinstance(value, dict) else json.loads(value)

    def _list(self, kind: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data FROM controller_objects WHERE kind=%s ORDER BY id", (kind,))
            rows = cursor.fetchall()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor", sensor["sensor_id"], sensor)

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor", sensor_id)

    def list_sensors(self) -> list[dict[str, Any]]:
        return self._list("sensor")

    def create_group(self, group: dict[str, Any]) -> dict[str, Any]:
        return self._put("group", group["id"], group)

    def list_groups(self) -> list[dict[str, Any]]:
        return self._list("group")

    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
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
                (job["id"], self._json(job)),
            )
            self._audit("job", job["id"], job)
            self.connection.commit()
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        return self._put("job", job["id"], job)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return self._get("job", job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        return self._list("job")

    def delete_job(self, job_id: str) -> bool:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                (job_id,),
            )
            row = cursor.fetchone()
            if row is None:
                self.connection.commit()
                return False
            cursor.execute(
                "SELECT data->>'object_key' FROM controller_objects "
                "WHERE kind='export' AND data->>'job_id'=%s",
                (job_id,),
            )
            object_keys = [str(item[0]) for item in cursor.fetchall() if item[0]]
            cursor.execute(
                "DELETE FROM controller_objects WHERE kind='export' AND data->>'job_id'=%s",
                (job_id,),
            )
            cursor.execute("DELETE FROM job_candidates WHERE job_id=%s", (job_id,))
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
        return True

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO job_candidates(job_id,data) VALUES(%s,%s::jsonb) "
                "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                (job_id, self._json(candidates)),
            )
            self._audit("candidates", job_id, candidates)
            self.connection.commit()

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data FROM job_candidates WHERE job_id=%s", (job_id,))
            row = cursor.fetchone()
        if not row:
            return []
        return row[0] if isinstance(row[0], list) else json.loads(row[0])

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
