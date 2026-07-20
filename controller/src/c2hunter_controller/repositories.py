from __future__ import annotations

import json
import sqlite3
import threading
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol


class Repository(Protocol):
    """PostgreSQL adapter가 구현해야 하는 제어 영역 경계."""

    def ready(self) -> bool: ...
    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]: ...
    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None: ...
    def list_sensors(self) -> list[dict[str, Any]]: ...
    def create_group(self, group: dict[str, Any]) -> dict[str, Any]: ...
    def list_groups(self) -> list[dict[str, Any]]: ...
    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]: ...
    def save_job(self, job: dict[str, Any]) -> dict[str, Any]: ...
    def get_job(self, job_id: str) -> dict[str, Any] | None: ...
    def list_jobs(self) -> list[dict[str, Any]]: ...
    def delete_job(self, job_id: str) -> bool: ...
    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None: ...
    def get_candidates(self, job_id: str) -> list[dict[str, Any]]: ...
    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]: ...
    def list_allowlist(self) -> list[dict[str, Any]]: ...
    def delete_allowlist(self, entry_id: str) -> bool: ...
    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any]: ...
    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None: ...
    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]: ...
    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None: ...
    def list_enrollments(self) -> list[dict[str, Any]]: ...
    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]: ...
    def claim_enrollment(
        self, token_hash: str, now: datetime
    ) -> tuple[dict[str, Any] | None, str]: ...
    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]: ...
    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None: ...
    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]: ...


class MemoryRepository:
    def __init__(self) -> None:
        self.sensors: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.idempotency_keys: dict[str, str] = {}
        self.candidates: dict[str, list[dict[str, Any]]] = {}
        self.allowlist: dict[str, dict[str, Any]] = {}
        self.exports: dict[str, dict[str, Any]] = {}
        self.export_content: dict[str, bytes] = {}
        self.enrollments: dict[str, dict[str, Any]] = {}
        self.sensor_credentials: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def ready(self) -> bool:
        return True

    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.sensors[sensor["sensor_id"]] = deepcopy(sensor)
            return deepcopy(sensor)

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        value = self.sensors.get(sensor_id)
        return deepcopy(value) if value else None

    def list_sensors(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.sensors.values()))

    def create_group(self, group: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.groups[group["id"]] = deepcopy(group)
            return deepcopy(group)

    def list_groups(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.groups.values()))

    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self._lock:
            existing_id = self.idempotency_keys.get(job["idempotency_key"])
            if existing_id:
                return deepcopy(self.jobs[existing_id]), False
            self.jobs[job["id"]] = deepcopy(job)
            self.idempotency_keys[job["idempotency_key"]] = job["id"]
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.jobs[job["id"]] = deepcopy(job)
            return deepcopy(job)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        value = self.jobs.get(job_id)
        return deepcopy(value) if value else None

    def list_jobs(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.jobs.values()))

    def delete_job(self, job_id: str) -> bool:
        with self._lock:
            job = self.jobs.pop(job_id, None)
            if job is None:
                return False
            self.idempotency_keys.pop(str(job["idempotency_key"]), None)
            self.candidates.pop(job_id, None)
            export_ids = [
                export_id
                for export_id, metadata in self.exports.items()
                if metadata.get("job_id") == job_id
            ]
            for export_id in export_ids:
                self.exports.pop(export_id, None)
                self.export_content.pop(export_id, None)
            return True

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        with self._lock:
            self.candidates[job_id] = deepcopy(candidates)

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        return deepcopy(self.candidates.get(job_id, []))

    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.allowlist[entry["id"]] = deepcopy(entry)
            return deepcopy(entry)

    def list_allowlist(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.allowlist.values()))

    def delete_allowlist(self, entry_id: str) -> bool:
        with self._lock:
            return self.allowlist.pop(entry_id, None) is not None

    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any]:
        with self._lock:
            self.exports[export["id"]] = deepcopy(export)
            self.export_content[export["id"]] = bytes(content)
            return deepcopy(export)

    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None:
        if export_id not in self.exports:
            return None
        return deepcopy(self.exports[export_id]), bytes(self.export_content[export_id])

    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.enrollments[enrollment["enrollment_id"]] = deepcopy(enrollment)
            return deepcopy(enrollment)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        value = self.enrollments.get(enrollment_id)
        return deepcopy(value) if value else None

    def list_enrollments(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.enrollments.values()))

    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self.create_enrollment(enrollment)

    def claim_enrollment(self, token_hash: str, now: datetime) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            enrollment = next(
                (item for item in self.enrollments.values() if item["token_hash"] == token_hash),
                None,
            )
            if enrollment is None:
                return None, "NOT_FOUND"
            if enrollment.get("revoked_at") is not None:
                return deepcopy(enrollment), "REVOKED"
            if enrollment.get("claimed_at") is not None:
                return deepcopy(enrollment), "CLAIMED"
            if datetime.fromisoformat(enrollment["expires_at"]) <= now:
                return deepcopy(enrollment), "EXPIRED"
            enrollment["claimed_at"] = now.isoformat()
            return deepcopy(enrollment), "OK"

    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.sensor_credentials[credential["sensor_id"]] = deepcopy(credential)
            return deepcopy(credential)

    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None:
        value = self.sensor_credentials.get(sensor_id)
        return deepcopy(value) if value else None

    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            sensor = self.sensors.get(sensor_id)
            if sensor is None:
                return None, "NOT_FOUND"
            if sensor.get("config_version") != expected_version:
                return deepcopy(sensor), "CONFLICT"
            sensor.update(deepcopy(configuration))
            sensor["config_version"] = expected_version + 1
            return deepcopy(sensor), "OK"


class SQLiteRepository:
    """외부 서비스 없이 계약 테스트 가능한 SQLite adapter. 같은 경계로 PostgreSQL 교체 가능."""

    def __init__(self, path: str | Path) -> None:
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.RLock()
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS objects (
              kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
              PRIMARY KEY(kind, id)
            );
            CREATE TABLE IF NOT EXISTS idempotency (
              key TEXT PRIMARY KEY, job_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS candidates (
              job_id TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS export_blobs (
              export_id TEXT PRIMARY KEY, content BLOB NOT NULL
            );
        """)
        self.connection.commit()

    @staticmethod
    def _serialize(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"), default=str)

    def _put(self, kind: str, object_id: str, value: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT INTO objects(kind,id,data) VALUES(?,?,?) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (kind, object_id, self._serialize(value)),
            )
            self.connection.commit()
        return deepcopy(value)

    def _get(self, kind: str, object_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT data FROM objects WHERE kind=? AND id=?", (kind, object_id)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def _list(self, kind: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM objects WHERE kind=? ORDER BY rowid", (kind,)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def ready(self) -> bool:
        try:
            return bool(self.connection.execute("SELECT 1").fetchone() == (1,))
        except sqlite3.Error:
            return False

    def close(self) -> None:
        self.connection.close()

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
        with self._lock:
            row = self.connection.execute(
                "SELECT job_id FROM idempotency WHERE key=?", (job["idempotency_key"],)
            ).fetchone()
            if row:
                existing = self.get_job(row[0])
                if existing is None:
                    raise RuntimeError("idempotency ledger references missing job")
                return existing, False
            self._put("job", job["id"], job)
            self.connection.execute(
                "INSERT INTO idempotency(key,job_id) VALUES(?,?)",
                (job["idempotency_key"], job["id"]),
            )
            self.connection.commit()
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        return self._put("job", job["id"], job)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return self._get("job", job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        return self._list("job")

    def delete_job(self, job_id: str) -> bool:
        with self._lock:
            job = self.get_job(job_id)
            if job is None:
                return False
            export_rows = self.connection.execute(
                "SELECT id FROM objects WHERE kind='export' AND json_extract(data, '$.job_id')=?",
                (job_id,),
            ).fetchall()
            export_ids = [str(row[0]) for row in export_rows]
            if export_ids:
                placeholders = ",".join("?" for _ in export_ids)
                self.connection.execute(
                    f"DELETE FROM export_blobs WHERE export_id IN ({placeholders})", export_ids
                )
                self.connection.execute(
                    f"DELETE FROM objects WHERE kind='export' AND id IN ({placeholders})",
                    export_ids,
                )
            self.connection.execute("DELETE FROM candidates WHERE job_id=?", (job_id,))
            self.connection.execute("DELETE FROM idempotency WHERE job_id=?", (job_id,))
            cursor = self.connection.execute(
                "DELETE FROM objects WHERE kind='job' AND id=?", (job_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT INTO candidates(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                (job_id, self._serialize(candidates)),
            )
            self.connection.commit()

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        row = self.connection.execute(
            "SELECT data FROM candidates WHERE job_id=?", (job_id,)
        ).fetchone()
        return json.loads(row[0]) if row else []

    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]:
        return self._put("allowlist", entry["id"], entry)

    def list_allowlist(self) -> list[dict[str, Any]]:
        return self._list("allowlist")

    def delete_allowlist(self, entry_id: str) -> bool:
        with self._lock:
            cursor = self.connection.execute(
                "DELETE FROM objects WHERE kind='allowlist' AND id=?", (entry_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any]:
        with self._lock:
            self._put("export", export["id"], export)
            self.connection.execute(
                "INSERT INTO export_blobs(export_id,content) VALUES(?,?) "
                "ON CONFLICT(export_id) DO UPDATE SET content=excluded.content",
                (export["id"], content),
            )
            self.connection.commit()
            return deepcopy(export)

    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None:
        metadata = self._get("export", export_id)
        row = self.connection.execute(
            "SELECT content FROM export_blobs WHERE export_id=?", (export_id,)
        ).fetchone()
        return (metadata, bytes(row[0])) if metadata is not None and row else None

    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self._put("enrollment", enrollment["enrollment_id"], enrollment)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        return self._get("enrollment", enrollment_id)

    def list_enrollments(self) -> list[dict[str, Any]]:
        return self._list("enrollment")

    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self.create_enrollment(enrollment)

    def claim_enrollment(self, token_hash: str, now: datetime) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            row = self.connection.execute(
                "SELECT id,data FROM objects WHERE kind='enrollment' "
                "AND json_extract(data, '$.token_hash')=?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None, "NOT_FOUND"
            enrollment = json.loads(row[1])
            if enrollment.get("revoked_at") is not None:
                return enrollment, "REVOKED"
            if enrollment.get("claimed_at") is not None:
                return enrollment, "CLAIMED"
            if datetime.fromisoformat(enrollment["expires_at"]) <= now:
                return enrollment, "EXPIRED"
            enrollment["claimed_at"] = now.isoformat()
            self._put("enrollment", str(row[0]), enrollment)
            return enrollment, "OK"

    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor_credential", credential["sensor_id"], credential)

    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor_credential", sensor_id)

    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            sensor = self.get_sensor(sensor_id)
            if sensor is None:
                return None, "NOT_FOUND"
            if sensor.get("config_version") != expected_version:
                return sensor, "CONFLICT"
            sensor.update(configuration)
            sensor["config_version"] = expected_version + 1
            return self.upsert_sensor(sensor), "OK"
