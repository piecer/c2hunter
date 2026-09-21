from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import Any


class PostgresJobLoader:
    """Load immutable analysis payloads by reference instead of carrying them through Redis."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._connection: Any = None

    @property
    def connection(self) -> Any:
        if self._connection is not None and not self._connection.closed:
            return self._connection
        import psycopg

        self._connection = psycopg.connect(self.database_url, autocommit=True)
        return self._connection

    def load(self, job_id: str) -> dict[str, Any]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=%s",
                (job_id,),
            )
            metadata_row = cursor.fetchone()
            if metadata_row is None:
                raise LookupError(f"analysis job {job_id} was not found")
            cursor.execute(
                "SELECT data FROM job_flow_record_chunks "
                "WHERE job_id=%s ORDER BY chunk_no",
                (job_id,),
            )
            flow_rows = cursor.fetchall()
            flow_row = None
            if not flow_rows:
                cursor.execute(
                    "SELECT data FROM job_flow_records WHERE job_id=%s", (job_id,)
                )
                flow_row = cursor.fetchone()
            cursor.execute(
                "SELECT data FROM job_payload_signatures WHERE job_id=%s", (job_id,)
            )
            signature_row = cursor.fetchone()
        raw_metadata = metadata_row[0]
        metadata = (
            dict(raw_metadata)
            if isinstance(raw_metadata, dict)
            else json.loads(raw_metadata)
        )
        if flow_rows:
            flow_records: list[Any] = []
            for row in flow_rows:
                raw_chunk = row[0]
                chunk = (
                    list(raw_chunk)
                    if isinstance(raw_chunk, list)
                    else json.loads(raw_chunk)
                )
                if not isinstance(chunk, list):
                    raise RuntimeError("stored flow-record chunk is not a JSON array")
                flow_records.extend(chunk)
            metadata["flow_records"] = flow_records
        elif flow_row is None:
            metadata["flow_records"] = []
        else:
            raw_flows = flow_row[0]
            metadata["flow_records"] = (
                list(raw_flows)
                if isinstance(raw_flows, list)
                else json.loads(raw_flows)
            )
        if signature_row is None:
            metadata["payload_signatures"] = []
        else:
            raw_signatures = signature_row[0]
            metadata["payload_signatures"] = (
                list(raw_signatures)
                if isinstance(raw_signatures, list)
                else json.loads(raw_signatures)
            )
        return metadata

    def claim_analysis(
        self,
        job_id: str,
        *,
        attempt: int,
        lease_token: str,
        lease_seconds: int,
    ) -> tuple[str, str | None]:
        with self.connection.transaction(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                (job_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return ("SUPERSEDED", None)
            raw = row[0]
            job = dict(raw) if isinstance(raw, dict) else json.loads(raw)
            processing = job.get("processing")
            if job.get("status") != "ANALYZING" or not isinstance(processing, dict):
                return ("SUPERSEDED", None)
            cursor.execute("SELECT clock_timestamp()")
            clock_row = cursor.fetchone()
            if clock_row is None or not isinstance(clock_row[0], datetime):
                raise RuntimeError("database clock unavailable")
            now = clock_row[0]
            if processing.get("phase") in {"ANALYSIS_CLAIMED", "ANALYSIS_RUNNING"}:
                raw_expiry = processing.get("analysis_lease_expires_at")
                if raw_expiry and now < datetime.fromisoformat(str(raw_expiry)):
                    return ("ACTIVE", None)
                occurred_at = now.isoformat()
                job["status"] = "FAILED"
                job["error_code"] = "ANALYSIS_WORKER_LOST"
                job["error"] = "analysis worker lease expired before a durable result"
                job["completed_at"] = occurred_at
                job["updated_at"] = occurred_at
                failed_processing = dict(processing)
                failed_processing.update(
                    {
                        "phase": "FAILED",
                        "phase_started_at": occurred_at,
                        "updated_at": occurred_at,
                    }
                )
                failed_processing.pop("analysis_claim_token", None)
                failed_processing.pop("analysis_lease_expires_at", None)
                job["processing"] = failed_processing
                cursor.execute(
                    "UPDATE controller_objects SET data=%s::jsonb WHERE kind='job' AND id=%s",
                    (json.dumps(job, separators=(",", ":"), default=str), job_id),
                )
                return ("SUPERSEDED", None)
            if int(processing.get("attempt", -1)) != attempt:
                return ("SUPERSEDED", None)
            phase = processing.get("phase")
            if phase not in {"ANALYSIS_ENQUEUE_PENDING", "ANALYSIS_QUEUED"}:
                return ("SUPERSEDED", None)
            if processing.get("lease_token") != lease_token:
                return ("SUPERSEDED", None)
            occurred_at = now.isoformat()
            analysis_claim_token = str(uuid.uuid4())
            claimed_processing = dict(processing)
            claimed_processing.update(
                {
                    "phase": "ANALYSIS_CLAIMED",
                    "phase_started_at": occurred_at,
                    "updated_at": occurred_at,
                    "analysis_claim_token": analysis_claim_token,
                    "analysis_lease_expires_at": (
                        now + timedelta(seconds=lease_seconds)
                    ).isoformat(),
                }
            )
            claimed_processing.pop("lease_expires_at", None)
            job["processing"] = claimed_processing
            job["analysis_claimed_at"] = occurred_at
            job["updated_at"] = occurred_at
            cursor.execute(
                "UPDATE controller_objects SET data=%s::jsonb WHERE kind='job' AND id=%s",
                (json.dumps(job, separators=(",", ":"), default=str), job_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("analysis claim update was not persisted")
            return ("CLAIMED", analysis_claim_token)

    def renew_analysis(
        self, job_id: str, *, claim_token: str, lease_seconds: int
    ) -> bool:
        with self.connection.transaction(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                (job_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return False
            raw = row[0]
            job = dict(raw) if isinstance(raw, dict) else json.loads(raw)
            processing = job.get("processing")
            cursor.execute("SELECT clock_timestamp()")
            clock_row = cursor.fetchone()
            if clock_row is None or not isinstance(clock_row[0], datetime):
                raise RuntimeError("database clock unavailable")
            now = clock_row[0]
            if (
                job.get("status") != "ANALYZING"
                or not isinstance(processing, dict)
                or processing.get("phase")
                not in {"ANALYSIS_CLAIMED", "ANALYSIS_RUNNING"}
                or processing.get("analysis_claim_token") != claim_token
            ):
                return False
            raw_expiry = processing.get("analysis_lease_expires_at")
            if not raw_expiry or now >= datetime.fromisoformat(str(raw_expiry)):
                return False
            occurred_at = now.isoformat()
            renewed_processing = dict(processing)
            renewed_processing["analysis_lease_expires_at"] = (
                now + timedelta(seconds=lease_seconds)
            ).isoformat()
            renewed_processing["updated_at"] = occurred_at
            job["processing"] = renewed_processing
            job["updated_at"] = occurred_at
            cursor.execute(
                "UPDATE controller_objects SET data=%s::jsonb WHERE kind='job' AND id=%s",
                (json.dumps(job, separators=(",", ":"), default=str), job_id),
            )
            return cursor.rowcount == 1

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
