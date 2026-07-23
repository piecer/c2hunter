from __future__ import annotations

import json
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
        if flow_row is None:
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

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
