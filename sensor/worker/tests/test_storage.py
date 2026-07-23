from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

from c2hunter_worker.storage import PostgresJobLoader


class CursorStub:
    def __init__(self) -> None:
        self.row: tuple[object, ...] | None = None

    def __enter__(self) -> CursorStub:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, parameters: tuple[str]) -> None:
        assert parameters == ("job-1",)
        if "controller_objects" in query:
            self.row = ({"id": "job-1", "dataset_id": "dataset-1"},)
        elif "job_payload_signatures" in query:
            self.row = ([{"id": "signature-1", "enabled": True}],)
        else:
            self.row = ([{"source_ip": "10.0.0.1"}],)

    def fetchone(self) -> tuple[object, ...] | None:
        return self.row


class ConnectionStub:
    def __init__(self) -> None:
        self.closed = False

    def cursor(self) -> CursorStub:
        return CursorStub()

    def close(self) -> None:
        self.closed = True


def test_postgres_job_loader_hydrates_payload_by_job_reference(
    monkeypatch: Any,
) -> None:
    connection = ConnectionStub()

    def connect(database_url: str, *, autocommit: bool) -> ConnectionStub:
        assert database_url == "postgresql://test"
        assert autocommit is True
        return connection

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    loader = PostgresJobLoader("postgresql://test")

    payload = loader.load("job-1")

    assert payload == {
        "id": "job-1",
        "dataset_id": "dataset-1",
        "flow_records": [{"source_ip": "10.0.0.1"}],
        "payload_signatures": [{"id": "signature-1", "enabled": True}],
    }
    loader.close()
    assert connection.closed is True
