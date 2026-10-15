"""Actual PostgreSQL adapter/loader contract, modeled DB transport (not deployed PG)."""

from copy import deepcopy
from types import SimpleNamespace

import pytest
from c2hunter_worker.analysis import execute_analysis
from c2hunter_worker.storage import PostgresJobLoader
from psycopg.pq import TransactionStatus
from test_ddos_attack_api import ddos_payload
from test_ddos_reference import MemoryRepository, Settings, TestClient, create_app

from c2hunter_controller.production import PostgresRepository


class Connection:
    closed = False
    autocommit = False
    info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)

    def __init__(self, metadata, rows):
        self.metadata, self.rows = metadata, rows
        self.queries = []
        self.row = None
        self.all = []

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def commit(self):
        pass

    def rollback(self):
        pass

    def execute(self, query, parameters=()):
        import json

        self.queries.append(query)
        if query.startswith("SET"):
            return
        if "controller_objects" in query:
            self.row = (deepcopy(self.metadata),)
        elif "sum(octet_length" in query:
            self.row = (1, len(json.dumps(self.rows).encode()), len(self.rows))
        elif "job_flow_record_chunks" in query:
            self.all = [(deepcopy(self.rows),)]
        elif "job_payload_signatures" in query:
            self.row = ([],)
        else:
            raise AssertionError(query)

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.all


def test_postgres_preflight_and_real_loader_reference_only_delivery():
    source = ddos_payload("source")
    connection = Connection(
        {"id": "source", "dataset_id": "dataset", "status": "COMPLETED"}, source["flow_records"]
    )
    repo = PostgresRepository("postgresql://unused", None)
    repo._connection = connection
    snapshot = repo.read_ddos_reference("source", "dataset")
    assert len(snapshot["records"]) == 100
    assert connection.queries.index(
        next(q for q in connection.queries if "sum(octet_length" in q)
    ) < connection.queries.index(
        next(
            q for q in connection.queries if q.startswith("SELECT data FROM job_flow_record_chunks")
        )
    )
    memory = MemoryRepository()
    memory.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), memory))
    normal = client.post("/api/v1/analysis-jobs", json=source).json()
    request = ddos_payload("attack")
    request["ddos_normal_reference"] = {"job_id": normal["id"], "dataset_id": normal["dataset_id"]}
    accepted = client.post("/api/v1/analysis-jobs", json=request)
    assert accepted.status_code == 201, accepted.text
    saved = memory.get_job(accepted.json()["id"])
    metadata = {k: v for k, v in saved.items() if k not in {"flow_records", "payload_signatures"}}
    connection = Connection(metadata, saved["flow_records"])
    loader = PostgresJobLoader("postgresql://unused")
    loader._connection = connection
    loaded = loader.load(saved["id"])  # Production queue carries only this ID.
    assert loaded["ddos_reference_snapshot"] == saved["ddos_reference_snapshot"]
    result = execute_analysis(loaded)
    normal_result = result["ddos_attack"]["findings"][0]["signature_candidates"][0]["evaluation"][
        "normal"
    ]
    assert normal_result["result"]["matched_records"] == 100
    assert normal_result["result"]["record_match_rate"] == 1
    metadata.pop("ddos_reference_snapshot")
    with pytest.raises(ValueError, match="reference"):
        loader.load(saved["id"])
