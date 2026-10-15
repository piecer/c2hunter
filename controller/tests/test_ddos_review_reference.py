"""Independent source-bound reference audit. Offline only; no product edits."""

import hashlib
import importlib
import json
import sqlite3
import struct
from copy import deepcopy
from pathlib import Path

import pytest
from c2hunter_analysis.ddos_signatures import digest, load_reference
from c2hunter_worker.analysis import execute_analysis
from c2hunter_worker.storage import PostgresJobLoader
from fastapi.testclient import TestClient
from test_ddos_attack_api import ddos_payload
from test_ddos_reference_admission import capture
from test_ddos_reference_postgres_contract import Connection
from test_durable_pipeline import QueueStub

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.ddos_ai import build_ddos_input
from c2hunter_controller.ddos_reference import MAX_SOURCE_BYTES, ReferenceError
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository

C = Path(__file__).resolve().parents[2]


def create(client, payload):
    response = client.post("/api/v1/analysis-jobs", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def world(tmp_path, sqlite=True):
    repo = SQLiteRepository(tmp_path / "db") if sqlite else MemoryRepository()
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    normal = create(client, ddos_payload("normal"))
    selected = {"job_id": normal["id"], "dataset_id": normal["dataset_id"]}
    attack = create(client, {**ddos_payload("attack"), "ddos_normal_reference": selected})
    return repo, client, normal, attack, selected


def test_origins():
    modules = (
        "c2hunter_controller.app",
        "c2hunter_controller.ddos_reference",
        "c2hunter_controller.repositories",
        "c2hunter_controller.production",
        "c2hunter_analysis.ddos_signatures",
        "c2hunter_worker.analysis",
        "c2hunter_worker.storage",
        "test_ddos_attack_api",
        "test_ddos_reference_admission",
    )
    origins = {}
    for name in modules:
        p = Path(importlib.import_module(name).__file__).resolve()
        assert p.is_relative_to(C), (name, p)
        origins[name] = {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}


@pytest.mark.parametrize("sqlite", [False, True])
def test_lifecycle_and_binding_controls(tmp_path, sqlite):
    repo, client, normal, attack, selected = world(tmp_path, sqlite)
    saved = repo.get_job(attack["id"])
    initial = deepcopy(saved["ddos_reference_snapshot"])
    original = repo.get_job(normal["id"])
    child = client.post(
        f"/api/v1/analysis-jobs/{attack['id']}/reanalyze", json={"idempotency_key": "child"}
    )
    assert child.status_code == 201, child.text
    grandchild = client.post(
        f"/api/v1/analysis-jobs/{child.json()['id']}/reanalyze",
        json={"idempotency_key": "grandchild"},
    )
    assert grandchild.status_code == 201, grandchild.text
    for j in (child.json(), grandchild.json()):
        assert j["dataset_id"] == attack["dataset_id"] != normal["dataset_id"]
        assert repo.get_job(j["id"])["ddos_reference_snapshot"] == initial
    cleared = client.post(
        f"/api/v1/analysis-jobs/{grandchild.json()['id']}/reanalyze",
        json={"idempotency_key": "clear", "ddos_normal_reference": None},
    )
    assert cleared.status_code == 201, cleared.text
    assert load_reference(repo.get_job(cleared.json()["id"])) is None
    assert repo.get_job(normal["id"]) == original
    for mutation in ("missing_snapshot", "missing_binding", "corrupt_binding", "rehashed_foreign"):
        bad = deepcopy(saved)
        if mutation == "missing_snapshot":
            bad.pop("ddos_reference_snapshot")
        if mutation == "missing_binding":
            bad.pop("ddos_reference_binding")
        if mutation == "corrupt_binding":
            bad["ddos_reference_binding"] = "0" * 64
        if mutation == "rehashed_foreign":
            snap = bad["ddos_reference_snapshot"]
            snap["reference"]["dataset_id"] = "foreign"
            snap["records"][0]["destination_ip"] = "203.0.113.99"
            snap["reference"]["content_digest"] = digest(snap["records"])
        loader = PostgresJobLoader("postgresql://unused")
        loader._connection = Connection(
            {k: v for k, v in bad.items() if k != "flow_records"}, bad["flow_records"]
        )
        with pytest.raises(ValueError, match="reference"):
            loader.load(bad["id"])
    legacy = deepcopy(saved)
    legacy.pop("ddos_reference_binding")
    legacy.pop("ddos_reference_snapshot")
    assert (
        execute_analysis(legacy)["ddos_attack"]["findings"][0]["signature_candidates"][0][
            "evaluation"
        ]["normal"]["status"]
        == "UNMEASURED"
    )
    repo.delete_job(normal["id"])
    if sqlite:
        repo.close()
        repo = SQLiteRepository(tmp_path / "db")
    assert load_reference(repo.get_job(attack["id"])) == initial
    result = execute_analysis(repo.get_job(attack["id"]))
    assert (
        result["ddos_attack"]["findings"][0]["signature_candidates"][0]["evaluation"]["normal"][
            "reference"
        ]
        == initial["reference"]
    )
    assert "ddos_reference" not in json.dumps(build_ddos_input(result["ddos_attack"]))
    if sqlite:
        repo.close()


@pytest.mark.parametrize(
    "kind", ["valid", "valid_zero", "missing", "foreign", "missing_zero", "foreign_zero"]
)
def test_actual_result_drain_binding(tmp_path, kind):
    repo, client, normal, attack, selected = world(tmp_path)
    queue = QueueStub()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False), repo, queue=queue
        )
    )
    response = client.post(
        f"/api/v1/analysis-jobs/{attack['id']}/reanalyze", json={"idempotency_key": "queued"}
    )
    assert response.status_code == 201, response.text
    accepted = response.json()
    job_id = accepted["id"]
    assert len(queue.jobs) == 1 and set(queue.jobs[0]) <= {"id", "message_id"}
    saved = repo.get_job(job_id)
    producer = deepcopy(saved)
    if kind.startswith("missing"):
        producer.pop("ddos_reference_snapshot")
        producer.pop("ddos_reference_binding")
    if kind.startswith("foreign"):
        producer["id"] = "other-job"
        producer["dataset_id"] = "other-attack-dataset"
        producer["ddos_reference_snapshot"]["reference"]["dataset_id"] = "other-reference-dataset"
        producer["ddos_reference_binding"] = digest(producer["ddos_reference_snapshot"])
    if kind.endswith("zero"):
        producer["flow_records"] = []
    loader = PostgresJobLoader("postgresql://unused")
    loader._connection = Connection(
        {k: v for k, v in producer.items() if k not in {"flow_records", "payload_signatures"}},
        producer["flow_records"],
    )
    result = execute_analysis(loader.load(producer["id"]))
    if kind.endswith("zero"):
        assert result["ddos_attack"]["findings"] == []
    queue.results.append(
        {"job_id": job_id, "receipt": "receipt", "status": "COMPLETED", "result": result}
    )
    assert client.app.state.process_results_once()
    final = repo.get_job(job_id)
    assert queue.acked == ["receipt"]
    repo.close()
    assert final["status"] == ("COMPLETED" if kind.startswith("valid") else "FAILED"), (
        "Foreign/missing-reference worker result was persisted"
    )
    if not kind.startswith("valid"):
        assert final["error_code"] == "INVALID_DDOS_RESULT"


@pytest.mark.parametrize("surface", ["create", "get", "list", "reanalyze", "replay", "cancel"])
def test_no_private_binding_publication(tmp_path, surface):
    repo, client, normal, attack, selected = world(tmp_path)
    if surface == "create":
        value = attack
    elif surface == "get":
        value = client.get(f"/api/v1/analysis-jobs/{attack['id']}").json()
    elif surface == "list":
        value = client.get("/api/v1/analysis-jobs").json()
    elif surface == "replay":
        value = client.post(
            "/api/v1/analysis-jobs",
            json={**ddos_payload("attack"), "ddos_normal_reference": selected},
        ).json()
    else:
        if surface == "cancel":
            client = TestClient(
                create_app(
                    Settings(environment="test", inline_flow_records_enabled=False),
                    repo,
                    queue=QueueStub(),
                )
            )
        value = client.post(
            f"/api/v1/analysis-jobs/{attack['id']}/reanalyze",
            json={"idempotency_key": "private-child"},
        ).json()
        if surface == "cancel":
            response = client.post(
                f"/api/v1/analysis-jobs/{value['id']}/cancel", json={"reason": "privacy control"}
            )
            assert response.status_code == 200, response.text
            value = response.json()
    encoded = json.dumps(value)
    repo.close()
    assert "ddos_reference_snapshot" not in encoded
    assert "ddos_reference_binding" not in encoded
    assert "ddos_request_binding" not in encoded


@pytest.mark.parametrize("module", ["c2", "ddos_attack"])
@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("generations", [0, 2])
def test_original_offline_partial_reference_rejection(tmp_path, module, partial, generations):
    repo = SQLiteRepository(tmp_path / "partial.db")
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    # A valid Ethernet frame with unsupported EtherType: parser truth records a skipped packet.
    skipped = b"\x00" * 12 + b"\x88\xb5" + b"\x00" * 46
    mixed = capture() + (
        struct.pack("<IIII", 1784505620, 0, len(skipped), len(skipped)) + skipped
        if partial
        else b""
    )
    response = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "partial", "filename": "partial.pcap", "analysis_module": module},
        content=mixed,
        headers={"content-type": "application/octet-stream"},
    )
    assert response.status_code == 201, response.text
    source = response.json()
    assert source["source"]["skipped_packet_count"] == int(partial)
    for generation in range(generations):
        child = client.post(
            f"/api/v1/analysis-jobs/{source['id']}/reanalyze",
            json={"idempotency_key": f"child-{generation}"},
        )
        assert child.status_code == 201, child.text
        source = child.json()
    assert source["status"] == "COMPLETED"
    selected = {"job_id": source["id"], "dataset_id": source["dataset_id"]}
    before = len(repo.list_jobs())
    response = client.post(
        "/api/v1/analysis-jobs",
        json={**ddos_payload("selected-partial"), "ddos_normal_reference": selected},
    )
    repo.close()
    assert response.status_code == (422 if partial else 201), response.text[:500]
    if partial:
        assert response.json()["error"]["code"] == "DDOS_REFERENCE_INCOMPLETE"
        # No new job or worker delivery on failed reference admission.
        reopened = SQLiteRepository(tmp_path / "partial.db")
        assert len(reopened.list_jobs()) == before
        reopened.close()


@pytest.mark.parametrize("case", ["unicode", "huge_unselected", "count"])
def test_sqlite_actual_source_bounds_before_hydration(tmp_path, case):
    repo = SQLiteRepository(tmp_path / "bounds.db")
    job = {
        "id": "n",
        "dataset_id": "d",
        "status": "COMPLETED",
        "flow_records": [{"packet_count": 1}],
    }
    repo.save_job(job)
    # Metadata counters are deliberately small; admission must count stored source.
    rows = (
        [{"packet_count": 1, "unused": "😀" * (MAX_SOURCE_BYTES // 4)}]
        if case == "unicode"
        else [{"packet_count": 1, "unused": "x" * MAX_SOURCE_BYTES}]
        if case == "huge_unselected"
        else [{"packet_count": 1}] * 513
    )
    raw = json.dumps(rows, ensure_ascii=False)
    with repo.connection:
        repo.connection.execute("UPDATE job_flow_records SET data=? WHERE job_id=?", (raw, "n"))
    queries = []
    repo.connection.set_trace_callback(queries.append)
    with pytest.raises(ReferenceError):
        repo.read_ddos_reference("n", "d")
    assert not any(q.startswith("SELECT data FROM job_flow_records") for q in queries)
    repo.close()


def test_memory_avoids_unselected_deepcopy():
    class Bomb:
        def __deepcopy__(self, memo):
            raise AssertionError("unselected sidecar copied")

    repo = MemoryRepository()
    repo.jobs["n"] = {
        "id": "n",
        "dataset_id": "d",
        "status": "COMPLETED",
        "flow_records": [{"packet_count": 1, "unused": Bomb()}],
    }
    assert len(repo.read_ddos_reference("n", "d")["records"]) == 1


def test_sqlite_transaction_snapshot_survives_interleaved_writer(tmp_path):
    p = tmp_path / "race.db"
    repo = SQLiteRepository(p)
    repo.connection.execute("PRAGMA journal_mode=WAL")
    repo.save_job(
        {"id": "n", "dataset_id": "d", "status": "COMPLETED", "flow_records": [{"packet_count": 1}]}
    )
    writer = sqlite3.connect(p)
    fired = []

    def trace(query):
        if query.startswith("SELECT data FROM job_flow_records") and not fired:
            fired.append(True)
            with writer:
                writer.execute(
                    "UPDATE job_flow_records SET data=? WHERE job_id='n'",
                    (json.dumps([{"packet_count": 2}] * 513),),
                )
                writer.execute(
                    "UPDATE objects SET data=json_set(data,'$.dataset_id','swapped') "
                    "WHERE kind='job' AND id='n'"
                )

    repo.connection.set_trace_callback(trace)
    result = repo.read_ddos_reference("n", "d")
    assert fired and len(result["records"]) == 1 and result["records"][0]["packet_count"] == 1
    with pytest.raises(ReferenceError, match="IDENTITY"):
        repo.read_ddos_reference("n", "d")
    writer.close()
    repo.close()


@pytest.mark.parametrize(
    "case", ["chunks_512", "chunks_513", "dense", "huge", "legacy", "legacy_huge", "mixed"]
)
def test_modeled_postgres_scalar_contract(case):
    # A deterministic SQL protocol double, not deployed PostgreSQL execution.
    class Model(Connection):
        def __init__(self):
            super().__init__({"id": "n", "dataset_id": "d", "status": "COMPLETED"}, [])
            count = 513 if case in {"chunks_513", "dense"} else 512 if case == "chunks_512" else 1
            self.chunks = (
                []
                if case.startswith("legacy")
                else [[{"packet_count": 1}]] * count
                if case.startswith("chunks_")
                else [[{"packet_count": 1}] * count]
            )
            self.legacy = (
                [{"packet_count": 1, "unused": "😀" * MAX_SOURCE_BYTES}]
                if case in {"legacy_huge", "mixed"}
                else [{"packet_count": 1}]
            )
            if case == "huge":
                self.chunks = [[{"packet_count": 1, "unused": "😀" * MAX_SOURCE_BYTES}]]
            self.hydrated = []

        def execute(self, q, parameters=()):
            self.queries.append(q)
            if q.startswith("SET"):
                return
            if "controller_objects" in q:
                self.row = (self.metadata,)
            elif "sum(octet_length" in q:
                self.row = (
                    len(self.chunks),
                    sum(len(json.dumps(c, ensure_ascii=False).encode()) for c in self.chunks),
                    sum(map(len, self.chunks)),
                )
            elif "octet_length" in q:
                self.row = (
                    len(json.dumps(self.legacy, ensure_ascii=False).encode()),
                    len(self.legacy),
                )
            elif q.startswith("SELECT data FROM job_flow_record_chunks"):
                self.hydrated.append("chunks")
                self.all = [(x,) for x in self.chunks]
            elif q.startswith("SELECT data FROM job_flow_records"):
                self.hydrated.append("legacy")
                self.row = (self.legacy,)
            else:
                raise AssertionError(q)

    db = Model()
    repo = PostgresRepository("postgresql://unused", None)
    repo._connection = db
    rejected = case in {"chunks_513", "dense", "huge", "legacy_huge"}
    if rejected:
        with pytest.raises(ReferenceError):
            repo.read_ddos_reference("n", "d")
        assert not db.hydrated
    else:
        out = repo.read_ddos_reference("n", "d")
        assert len(out["records"]) == (512 if case == "chunks_512" else 1)
        assert db.hydrated == (["legacy"] if case == "legacy" else ["chunks"])
    assert db.queries[0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"


@pytest.mark.parametrize("backend", ["memory", "sqlite", "postgres-model"])
@pytest.mark.parametrize(
    "facts",
    [
        {"source": {"skipped_packet_count": 1}},
        {"capture_quality": {"dropped_packet_count": 1}},
        {"capture_limit": {"discarded_packets": 1}},
        {"capture_incomplete": True},
        {"error_code": "LIVE_CAPTURE_RESTART_INCOMPLETE"},
    ],
)
def test_scalar_source_incompleteness(tmp_path, backend, facts):
    job = {
        "id": "n",
        "dataset_id": "d",
        "status": "COMPLETED",
        "flow_records": [{"packet_count": 1}],
        **facts,
    }
    if backend == "postgres-model":
        repo = PostgresRepository("postgresql://unused", None)
        db = Connection({k: v for k, v in job.items() if k != "flow_records"}, job["flow_records"])
        repo._connection = db
    else:
        repo = (
            MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "scalar.db")
        )
        repo.save_job(job)
    with pytest.raises(ReferenceError, match="DDOS_REFERENCE_INCOMPLETE"):
        repo.read_ddos_reference("n", "d")
    if backend == "postgres-model":
        assert not any(q.startswith("SELECT data FROM job_flow") for q in db.queries)
        projection = next(q for q in db.queries if "controller_objects" in q)
        assert "skipped_packet_count" in projection and "dropped_packet_count" in projection
    if backend == "sqlite":
        repo.close()


@pytest.mark.parametrize("representation", ["dict", "json", "missing"])
def test_postgres_idempotency_lookup_uses_metadata_only(representation):
    # SQL transport model only: the actual PostgresRepository cursor lifecycle runs.
    metadata = {"id": "winner", "ddos_request_binding": "a" * 64}

    class LookupConnection(Connection):
        def execute(self, query, parameters=()):
            self.queries.append(query)
            assert parameters == ("replay-key",)
            assert "job_idempotency" in query and "controller_objects" in query
            assert "job_flow" not in query
            self.row = (
                None
                if representation == "missing"
                else (json.dumps(metadata) if representation == "json" else metadata,)
            )

    db = LookupConnection(metadata, [])
    repo = PostgresRepository("postgresql://unused", None)
    repo._connection = db
    assert repo.get_job_by_idempotency("replay-key") == (
        None if representation == "missing" else metadata
    )
    assert len(db.queries) == 1
