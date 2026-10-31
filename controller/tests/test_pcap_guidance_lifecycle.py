from __future__ import annotations

import copy
import struct

import pytest
from test_analysis_history_pcap_api import _udp_packet
from test_analysis_job_api import START, api

from c2hunter_controller.repositories import MemoryRepository


@pytest.mark.parametrize("mode", ["valid", "old-worker", "null", "foreign", "wrong-module"])
def test_staged_preparation_real_worker_and_durable_result_readback(tmp_path, mode):
    from c2hunter_worker.analysis import execute_analysis
    from c2hunter_worker.runtime import Worker
    from fastapi.testclient import TestClient
    from test_durable_pipeline import QueueStub

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings

    repository, queue = MemoryRepository(), QueueStub()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False), repository, queue=queue
        )
    )
    created = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "guidance staged",
            "filename": "guide.pcap",
            "idempotency_key": "guide-staged",
            "analysis_module": "ddos_attack",
            "analysis": {"module": "ddos_attack"},
            "internal_networks": ["10.0.0.0/8"],
        },
    )
    assert created.status_code == 201, created.text
    job_id = created.json()["id"]
    accepted = client.put(
        f"/api/v1/pcap-analysis-jobs/{job_id}/capture",
        content=capture(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert accepted.status_code == 202, accepted.text
    assert client.app.state.process_pcap_preparations_once() is True
    (envelope,) = queue.jobs
    assert envelope["id"] == job_id

    class Loader:
        def load(self, identifier):
            return repository.get_job(identifier)

        def claim_analysis(self, identifier, **kwargs):
            return "CLAIMED", "test-claim"

        def renew_analysis(self, *args, **kwargs):
            return True

    worker = Worker(
        queue=queue,
        execute=execute_analysis,
        payload_loader=Loader(),
        health_path=tmp_path / "health.json",
    )
    result = worker._execute_job(envelope)
    assert result["status"] == "COMPLETED", result
    assert result["result"]["pcap_attack_guidance"]["candidates"][0]["family"] == "UDP_BURST"
    if mode == "old-worker":
        result["result"].pop("pcap_attack_guidance")
    elif mode == "null":
        result["result"]["pcap_attack_guidance"] = None
    elif mode == "foreign":
        result["result"]["pcap_attack_guidance"]["job_id"] = "foreign-owner"
    elif mode == "wrong-module":
        repository.jobs[job_id]["analysis"]["module"] = "c2"
    queue.results.append({**result, "receipt": "guide-result"})
    assert client.app.state.process_results_once() is True
    stored = client.get(f"/api/v1/analysis-jobs/{job_id}").json()
    assert queue.acked == ["guide-result"]
    if mode in {"null", "foreign", "wrong-module"}:
        assert stored["status"] == "FAILED"
        assert "pcap_attack_guidance" not in stored
        return
    assert stored["status"] == "COMPLETED"
    if mode == "old-worker":
        assert "pcap_attack_guidance" not in stored
        assert stored["pcap_attack_guidance_summary"] == {"status": "UNAVAILABLE"}
    else:
        assert stored["pcap_attack_guidance"] == result["result"]["pcap_attack_guidance"]


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_repository_admission_readback_and_compact_lists(tmp_path, backend):
    from test_pcap_guidance_contract import producer

    from c2hunter_controller.repositories import SQLiteRepository

    repository = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "guide.db")
    )
    try:
        job = producer()
        job.update(idempotency_key="repository-guide", status="ANALYZING", candidate_count=0)
        repository.create_job(job)
        bad = copy.deepcopy(job)
        bad["pcap_attack_guidance"]["job_id"] = "foreign"
        for save in (repository.save_job, repository.save_job_metadata):
            with pytest.raises(ValueError):
                save(bad)
        with pytest.raises(ValueError):
            repository.complete_job_with_candidates({**bad, "status": "COMPLETED"}, [])
        assert repository.complete_job_with_candidates({**job, "status": "COMPLETED"}, [])
        assert (
            repository.get_job_summary(job["id"])["pcap_attack_guidance"]
            == job["pcap_attack_guidance"]
        )
        (listed,) = repository.list_jobs()
        batched = repository.get_job_summaries([job["id"]])[job["id"]]
        assert "pcap_attack_guidance" not in batched
        assert "pcap_attack_guidance" not in listed
        assert listed["pcap_attack_guidance_summary"]["status"] == "REVIEW_CANDIDATES"
        if backend == "memory":
            repository.jobs[job["id"]]["pcap_attack_guidance"] = None
        else:
            import json

            bad["pcap_attack_guidance"] = None
            with repository.connection:
                repository.connection.execute(
                    "UPDATE objects SET data=? WHERE kind='job' AND id=?",
                    (json.dumps(bad), job["id"]),
                )
        for read in (
            lambda: repository.get_job(job["id"]),
            lambda: repository.get_job_summary(job["id"]),
            repository.list_jobs,
        ):
            with pytest.raises(ValueError):
                read()
    finally:
        if backend == "sqlite":
            repository.close()


def test_api_history_compact_and_historical_absence_is_unavailable():
    repository = MemoryRepository()
    client = api(repository=repository)
    job = upload(client)
    listed = client.get("/api/v1/analysis-jobs").json()["items"][0]
    assert "pcap_attack_guidance" not in listed
    assert listed["pcap_attack_guidance_summary"]["status"] == "REVIEW_CANDIDATES"
    repository.jobs[job["id"]].pop("pcap_attack_guidance")
    historical = client.get(f"/api/v1/analysis-jobs/{job['id']}").json()
    assert "pcap_attack_guidance" not in historical
    assert historical["pcap_attack_guidance_summary"] == {"status": "UNAVAILABLE"}


def test_api_malformed_present_returns_closed_error_not_absence():
    repository = MemoryRepository()
    client = api(repository=repository)
    job = upload(client)
    repository.jobs[job["id"]]["pcap_attack_guidance"] = None
    for path in (f"/api/v1/analysis-jobs/{job['id']}", "/api/v1/analysis-jobs"):
        response = client.get(path)
        assert response.status_code == 500
        assert response.json()["error"]["code"] == "INVALID_PCAP_GUIDANCE"


def test_postgres_loader_preserves_owner_and_adapter_rejects_bad_publication():
    from c2hunter_worker.analysis import execute_analysis
    from c2hunter_worker.storage import PostgresJobLoader
    from test_ddos_reference_postgres_contract import Connection
    from test_pcap_guidance_contract import producer

    from c2hunter_controller.production import PostgresRepository

    job = producer()
    records = job.pop("flow_records")
    connection = Connection(job, records)
    loader = PostgresJobLoader("postgresql://unused")
    loader._connection = connection
    loaded = loader.load(job["id"])
    assert loaded["source_type"] == "PCAP_UPLOAD"
    result = execute_analysis(loaded)
    assert result["pcap_attack_guidance"] == job["pcap_attack_guidance"]
    repository = PostgresRepository("postgresql://unused", None)
    repository._connection = connection
    assert (
        repository.get_job_summary(job["id"])["pcap_attack_guidance"] == job["pcap_attack_guidance"]
    )
    bad = {**job, "pcap_attack_guidance": None, "status": "COMPLETED", "candidate_count": 0}
    before = len(connection.queries)
    for write in (
        repository.create_job,
        repository.save_job,
        repository.save_job_metadata,
        repository.transition_job_terminal,
        lambda value: repository.complete_job_with_candidates(value, []),
    ):
        with pytest.raises(ValueError):
            write(bad)
    assert len(connection.queries) == before
    connection.metadata = bad
    with pytest.raises(ValueError):
        repository.get_job_summary(job["id"])
    # The analysis worker emits a fresh result, never copies the parent sidecar to another module.
    loaded["analysis"] = {"module": "network_anomaly"}
    assert "pcap_attack_guidance" not in execute_analysis(loaded)


def test_inline_invalid_guidance_terminalizes_without_publishing_artifact(monkeypatch):
    from c2hunter_analysis import ddos_job

    original = ddos_job.analyze_ddos_job

    def malformed(job):
        result = original(job)
        result["pcap_attack_guidance"] = None
        return result

    monkeypatch.setattr(ddos_job, "analyze_ddos_job", malformed)
    repository = MemoryRepository()
    client = api(repository=repository)
    response = client.post(
        "/api/v1/pcap-analysis-jobs?name=guidance&filename=guide.pcap&analysis_module=ddos_attack",
        content=capture(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INVALID_DDOS_RESULT"
    (saved,) = repository.list_jobs()
    assert saved["status"] == "FAILED"
    assert "pcap_attack_guidance" not in repository.get_job(saved["id"])


def capture() -> bytes:
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index in range(1200):
        packet = _udp_packet(f"10.0.0.{index % 20 + 1}", "203.0.113.77", 50000, index)
        data.extend(
            struct.pack("<IIII", int(START.timestamp()), index * 1000, len(packet), len(packet))
        )
        data.extend(packet)
    return bytes(data)


def upload(client):
    response = client.post(
        "/api/v1/pcap-analysis-jobs?name=guidance&filename=guide.pcap&analysis_module=ddos_attack",
        content=capture(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_binary_upload_inline_readback_and_reanalysis_bind_new_owner():
    repository = MemoryRepository()
    client = api(repository=repository)
    job = upload(client)
    guide = job["pcap_attack_guidance"]
    assert guide["job_id"] == job["id"]
    assert guide["dataset_id"] == job["dataset_id"]
    assert guide["candidates"][0]["family"] == "UDP_BURST"
    assert guide["summary"]["eligible_packet_count"] == 1200
    assert client.get(f"/api/v1/analysis-jobs/{job['id']}").json()["pcap_attack_guidance"] == guide
    child_response = client.post(
        f"/api/v1/analysis-jobs/{job['id']}/reanalyze", json={"idempotency_key": "guidance-child"}
    )
    assert child_response.status_code == 201, child_response.text
    child = child_response.json()
    assert child["pcap_attack_guidance"]["job_id"] == child["id"] != job["id"]
    assert child["pcap_attack_guidance"]["dataset_id"] == job["dataset_id"]
    assert child["pcap_attack_guidance"]["candidates"] == guide["candidates"]
    assert repository.get_job(job["id"])["pcap_attack_guidance"] == guide
