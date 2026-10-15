"""Real offline upload/preparation/ID queue/loader/worker/result-drain composition."""

from copy import deepcopy

from c2hunter_worker.analysis import execute_analysis
from c2hunter_worker.storage import PostgresJobLoader
from fastapi.testclient import TestClient
from test_ddos_reference_admission import capture
from test_ddos_reference_postgres_contract import Connection
from test_durable_pipeline import QueueStub

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository


def test_uploaded_reference_survives_source_deletion_and_id_only_queue(tmp_path):
    path = tmp_path / "durable.db"
    repo = SQLiteRepository(path)
    client = TestClient(create_app(Settings(environment="test"), repo))
    url = (
        "/api/v1/pcap-analysis-jobs?name=normal&filename=normal.pcap"
        "&analysis_module=ddos_attack&ddos_min_source_count=3&ddos_min_packet_count=6"
        "&ddos_min_packets_per_second=1&ddos_min_bits_per_second=1"
    )
    normal = client.post(
        url, content=capture(), headers={"content-type": "application/octet-stream"}
    )
    assert normal.status_code == 201, normal.text
    normal = normal.json()
    queue = QueueStub()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False), repo, queue=queue
        )
    )
    accepted = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "attack",
            "filename": "attack.pcap",
            "idempotency_key": "durable-attack",
            "analysis_module": "ddos_attack",
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {
                "module": "ddos_attack",
                "ddos_min_source_count": 3,
                "ddos_min_packet_count": 6,
                "ddos_min_packets_per_second": 1,
                "ddos_min_bits_per_second": 1,
            },
            "ddos_normal_reference": {"job_id": normal["id"], "dataset_id": normal["dataset_id"]},
        },
    )
    assert accepted.status_code == 201, accepted.text
    job_id = accepted.json()["id"]
    snapshot = deepcopy(repo.get_job(job_id)["ddos_reference_snapshot"])
    uploaded = client.put(
        f"/api/v1/pcap-analysis-jobs/{job_id}/capture",
        content=capture(60),
        headers={"content-type": "application/octet-stream"},
    )
    assert uploaded.status_code == 202, uploaded.text
    repo.delete_job(normal["id"])
    repo.close()
    repo = SQLiteRepository(path)
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False), repo, queue=queue
        )
    )
    assert client.app.state.process_pcap_preparations_once()
    assert len(queue.jobs) == 1
    envelope = queue.jobs[0]
    assert set(envelope) <= {"id", "message_id", "preparation_attempt", "preparation_lease_token"}
    saved = repo.get_job(job_id)
    assert saved["ddos_reference_snapshot"] == snapshot
    # DB transport modeled; production loader, analyzer and response drain are real.
    metadata = {k: v for k, v in saved.items() if k not in {"flow_records", "payload_signatures"}}
    loader = PostgresJobLoader("postgresql://unused")
    loader._connection = Connection(metadata, saved["flow_records"])
    result = execute_analysis(loader.load(envelope["id"]))
    queue.results.append(
        {
            **envelope,
            "job_id": job_id,
            "receipt": "result-1",
            "status": "COMPLETED",
            "result": result,
        }
    )
    assert client.app.state.process_results_once()
    final = client.get(f"/api/v1/analysis-jobs/{job_id}").json()
    assert final["status"] == "COMPLETED", final
    assert "ddos_reference_snapshot" not in final
    evaluation = final["ddos_attack"]["findings"][0]["signature_candidates"][0]["evaluation"]
    assert evaluation["normal"]["reference"] == snapshot["reference"]
    assert evaluation["normal"]["result"]["matched_packets"] == 12
    assert queue.acked == ["result-1"]
    repo.close()
