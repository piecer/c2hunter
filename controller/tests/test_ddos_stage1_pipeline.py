from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_durable_pipeline import AGENT_HEADERS, AGENT_TOKEN, QueueStub, sensor

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.jobs import evaluate_candidates
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import AnalysisParameters, DDoSAttackReport
from c2hunter_controller.storage import MemoryFlowStore

FIXTURES = Path(__file__).parents[2] / "analysis" / "tests" / "fixtures"


@pytest.mark.parametrize(
    "fixture",
    [
        "ddos-live-dns_response.json",
        "ddos-live-ntp_response.json",
        "ddos-pcap-coordination.json",
        "ddos-live-reverse-requests.json",
    ],
)
def test_real_metadata_ingress_store_queue_worker_and_c2_compatibility(fixture):
    # The sensor's HTTP transport maps Batch.Flows to records without filtering.
    data = json.loads((FIXTURES / fixture).read_text())
    if fixture == "ddos-live-reverse-requests.json":
        data = data["1000"]
    rows = data["flows"] if isinstance(data, dict) else data
    batch_id = data["batch_id"] if isinstance(data, dict) else "pcap-derived"
    repository, store, queue = MemoryRepository(), MemoryFlowStore(), QueueStub()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False),
            repository,
            flow_store=store,
            queue=queue,
        )
    )
    repository.upsert_sensor({"sensor_id": "fixture"})
    repository.save_sensor_credential(
        {"sensor_id": "fixture", "token_hash": hashlib.sha256(AGENT_TOKEN.encode()).hexdigest()}
    )
    registration = {**sensor(), "sensor_id": "fixture"}
    assert (
        client.post(
            "/api/v1/sensors/register", json=registration, headers=AGENT_HEADERS
        ).status_code
        == 201
    )
    response = client.post(
        "/api/v1/sensors/fixture/flow-batches",
        json={"batch_id": batch_id, "records": rows},
        headers=AGENT_HEADERS,
    )
    assert response.status_code == 202, response.text
    start = datetime.fromisoformat(rows[0]["timestamp"])
    request = {
        "name": "packet evidence",
        "idempotency_key": fixture,
        "sensor_ids": ["fixture"],
        "mode": "HISTORICAL",
        "start_time": start.isoformat(),
        "end_time": (start + timedelta(seconds=60)).isoformat(),
        "capture": {"directions": ["INBOUND", "OUTBOUND"], "protocols": ["TCP", "UDP"]},
        "analysis": {
            "module": "ddos_attack",
            "ddos_min_duration_seconds": 2,
            "ddos_min_source_count": 3,
            "ddos_min_packet_count": 6,
            "ddos_min_packets_per_second": 2,
        },
        "internal_networks": ["10.0.0.0/8"],
    }
    response = client.post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 201, response.text
    assert queue.jobs[0]["id"] == response.json()["id"]
    queued = repository.get_job(queue.jobs[0]["id"])
    assert queued is not None
    assert [row["ddos_packet_evidence"] for row in queued["flow_records"]] == [
        row["ddos_packet_evidence"] for row in rows
    ]
    # Import from this checkout even when the ordinary controller gate lacks the worker path.
    import importlib.util

    path = Path(__file__).parents[2] / "sensor/worker/src/c2hunter_worker/analysis.py"
    spec = importlib.util.spec_from_file_location("stage1_worker", path)
    assert spec is not None and spec.loader is not None
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    result = worker.execute_analysis(queued)
    assert result["candidates"] == []
    DDoSAttackReport.model_validate(result["ddos_attack"])
    queue.results.append(
        {"receipt": fixture, "job_id": queued["id"], "status": "COMPLETED", "result": result}
    )
    client.app.state.process_results_once()
    saved = client.get(f"/api/v1/analysis-jobs/{queued['id']}").json()
    assert saved["ddos_attack"] == DDoSAttackReport.model_validate(
        result["ddos_attack"]
    ).model_dump(mode="json", exclude_unset=True)
    assert queue.acked == [fixture]
    if fixture == "ddos-pcap-coordination.json":
        # Historical sensor quality is explicitly unknown, so observed timing is
        # retained but does not defeat capture-quality abstention.
        c = result["ddos_attack"]["findings"][0]["classification"]
        assert c["evidence"]["coordinated_sources"] == 3
        assert c["source_population"] != "BOTNET_LIKE_COORDINATION"
    if fixture == "ddos-live-reverse-requests.json":
        c = saved["ddos_attack"]["findings"][0]["classification"]
        assert c["evidence"]["response_samples"] == 1000
        assert c["evidence"]["matched_response_samples"] == 32
        assert c["evidence"]["coverage_limited"] is True
        assert c["axes"]["delivery_mechanism"]["confidence"] == "low"
        assert "EVIDENCE_COVERAGE_LIMITED" in c["axes"]["delivery_mechanism"]["unknown_codes"]
    c2 = {**queued, "analysis": AnalysisParameters().model_dump()}
    assert isinstance(worker.execute_analysis(c2)["candidates"], list)
    assert isinstance(evaluate_candidates(c2), list)


def test_saved_v2_reports_remain_valid_without_reinterpretation():
    source = Path(__file__).parents[2] / "web/tests/fixtures/ddos-report-scenarios-v2.json"
    reports = json.loads(source.read_text())
    for report in reports.values():
        validated = DDoSAttackReport.model_validate(report)
        assert validated.version == "ddos-attack-report-v2"
    outbound = reports["udp_outbound_participant"]["findings"][0]["classification"]
    assert outbound["source_population"] == "BOTNET_LIKE_COORDINATION"
    assert outbound["source_authenticity"] == "SOURCE_CONSISTENT"
