import pytest
from pydantic import ValidationError

from c2hunter_controller.schemas import AnalysisParameters, FlowRecord


@pytest.mark.parametrize(
    "field,value",
    [
        ("icmp_type", -1),
        ("icmp_type", 256),
        ("icmp_type", True),
        ("icmp_code", -1),
        ("icmp_code", 256),
        ("icmp_code", "3"),
        ("icmp_error", 1),
        ("unexpected_evidence", 1),
    ],
)
def test_icmp_fields_are_closed_and_bounded(field, value):
    record = dict(
        sensor_id="s1",
        timestamp="2026-09-11T00:00:00Z",
        source_ip="10.0.0.1",
        destination_ip="203.0.113.1",
        protocol="ICMP",
        direction="OUTBOUND",
    )
    with pytest.raises(ValidationError):
        FlowRecord.model_validate({**record, field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_port", -1),
        ("destination_port", 65536),
        ("source_port", True),
        ("protocol", "ICMP"),
        ("source_ip", "x" * 46),
        ("extra", 1),
    ],
)
def test_icmp_quote_is_closed_and_bounded(field, value):
    from c2hunter_controller.schemas import ICMPQuotedFlow

    quote = dict(
        source_ip="10.0.0.1",
        destination_ip="203.0.113.1",
        source_port=0,
        destination_port=65535,
        protocol="UDP",
    )
    assert ICMPQuotedFlow.model_validate(quote).model_dump() == quote
    with pytest.raises(ValidationError):
        ICMPQuotedFlow.model_validate({**quote, field: value})


def test_analysis_module_is_explicit_and_closed():
    assert AnalysisParameters().model_dump()["module"] == "c2"
    assert AnalysisParameters(module="network_anomaly").module == "network_anomaly"
    with pytest.raises(ValidationError):
        AnalysisParameters(module="unknown")


def test_pcap_upload_runs_network_module_and_persists_independent_report():
    from test_analysis_history_pcap_api import _pcap
    from test_analysis_job_api import api

    client = api()
    response = client.post(
        "/api/v1/pcap-analysis-jobs?name=network&filename=network.pcap&analysis_module=network_anomaly",
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 201, response.text
    job = response.json()
    assert job["analysis"]["module"] == "network_anomaly"
    assert job["status"] == "COMPLETED"
    assert job["candidate_count"] == 0
    assert job["network_anomaly"]["version"] == "network-pattern-report-v1"
    assert job["network_anomaly"]["summary"]["flow_count"] > 0
    assert isinstance(job["network_anomaly"]["issues"], list)
    assert job["network_anomaly"]["flows"] == []
    stored = client.get(f"/api/v1/analysis-jobs/{job['id']}").json()
    assert stored["network_anomaly"] == job["network_anomaly"]
    assert "flow_records" not in stored


def test_default_c2_upload_remains_compatible_with_packet_evidence():
    from test_analysis_history_pcap_api import _pcap
    from test_analysis_job_api import api

    response = api().post(
        "/api/v1/pcap-analysis-jobs?name=c2&filename=c2.pcap",
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 201
    assert response.json()["candidate_count"] > 0
    assert "network_anomaly" not in response.json()


def test_icmp_upload_preserves_quoted_network_evidence():
    import struct

    from test_analysis_history_pcap_api import _pcap_for_packets, _udp_packet
    from test_analysis_job_api import api

    udp = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    icmp = bytes([3, 1, 0, 0, 0, 0, 0, 0]) + udp[14:42]
    header = bytearray(udp[14:34])
    header[2:4] = struct.pack("!H", 20 + len(icmp))
    header[9] = 1
    capture = _pcap_for_packets([udp, udp[:14] + header + icmp])
    client = api()
    response = client.post(
        "/api/v1/pcap-analysis-jobs?name=icmp&filename=icmp.pcap&analysis_module=network_anomaly",
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 201, response.text
    report = response.json()["network_anomaly"]
    assert report["version"] == "network-pattern-report-v1"
    assert any(issue["pattern"] == "icmp_errors" for issue in report["issues"])
    stored = client.get(f"/api/v1/analysis-jobs/{response.json()['id']}").json()
    assert stored["network_anomaly"] == report
    issue = next(issue for issue in report["issues"] if issue["pattern"] == "icmp_errors")
    assert issue["scope"]["peer"]["port"] == 443
    assert issue["event_count"] == 1
    assert issue["examples"][0]["facts"]["icmp_type"] == 3
    assert issue["examples"][0]["facts"]["icmp_code"] == 1


@pytest.mark.parametrize("worker", [False, True])
@pytest.mark.parametrize("known_interfaces", [False, True])
def test_historical_unknown_interface_preserves_counts(monkeypatch, worker, known_interfaces):
    from pathlib import Path

    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))
    from c2hunter_worker.analysis import execute_analysis
    from test_analysis_job_api import api, payload, synthetic_flows

    from c2hunter_controller.repositories import MemoryRepository

    repo = MemoryRepository()
    client = api(repo)
    records = synthetic_flows()
    # Exercise the existing schema's default, not a handcrafted packet mapping.
    assert FlowRecord.model_validate(records[0]).model_dump()["capture_interface_id"] is None
    if known_interfaces:
        records = [
            {**record, "capture_interface_id": interface}
            for interface in (None, 0, 1)
            for record in records
        ]
    request = payload(flows=records)
    request["analysis"]["module"] = "network_anomaly"
    response = client.post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 201, response.text
    job = response.json()
    assert job["status"] == "COMPLETED"
    report = (
        execute_analysis(repo.get_job(job["id"]))["network_anomaly"]
        if worker
        else job["network_anomaly"]
    )
    assert report["summary"]["scanned_records"] == len(records)
    assert report["summary"]["skipped_records"] == 0
    assert report["summary"]["flow_count"] == (12 if known_interfaces else 4)
    assert report["version"] == "network-pattern-report-v1"
    assert report["flows"] == []
    assert report["issues"] == []
    assert report["summary"]["incomplete_records"] == len(records)
    assert report["summary"]["verdict"] == "insufficient_evidence"
    assert "INCOMPLETE_PACKET_EVIDENCE" in report["warnings"]


def test_network_worker_result_uses_existing_queue_and_metadata(monkeypatch):
    from pathlib import Path

    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))
    from c2hunter_worker.analysis import execute_analysis
    from fastapi.testclient import TestClient
    from test_analysis_history_pcap_api import _pcap
    from test_durable_pipeline import QueueStub

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.repositories import MemoryRepository

    queue = QueueStub()
    repo = MemoryRepository()
    app = create_app(Settings(environment="test"), repo, queue=queue)
    client = TestClient(app)
    response = client.post(
        "/api/v1/pcap-analysis-jobs?name=network&filename=n.pcap&analysis_module=network_anomaly",
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 201, response.text
    job = response.json()
    assert job["status"] == "ANALYZING"
    assert queue.jobs == [{"id": job["id"]}]
    result = execute_analysis(repo.get_job(job["id"]))
    assert result["candidates"] == []
    assert result["network_anomaly"]["version"] == "network-pattern-report-v1"
    assert result["network_anomaly"]["summary"]["flow_count"] > 0
    assert isinstance(result["network_anomaly"]["issues"], list)
    assert result["network_anomaly"]["flows"] == []
    queue.results.append(
        {"receipt": "network-result", "job_id": job["id"], "status": "COMPLETED", "result": result}
    )
    app.state.process_results_once()
    stored = client.get(f"/api/v1/analysis-jobs/{job['id']}").json()
    assert stored["status"] == "COMPLETED"
    assert stored["network_anomaly"] == result["network_anomaly"]
    assert stored["candidate_count"] == 0
    assert queue.acked == ["network-result"]
