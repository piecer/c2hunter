from __future__ import annotations

import copy
import json
import struct
from datetime import timedelta
from pathlib import Path

import pytest
from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_analysis_job_api import START, api, payload
from test_durable_pipeline import QueueStub

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import (
    AnalysisParameters,
    DDoSAttackReport,
    DDoSMetrics,
    ReanalysisRequest,
)

DDOS_PARAMETERS = {
    "module": "ddos_attack",
    "ddos_min_duration_seconds": 2,
    "ddos_min_source_count": 3,
    "ddos_min_packet_count": 6,
    "ddos_min_packets_per_second": 2,
    "ddos_min_bits_per_second": 1_000_000,
    "ddos_baseline_min_buckets": 5,
}


def syn_records() -> list[dict[str, object]]:
    return [
        {
            "sensor_id": "s1",
            "timestamp": (START + timedelta(seconds=second)).isoformat(),
            "source_ip": f"198.51.100.{source}",
            "destination_ip": "10.0.0.10",
            "source_port": 40000 + source,
            "destination_port": 443,
            "protocol": "TCP",
            "direction": "INBOUND",
            "packet_count": 1,
            "total_bytes": 60,
            "tcp_flags": {"syn": 1, "ack": 0, "rst": 0, "fin": 0},
            "tcp_flags_observed": True,
            "tcp_syn_count": 1,
            "tcp_syn_only_count": 1,
            "tcp_sequence": source * 1000 + second,
            "tcp_acknowledgment": 0,
            "tcp_window": 64240,
            "transport_payload_length": 0,
            "packet_evidence_complete": True,
        }
        for second in range(25)
        for source in range(1, 5)
    ]


def ddos_payload(key: str = "ddos-inline") -> dict[str, object]:
    request = payload(flows=syn_records(), key=key)
    request["analysis"] = dict(DDOS_PARAMETERS)
    request["capture"] = {
        "max_packets": 10000,
        "directions": ["INBOUND", "OUTBOUND"],
        "protocols": ["TCP", "UDP", "ICMP"],
        "store_pcap": False,
    }
    return request


def test_ddos_module_and_thresholds_are_closed_and_bounded() -> None:
    parameters = AnalysisParameters.model_validate(DDOS_PARAMETERS)
    assert parameters.module == "ddos_attack"
    assert parameters.ddos_min_source_count == 3
    with pytest.raises(ValidationError):
        AnalysisParameters(module="ddos_attack", ddos_min_source_count=1)
    for value in ("20", 20.0):
        with pytest.raises(ValidationError):
            AnalysisParameters.model_validate(
                {"module": "ddos_attack", "ddos_min_source_count": value}
            )
        with pytest.raises(ValidationError):
            ReanalysisRequest.model_validate(
                {"idempotency_key": "strict-ddos", "ddos_min_source_count": value}
            )
    with pytest.raises(ValidationError):
        AnalysisParameters(module="ddos_attack", ddos_protocol_share_threshold=float("nan"))
    with pytest.raises(ValidationError):
        AnalysisParameters(module="unknown")
    invalid = ddos_payload("invalid-counter")
    invalid["flow_records"][0]["tcp_syn_count"] = 2  # type: ignore[index]
    invalid["flow_records"][0]["tcp_syn_only_count"] = 2  # type: ignore[index]
    assert api().post("/api/v1/analysis-jobs", json=invalid).status_code == 422


def test_inline_ddos_analysis_persists_independent_report_without_candidates() -> None:
    client = api()
    response = client.post("/api/v1/analysis-jobs", json=ddos_payload())

    assert response.status_code == 201, response.text
    job = response.json()
    assert job["status"] == "COMPLETED"
    assert job["analysis"]["module"] == "ddos_attack"
    assert job["candidate_count"] == 0
    assert job["ddos_attack"]["version"] == "ddos-attack-report-v2"
    assert job["ddos_attack"]["findings"][0]["attack_type"] == "TCP_SYN_FLOOD"
    assert job["ddos_attack_summary"] == {
        "verdict": "suspicious_traffic",
        "confidence": "low",
        "finding_count": 1,
        "primary_attack_type": "TCP_SYN_FLOOD",
        "primary_objective": "CONNECTION_STATE_EXHAUSTION",
        "coverage_complete": False,
    }
    candidates = client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates")
    assert candidates.status_code == 200
    assert candidates.json()["total"] == 0
    stored = client.get(f"/api/v1/analysis-jobs/{job['id']}").json()
    assert stored["ddos_attack"] == job["ddos_attack"]
    assert "flow_records" not in stored
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate({**job["ddos_attack"], "warnings": ["FUTURE_WARNING"]})
    poisoned_action = {**job["ddos_attack"]}
    poisoned_action["recommendations"] = [
        {**job["ddos_attack"]["recommendations"][0], "code": "FUTURE_ACTION"}
    ]
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate(poisoned_action)


def test_job_list_returns_only_compact_ddos_summary() -> None:
    client = api()
    job = client.post("/api/v1/analysis-jobs", json=ddos_payload("ddos-list")).json()
    listing = client.get("/api/v1/analysis-jobs").json()["items"]
    listed = next(item for item in listing if item["id"] == job["id"])
    assert "ddos_attack" not in listed
    assert listed["ddos_attack_summary"] == job["ddos_attack_summary"]


def test_ddos_job_is_rejected_by_c2_ai_boundary() -> None:
    client = api(settings=Settings(environment="test", ai_analysis_enabled=True))
    job = client.post("/api/v1/analysis-jobs", json=ddos_payload("ddos-no-c2-ai")).json()
    response = client.post(
        f"/api/v1/analysis-jobs/{job['id']}/ai-runs",
        json={"idempotency_key": "not-c2", "candidate_limit": 5},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ANALYSIS_MODULE_NOT_C2"


def test_ddos_reanalysis_reuses_dataset_and_only_overrides_ddos_thresholds() -> None:
    client = api()
    source = client.post("/api/v1/analysis-jobs", json=ddos_payload("ddos-source")).json()
    response = client.post(
        f"/api/v1/analysis-jobs/{source['id']}/reanalyze",
        json={
            "idempotency_key": "ddos-reanalyze",
            "ddos_min_source_count": 4,
            "ddos_bucket_seconds": 10,
            "ddos_min_duration_seconds": 5,
            "ddos_baseline_min_buckets": 30,
            "ddos_baseline_ratio": 7,
            "ddos_mad_z_threshold": 8,
            "ddos_protocol_share_threshold": 0.7,
            "ddos_tcp_flag_share_threshold": 0.75,
            "ddos_response_ratio_max": 0.1,
            "ddos_reflection_port_share_threshold": 0.65,
            "ddos_reflection_min_average_packet_bytes": 512,
            "ddos_overlap_window_seconds": 20,
        },
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["parent_job_id"] == source["id"]
    assert result["dataset_id"] == source["dataset_id"]
    assert result["analysis"]["module"] == "ddos_attack"
    assert result["analysis"]["ddos_min_source_count"] == 4
    assert result["analysis"]["ddos_bucket_seconds"] == 10
    assert result["analysis"]["ddos_reflection_min_average_packet_bytes"] == 512
    rejected = client.post(
        f"/api/v1/analysis-jobs/{source['id']}/reanalyze",
        json={"idempotency_key": "ddos-c2-weight", "detector_weights": {}},
    )
    assert rejected.status_code == 422


@pytest.mark.parametrize("provenance", ["quality", "limit", "restart", "context"])
@pytest.mark.parametrize("child_limit", [50, 10000])
def test_ddos_reanalysis_preserves_immutable_coverage(provenance, child_limit) -> None:
    repository = MemoryRepository()
    client = api(repository=repository)
    created = client.post("/api/v1/analysis-jobs", json=ddos_payload()).json()
    source = repository.get_job(created["id"])
    assert source is not None
    source.pop("ddos_coverage_context", None)
    source["source"] = {"captured_packet_count": 100, "skipped_packet_count": 3}
    if provenance == "quality":
        source["capture_quality"] = {"dropped_packet_count": 7, "clock_skew_detected": True}
        source["capture_incomplete"] = True
    elif provenance == "limit":
        source["capture_limit"] = {"discarded_packets": 7}
    elif provenance == "restart":
        source["error_code"] = "LIVE_CAPTURE_RESTART_INCOMPLETE"
    else:
        source["ddos_coverage_context"] = {
            "parser_skipped_packet_count": 3,
            "sensor_dropped_packet_count": 7,
            "sensor_clock_skew_detected": True,
            "sensor_capture_quality_unavailable": False,
            "capture_partial": False,
        }
    source["capture"]["max_packets"] = child_limit
    repository.save_job_metadata(source)
    original = copy.deepcopy(repository.get_job(source["id"]))
    assert original is not None
    for generation in range(2):
        response = client.post(
            f"/api/v1/analysis-jobs/{source['id']}/reanalyze",
            json={"idempotency_key": f"coverage-generation-{generation}"},
        )
        assert response.status_code == 201, response.text
        child = repository.get_job(response.json()["id"])
        assert child is not None
        assert child["dataset_id"] == original["dataset_id"]
        assert child["ddos_coverage_context"] == {
            "parser_skipped_packet_count": 3,
            "sensor_dropped_packet_count": 7 if provenance in {"quality", "context"} else 0,
            "sensor_clock_skew_detected": provenance in {"quality", "context"},
            "sensor_capture_quality_unavailable": False,
            "capture_partial": provenance != "context" or child_limit == 50,
        }
        assert child["ddos_attack"]["summary"]["coverage_complete"] is False
        assert child["ddos_attack"]["summary"]["counts_are_lower_bounds"] is True
        assert child["ddos_attack"]["summary"]["packet_count"] == min(child_limit, 100)
        source = child
    assert repository.get_job(original["id"]) == original


def test_pcap_upload_accepts_ddos_module_and_retains_packet_evidence() -> None:
    from test_analysis_history_pcap_api import _udp_packet

    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    epoch = int(START.timestamp())
    for sample in range(100):
        packet = _udp_packet(f"10.0.0.{sample + 1}", "203.0.113.77", 50000 + sample, sample + 1)
        content.extend(struct.pack("<IIII", epoch + sample, 0, len(packet), len(packet)))
        content.extend(packet)
    response = api().post(
        "/api/v1/pcap-analysis-jobs?name=ddos&filename=ddos.pcap&analysis_module=ddos_attack"
        "&ddos_min_source_count=3&ddos_min_packet_count=6"
        "&ddos_min_packets_per_second=1&ddos_min_bits_per_second=1"
        "&ddos_bucket_seconds=10&ddos_overlap_window_seconds=20",
        content=bytes(content),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 201, response.text
    job = response.json()
    assert job["analysis"]["module"] == "ddos_attack"
    assert job["analysis"]["ddos_min_source_count"] == 3
    assert job["analysis"]["ddos_min_packet_count"] == 6
    assert job["analysis"]["ddos_bucket_seconds"] == 10
    assert job["analysis"]["ddos_overlap_window_seconds"] == 20
    assert job["ddos_attack"]["version"] == "ddos-attack-report-v2"
    assert job["ddos_attack"]["summary"]["evaluated_records"] > 0
    finding = job["ddos_attack"]["findings"][0]
    assert finding["attack_type"] == "UDP_FLOOD"
    assert finding["attack_role"] == "PARTICIPANT_SIDE_OUTBOUND"
    assert finding["target"]["ip"] == "203.0.113.77"


def test_durable_worker_result_is_validated_and_persisted() -> None:
    monkey_path = Path(__file__).parents[2] / "sensor/worker/src"
    import sys

    sys.path.insert(0, str(monkey_path))
    try:
        from c2hunter_worker.analysis import execute_analysis

        queue = QueueStub()
        repository = MemoryRepository()
        client = TestClient(
            create_app(
                Settings(environment="test", inline_flow_records_enabled=False),
                repository,
                queue=queue,
            )
        )
        from test_durable_pipeline import register_sensor

        register_sensor(client)
        request = ddos_payload("ddos-worker")
        request["flow_records"] = []
        created = client.post("/api/v1/analysis-jobs", json=request)
        assert created.status_code == 201, created.text
        job = repository.get_job(created.json()["id"])
        assert job is not None
        job["flow_records"] = syn_records()
        result = execute_analysis(job)
        assert result["candidates"] == []
        assert result["ddos_attack"]["version"] == "ddos-attack-report-v2"
        queue.results.append(
            {
                "receipt": "ddos-result",
                "job_id": job["id"],
                "status": "COMPLETED",
                "result": result,
            }
        )
        client.app.state.process_results_once()
        stored = client.get(f"/api/v1/analysis-jobs/{job['id']}").json()
        expected_report = DDoSAttackReport.model_validate(result["ddos_attack"]).model_dump(
            mode="json", exclude_unset=True
        )
        assert stored["ddos_attack"] == expected_report
        assert stored["candidate_count"] == 0
        assert queue.acked == ["ddos-result"]
    finally:
        sys.path.remove(str(monkey_path))


def test_controller_rejects_malformed_worker_ddos_report() -> None:
    report = {
        "version": "ddos-attack-report-v1",
        "catalog_version": "ddos-taxonomy-v1",
        "verdict": "attack_likely",
        "confidence": "high",
        "primary_finding_id": None,
        "summary": {},
        "findings": [],
        "recommendations": [],
        "warnings": [],
        "limitations": [],
        "omitted_finding_count": 0,
        "poison": True,
    }
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate(report)

    queue = QueueStub()
    repository = MemoryRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False),
            repository,
            queue=queue,
        )
    )
    from test_durable_pipeline import register_sensor

    register_sensor(client)
    created = client.post(
        "/api/v1/analysis-jobs",
        json={**ddos_payload("invalid-result"), "flow_records": []},
    )
    queue.results.append(
        {
            "receipt": "invalid-ddos",
            "job_id": created.json()["id"],
            "status": "COMPLETED",
            "result": {"candidates": [], "ddos_attack": report},
        }
    )
    assert client.app.state.process_results_once() is True
    failed = client.get(f"/api/v1/analysis-jobs/{created.json()['id']}").json()
    assert failed["status"] == "FAILED"
    assert failed["error_code"] == "INVALID_DDOS_RESULT"
    assert queue.acked == ["invalid-ddos"]


def test_inline_invalid_ddos_result_terminalizes_created_job(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(
        ddos_attack,
        "analyze_ddos_attack",
        lambda *_args, **_kwargs: {"version": "invalid"},
    )
    repository = MemoryRepository()
    client = api(repository=repository)
    response = client.post("/api/v1/analysis-jobs", json=ddos_payload("invalid-inline"))
    assert response.status_code == 500
    jobs = repository.list_jobs()
    assert len(jobs) == 1
    assert jobs[0]["status"] == "FAILED"
    assert jobs[0]["error_code"] == "INVALID_DDOS_RESULT"


def test_ddos_report_forbids_clear_verdict_with_incomplete_coverage() -> None:
    report = (
        api()
        .post("/api/v1/analysis-jobs", json=ddos_payload("coverage-contract"))
        .json()["ddos_attack"]
    )
    report["verdict"] = "no_clear_attack"
    report["summary"]["coverage_complete"] = False
    report["summary"]["counts_are_lower_bounds"] = True
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate(report)


def test_ddos_report_metrics_are_closed_and_bounded() -> None:
    maximum_components = DDoSMetrics.model_validate(
        {
            "component_types": ["TCP_SYN_FLOOD", "UDP_FLOOD"],
            "component_finding_count": 4096,
        }
    )
    assert maximum_components.component_finding_count == 4096

    large_aggregate_packet = DDoSMetrics.model_validate({"average_packet_bytes": 1_000_000})
    assert large_aggregate_packet.average_packet_bytes == 1_000_000
    report = (
        api()
        .post("/api/v1/analysis-jobs", json=ddos_payload("metrics-contract"))
        .json()["ddos_attack"]
    )
    report["findings"][0]["metrics"]["future_unbounded_metric"] = "x" * 1_000_000
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate(report)

    missing_facts = (
        api()
        .post("/api/v1/analysis-jobs", json=ddos_payload("missing-facts-contract"))
        .json()["ddos_attack"]
    )
    missing_facts["findings"][0]["metrics"] = {}
    missing_facts["findings"][0]["evidence_codes"] = []
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate(missing_facts)

    missing_phase2_metrics = (
        api()
        .post("/api/v1/analysis-jobs", json=ddos_payload("missing-phase2-metrics"))
        .json()["ddos_attack"]
    )
    del missing_phase2_metrics["findings"][0]["metrics"]["hop_limit_min"]
    with pytest.raises(ValidationError, match="Phase 2 identity metrics"):
        DDoSAttackReport.model_validate(missing_phase2_metrics)

    inconsistent = (
        api()
        .post("/api/v1/analysis-jobs", json=ddos_payload("verdict-contract"))
        .json()["ddos_attack"]
    )
    inconsistent["verdict"] = "insufficient_evidence"
    inconsistent["confidence"] = "unknown"
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate(inconsistent)

    coerced_count = (
        api()
        .post("/api/v1/analysis-jobs", json=ddos_payload("strict-count-contract"))
        .json()["ddos_attack"]
    )
    coerced_count["findings"][0]["metrics"]["packet_count"] = "1200"
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate(coerced_count)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("delivery_mechanism", "REFLECTION_AMPLIFICATION"),
        ("source_population", "REFLECTOR_SET"),
        ("source_authenticity", "SOURCE_CONSISTENT"),
    ],
)
def test_ddos_report_rejects_semantically_inconsistent_classification(
    field: str, value: str
) -> None:
    report = analyze_ddos_attack(
        syn_records(),
        internal_cidrs=("10.0.0.0/8",),
        parameters=DDOS_PARAMETERS,
    )
    finding = report["findings"][0]
    finding["classification"][field] = value

    with pytest.raises(ValidationError, match="classification"):
        DDoSAttackReport.model_validate(report)


def test_generated_mixed_authenticity_multi_vector_validates_end_to_end() -> None:
    tcp_records: list[dict[str, object]] = []
    reflection_records: list[dict[str, object]] = []
    for row in syn_records():
        tcp_records.append(
            {
                **row,
                "packet_count": 8,
                "total_bytes": 480,
                "tcp_syn_count": 8,
                "tcp_syn_only_count": 8,
                "hop_limit_min": 32,
                "hop_limit_max": 128,
                "hop_limit_mode": 64,
                "hop_limit_distinct_count": 5,
                "ip_id_observed_count": 8,
                "ip_id_distinct_count": 8,
                "ip_id_monotonic_transitions": 0,
                "ip_id_transition_count": 7,
            }
        )
        reflection_records.append(
            {
                **row,
                "protocol": "UDP",
                "source_port": 53,
                "destination_port": 53000,
                "packet_count": 1,
                "total_bytes": 600,
                "tcp_flags": None,
                "tcp_flags_observed": False,
                "tcp_syn_count": 0,
                "tcp_syn_only_count": 0,
            }
        )

    report = analyze_ddos_attack(
        [*tcp_records, *reflection_records],
        internal_cidrs=("10.0.0.0/8",),
        parameters=DDOS_PARAMETERS,
    )
    multi = next(item for item in report["findings"] if item["attack_type"] == "MULTI_VECTOR")

    assert multi["classification"]["source_authenticity"] == "MIXED"
    assert multi["classification"]["confidence"] == "medium"
    DDoSAttackReport.model_validate(report)


def test_maximum_derived_finding_cardinality_validates_end_to_end(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    rows: list[dict[str, object]] = []
    for index in range(1, 2049):
        target = f"10.0.{index // 256}.{index % 256}"
        for protocol in ("TCP", "UDP"):
            for source in (1, 2):
                row: dict[str, object] = {
                    "sensor_id": "s1",
                    "timestamp": START.isoformat(),
                    "source_ip": f"198.18.{source}.{1 if protocol == 'TCP' else 2}",
                    "destination_ip": target,
                    "source_port": 40000 + source,
                    "destination_port": 443,
                    "protocol": protocol,
                    "direction": "INBOUND",
                    "packet_count": 1,
                    "total_bytes": 60,
                    "duration_seconds": 2,
                    "packet_evidence_complete": False,
                }
                if protocol == "TCP":
                    row.update(
                        tcp_flags_observed=True,
                        tcp_syn_count=1,
                        tcp_syn_only_count=1,
                    )
                rows.append(row)
    report = analyze_ddos_attack(
        rows,
        internal_cidrs=("10.0.0.0/8",),
        parameters={
            "ddos_min_source_count": 2,
            "ddos_min_packet_count": 2,
            "ddos_min_duration_seconds": 1,
            "ddos_min_packets_per_second": 1,
            "ddos_min_bits_per_second": 1,
        },
    )
    assert report["summary"]["finding_count"] == 6144
    assert report["omitted_finding_count"] == 6044
    DDoSAttackReport.model_validate(report)


def test_derived_rate_and_long_span_reports_validate_end_to_end(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)

    def udp(timestamp: str, source: str, packets: int) -> dict[str, object]:
        return {
            "sensor_id": "s1",
            "timestamp": timestamp,
            "source_ip": source,
            "destination_ip": "10.0.0.10",
            "source_port": 40000,
            "destination_port": 443,
            "protocol": "UDP",
            "direction": "INBOUND",
            "packet_count": packets,
            "total_bytes": 60,
            "duration_seconds": 1,
            "packet_evidence_complete": False,
        }

    parameters = {
        "ddos_min_source_count": 2,
        "ddos_min_packet_count": 1,
        "ddos_min_duration_seconds": 1,
        "ddos_min_packets_per_second": 1,
        "ddos_min_bits_per_second": 1,
    }
    rate_report = analyze_ddos_attack(
        [
            udp("2026-01-01T00:00:00Z", "198.51.100.1", 2**53 - 2),
            udp("2026-01-01T00:00:00Z", "198.51.100.2", 1),
        ],
        internal_cidrs=("10.0.0.0/8",),
        parameters=parameters,
    )
    DDoSAttackReport.model_validate(rate_report)

    span_report = analyze_ddos_attack(
        [
            udp("1900-01-01T00:00:00Z", "198.51.100.1", 1000),
            udp("2100-01-01T00:00:00Z", "198.51.100.2", 1000),
        ],
        internal_cidrs=("10.0.0.0/8",),
        parameters=parameters,
    )
    DDoSAttackReport.model_validate(span_report)


def test_report_rejects_producer_unreachable_semantics_and_array_drift() -> None:
    base = (
        api()
        .post("/api/v1/analysis-jobs", json=ddos_payload("closed-report-semantics"))
        .json()["ddos_attack"]
    )
    for mutate in (
        lambda value: value.update(limitations=[]),
        lambda value: value["findings"][0].update(severity="LOW"),
        lambda value: value["findings"][0].update(severity="CRITICAL"),
        lambda value: value["findings"][0].update(objective="UNKNOWN"),
        lambda value: value["findings"][0].update(attack_role="UNKNOWN"),
        lambda value: (
            value["findings"][0].update(likelihood="LIKELY", severity="HIGH", confidence="high"),
            value.update(verdict="attack_likely", confidence="high"),
        ),
        lambda value: value["findings"][0]["metrics"].update(packet_count=None),
        lambda value: value["findings"][0]["metrics"].update(measurement_precision=None),
        lambda value: value["findings"][0].update(uncertainty_codes=[]),
        lambda value: value["summary"].update(packet_count=0),
        lambda value: value["summary"].update(target_count=0),
        lambda value: value["findings"][0]["target"].update(ip="10.0.0.11"),
        lambda value: value["findings"][0]["evidence_codes"].append("VOLUME_GATE_MET"),
        lambda value: value.update(warnings=["BASELINE_UNAVAILABLE"] * 17),
        lambda value: value.update(limitations=[value["limitations"][0]] * 9),
        lambda value: value["findings"][0]["target"].pop("port"),
    ):
        poisoned = copy.deepcopy(base)
        mutate(poisoned)
        with pytest.raises(ValidationError):
            DDoSAttackReport.model_validate(poisoned)

    scenarios = json.loads(
        (Path(__file__).parents[2] / "web/tests/fixtures/ddos-report-scenarios.json").read_text()
    )
    for component_types in ([], ["MULTI_VECTOR", "MULTI_VECTOR"], ["TCP_SYN_FLOOD"]):
        poisoned = copy.deepcopy(scenarios["multi_vector"])
        poisoned["findings"][0]["metrics"]["component_types"] = component_types
        with pytest.raises(ValidationError):
            DDoSAttackReport.model_validate(poisoned)

    family_mutations = (
        ("multi_vector", lambda value: value["findings"][0].update(confidence="high")),
        (
            "tcp_ack_inbound",
            lambda value: value["findings"][0]["uncertainty_codes"].remove(
                "ACK_TRAFFIC_MAY_BE_LEGITIMATE"
            ),
        ),
        (
            "tcp_rst_inbound",
            lambda value: value["findings"][0]["uncertainty_codes"].remove(
                "RESETS_MAY_BE_DEFENSIVE_RESPONSES"
            ),
        ),
        (
            "possible_reflection",
            lambda value: value["findings"][0]["uncertainty_codes"].remove(
                "AMPLIFICATION_RATIO_UNOBSERVED"
            ),
        ),
        ("multi_vector", lambda value: value["findings"][0].update(uncertainty_codes=[])),
        ("tcp_syn_inbound", lambda value: value["summary"].update(scanned_records=0)),
        (
            "tcp_syn_inbound",
            lambda value: value["findings"][0]["metrics"].update(distinct_sources=0),
        ),
    )
    for scenario, mutate in family_mutations:
        poisoned = copy.deepcopy(scenarios[scenario])
        mutate(poisoned)
        with pytest.raises(ValidationError):
            DDoSAttackReport.model_validate(poisoned)


@pytest.mark.parametrize("ratio", [0, 1, 999])
def test_v1_reflection_rejects_measured_amplification_ratio(ratio) -> None:
    scenarios = json.loads(
        (Path(__file__).parents[2] / "web/tests/fixtures/ddos-report-scenarios.json").read_text()
    )
    report = scenarios["possible_reflection"]
    assert report["findings"][0]["metrics"]["amplification_ratio"] is None
    DDoSAttackReport.model_validate(report)
    report["findings"][0]["metrics"]["amplification_ratio"] = ratio
    with pytest.raises(ValidationError):
        DDoSAttackReport.model_validate(report)


def test_sparse_nonfinding_target_does_not_invalidate_a_likely_finding() -> None:
    value = (
        api()
        .post("/api/v1/analysis-jobs", json=ddos_payload("sparse-decoy-contract"))
        .json()["ddos_attack"]
    )
    value["warnings"] = ["SAMPLE_WINDOW_SHORT"]
    value["summary"]["coverage_complete"] = True
    value["findings"][0]["metrics"].update(
        baseline_packets_per_second=1.0,
        baseline_ratio=5.0,
        robust_z_score=None,
        response_ratio=0.0,
    )
    value["findings"][0]["uncertainty_codes"] = []
    value["findings"][0].update(likelihood="LIKELY", severity="HIGH", confidence="high")
    value.update(verdict="attack_likely", confidence="high")
    DDoSAttackReport.model_validate(value)


def test_ddos_job_rejects_unbounded_internal_networks() -> None:
    request = ddos_payload("bounded-internal-networks")
    request["internal_networks"] = [f"10.{index // 256}.{index % 256}.0/24" for index in range(257)]
    response = api().post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 422


def test_durable_unknown_module_terminalizes_and_acknowledges_result() -> None:
    queue = QueueStub()
    repository = MemoryRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False),
            repository,
            queue=queue,
        )
    )
    from test_durable_pipeline import register_sensor

    register_sensor(client)
    created = client.post(
        "/api/v1/analysis-jobs",
        json={**ddos_payload("legacy-unknown"), "flow_records": []},
    ).json()
    job = repository.get_job(created["id"])
    assert job is not None
    job["analysis"]["module"] = "future_module"
    repository.save_job_metadata(job)
    queue.results.append(
        {
            "receipt": "unknown-result",
            "job_id": created["id"],
            "status": "COMPLETED",
            "result": {},
        }
    )
    assert client.app.state.process_results_once() is True
    failed = repository.get_job(created["id"])
    assert failed is not None
    assert failed["status"] == "FAILED"
    assert failed["error_code"] == "UNSUPPORTED_ANALYSIS_MODULE"
    assert queue.acked == ["unknown-result"]


def test_durable_worker_error_is_closed_sanitized_and_acknowledged() -> None:
    queue = QueueStub()
    repository = MemoryRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False),
            repository,
            queue=queue,
        )
    )
    from test_durable_pipeline import register_sensor

    register_sensor(client)
    created = client.post(
        "/api/v1/analysis-jobs",
        json={**ddos_payload("worker-error"), "flow_records": []},
    ).json()
    queue.results.append(
        {
            "receipt": "error-result",
            "job_id": created["id"],
            "status": "ERROR",
            "error_code": "ANALYSIS_EXECUTION_FAILED",
            "error": "secret implementation details",
        }
    )
    assert client.app.state.process_results_once() is True
    failed = repository.get_job(created["id"])
    assert failed is not None
    assert failed["status"] == "FAILED"
    assert failed["error_code"] == "ANALYSIS_EXECUTION_FAILED"
    assert failed["error"] == "worker analysis failed"
    assert "secret" not in str(failed)
    assert queue.acked == ["error-result"]
