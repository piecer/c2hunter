"""Source omissions through actual admission, worker delivery and persisted reports."""

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_durable_pipeline import START, QueueStub, job_payload, register_sensor

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.network_ai import build_network_input
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import FlowRecord
from c2hunter_controller.storage import MemoryFlowStore


def native():
    path = Path(__file__).parents[2] / "analysis/tests/test_network_anomaly.py"
    spec = importlib.util.spec_from_file_location("native_coverage_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def packets():
    frame = native().frame
    return [
        frame(),
        frame(flags=18, seq=500, ack=101, reverse=True),
        frame(flags=16, seq=101, ack=501),
        frame(flags=24, seq=101, ack=501, payload=b"abc"),
        frame(flags=24, seq=101, ack=501, payload=b"abc"),
    ]


def run_worker(monkeypatch, app, client, queue, job_id):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))
    from c2hunter_worker.analysis import execute_analysis

    loaded = app.state.repository.get_job(job_id)
    result = execute_analysis(loaded)
    queue.results.append(
        {"receipt": job_id, "job_id": job_id, "status": "COMPLETED", "result": result}
    )
    assert app.state.process_results_once()
    stored = client.get(f"/api/v1/analysis-jobs/{job_id}").json()
    assert stored["status"] == "COMPLETED"
    assert stored["network_anomaly"] == result["network_anomaly"]
    return loaded, stored


def assert_partial(report, code, scanned):
    assert code in report["warnings"]
    summary = report["summary"]
    assert summary["coverage_complete"] is False
    assert summary["counts_are_lower_bounds"] is True
    assert summary["truncated"] is True
    assert summary["scanned_records"] == scanned
    assert summary["skipped_records"] == 0  # source packets are not analysis records
    if not report["issues"]:
        assert summary["verdict"] == "insufficient_evidence"
    bundle = build_network_input(report, "en")
    assert code in bundle["warnings"]
    for key in ("coverage_complete", "counts_are_lower_bounds", "truncated", "verdict"):
        assert bundle["summary"][key] == summary[key]


def test_actual_queued_packet_cap_reaches_persisted_report_and_ai(monkeypatch):
    rows = [
        FlowRecord.model_validate(row).model_dump(mode="json")
        for row in native().records(*packets(), start_time=START)
    ]
    store, queue, repo = MemoryFlowStore(), QueueStub(), MemoryRepository()
    app = create_app(
        Settings(environment="test", inline_flow_records_enabled=False),
        repo,
        flow_store=store,
        queue=queue,
    )
    with TestClient(app) as client:
        register_sensor(client)
        store.ingest_batch("s1", "native-coverage", rows)
        request = job_payload()
        request["analysis"]["module"] = "network_anomaly"
        request["capture"].update(max_packets=3, directions=["OUTBOUND", "INBOUND"])
        created = client.post("/api/v1/analysis-jobs", json=request)
        assert created.status_code == 201, created.text
        job_id = created.json()["id"]
        assert queue.jobs == [{"id": job_id}]
        loaded, stored = run_worker(monkeypatch, app, client, queue, job_id)
        assert len(loaded["flow_records"]) == 3
        assert stored["capture_limit"]["discarded_packets"] == 2
        assert_partial(stored["network_anomaly"], "CAPTURE_PACKET_LIMIT_REACHED", 3)


@pytest.mark.parametrize("skipped", [False, True])
def test_uploaded_parser_skip_reaches_report_without_inventing_record_counts(skipped):
    repo = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repo))
    frames = packets()[:3] + ([native().frame()[:15]] if skipped else [])
    content = native().capture(*frames, start_time=START)
    response = client.post(
        "/api/v1/pcap-analysis-jobs?name=coverage&filename=coverage.pcap"
        "&analysis_module=network_anomaly",
        content=content,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 201, response.text
    stored = client.get(f"/api/v1/analysis-jobs/{response.json()['id']}").json()
    assert stored["source"]["captured_packet_count"] == 3 + int(skipped)
    assert stored["source"]["parsed_packet_count"] == 3
    assert stored["source"]["skipped_packet_count"] == int(skipped)
    if skipped:
        assert_partial(stored["network_anomaly"], "PARSER_SKIPPED_PACKETS", 3)
    else:
        report = stored["network_anomaly"]
        assert report["warnings"] == []
        assert report["summary"]["coverage_complete"] is True
        assert report["summary"]["verdict"] == "no_clear_anomaly"
        assert report["summary"]["truncated"] is False
        assert report["summary"]["counts_are_lower_bounds"] is False


def test_preparation_and_two_reanalyses_preserve_bounded_source_context(monkeypatch, tmp_path):
    from copy import deepcopy

    from c2hunter_controller.pcap_preparation_worker import PcapPreparationWorker
    from c2hunter_controller.repositories import SQLiteRepository

    repo = SQLiteRepository(tmp_path / "coverage.db")
    queue = QueueStub()
    app = create_app(
        Settings(environment="test", inline_flow_records_enabled=False), repo, queue=queue
    )
    client = TestClient(app)
    # Admission retains native bytes; preparation is exercised separately from inline upload.
    created = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "coverage",
            "filename": "coverage.pcap",
            "idempotency_key": "cov-prep",
            "analysis_module": "network_anomaly",
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"module": "network_anomaly"},
        },
    )
    assert created.status_code == 201, created.text
    job_id = created.json()["id"]
    content = native().capture(*packets(), native().frame()[:15], start_time=START)
    uploaded = client.put(
        f"/api/v1/pcap-analysis-jobs/{job_id}/capture",
        content=content,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert uploaded.status_code == 202, uploaded.text
    deliveries = []
    preparation = PcapPreparationWorker(
        repo, enqueue=deliveries.append, lease_seconds=30, max_packets=2_000_000
    )
    assert preparation.run_once()
    assert len(deliveries) == 1
    loaded, stored = run_worker(monkeypatch, app, client, queue, job_id)
    assert_partial(stored["network_anomaly"], "PARSER_SKIPPED_PACKETS", 5)
    assert stored["network_anomaly"]["summary"]["verdict"] == "anomaly_observed"
    original = deepcopy(repo.get_job(job_id))
    context = loaded.get("network_coverage_context")
    assert context and context["PARSER_SKIPPED_PACKETS"] is True
    assert len(context) == 6 and all(type(value) is bool for value in context.values())
    for generation in range(2):
        response = client.post(
            f"/api/v1/analysis-jobs/{stored['id']}/reanalyze",
            json={"idempotency_key": f"cov-reanalysis-{generation}"},
        )
        assert response.status_code == 201, response.text
        child, stored = run_worker(monkeypatch, app, client, queue, response.json()["id"])
        assert child["network_coverage_context"] == context
        # Reanalysis omits null raw-byte fields; compare the actual DTO semantics.
        assert [FlowRecord.model_validate(row) for row in child["flow_records"]] == [
            FlowRecord.model_validate(row) for row in original["flow_records"]
        ]
        assert_partial(stored["network_anomaly"], "PARSER_SKIPPED_PACKETS", 5)
        assert stored["network_anomaly"]["issues"] == original["network_anomaly"]["issues"]
    assert repo.get_job(job_id) == original
    repo.close()


@pytest.mark.parametrize("queued", [False, True])
@pytest.mark.parametrize(
    "quality", [None, {"dropped_packet_count": 7, "clock_skew_detected": True}]
)
def test_sensor_quality_restart_and_cap_survive_two_generations(monkeypatch, queued, quality):
    from copy import deepcopy

    from c2hunter_analysis.network_coverage import network_coverage_context

    repo, queue = MemoryRepository(), QueueStub()
    # The inline controller retains immutable raw rows, while its analysis view is capped.
    app = create_app(Settings(environment="test"), repo, queue=queue)
    client = TestClient(app)
    register_sensor(client)
    request = job_payload()
    request["analysis"]["module"] = "network_anomaly"
    request["capture"].update(max_packets=3, directions=["OUTBOUND", "INBOUND"])
    request["flow_records"] = [
        FlowRecord.model_validate(row).model_dump(mode="json")
        for row in native().records(*packets(), start_time=START)
    ]
    response = client.post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 201, response.text
    job_id = response.json()["id"]
    assert_partial(response.json()["network_anomaly"], "CAPTURE_PACKET_LIMIT_REACHED", 3)
    parent = repo.get_job(job_id)
    # Recorded LIVE restart/quality metadata only: no capture service or sensor is started.
    parent["error_code"] = "LIVE_CAPTURE_RESTART_INCOMPLETE"
    if quality is not None:
        parent["capture_quality"] = quality
    repo.save_job_metadata(parent)
    before = deepcopy(repo.get_job(job_id))
    expected = network_coverage_context(before)
    if queued:
        app = create_app(
            Settings(environment="test", inline_flow_records_enabled=False), repo, queue=queue
        )
        client = TestClient(app)
    previous_id = job_id
    for generation in range(2):
        response = client.post(
            f"/api/v1/analysis-jobs/{previous_id}/reanalyze",
            json={"idempotency_key": f"sensor-generation-{generation}"},
        )
        assert response.status_code == 201, response.text
        current = response.json()
        if queued:
            loaded, current = run_worker(monkeypatch, app, client, queue, current["id"])
            # Existing queued reanalysis reuses raw rows; do not pretend it loaded only 3.
            scanned = len(loaded["flow_records"])
        else:
            scanned = 3
        raw = repo.get_job(current["id"])
        assert raw["network_coverage_context"] == expected
        report = current["network_anomaly"]
        for code, present in expected.items():
            if present:
                assert code in report["warnings"]
        assert_partial(report, "PARTIAL_CAPTURE", scanned)
        assert len(report["warnings"]) == len(set(report["warnings"]))
        assert raw["capture_limit"]["discarded_packets"] == 2  # not 2 + 2 per generation
        previous_id = current["id"]
    assert repo.get_job(job_id) == before


def test_ai_preserves_all_upstream_qualifiers_with_full_issue_budget():
    from copy import deepcopy

    from c2hunter_analysis.network_coverage import SOURCE_WARNINGS, analyze_network_job

    from c2hunter_controller.network_ai import MAX_NETWORK_INPUT_BYTES, canonical_network_input

    report = analyze_network_job(
        {
            "flow_records": native().records(*packets(), start_time=START),
            "network_coverage_context": dict.fromkeys(SOURCE_WARNINGS, True),
        }
    )
    issue = report["issues"][0]
    report["issues"] = [{**deepcopy(issue), "id": f"coverage-{index}"} for index in range(20)]
    for value in report["issues"]:
        value["evidence"] = ["측정 " * 200] * 4
        value["uncertainty"] = ["unknown " * 100] * 4
    bundle = build_network_input(report)
    assert set(SOURCE_WARNINGS) <= set(bundle["warnings"])
    assert len(canonical_network_input(bundle).encode("utf-8")) <= MAX_NETWORK_INPUT_BYTES
    assert bundle["summary"]["coverage_complete"] is False
    assert len(bundle["issues"]) == 20
    assert bundle["input_detail_counts"]["capped_diagnostic_entries"] >= 0
