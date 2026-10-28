"""Real producer -> gateway -> worker -> reopened SQLite -> public API."""

import json
from copy import deepcopy

from c2hunter_analysis.network_report import analyze_network_report
from fastapi.testclient import TestClient
from test_network_ai import Transport
from test_network_anomaly import frame, records

from c2hunter_controller.ai_analysis import AIAnalysisService
from c2hunter_controller.ai_gateway import OllamaGateway
from c2hunter_controller.ai_queueing import MemoryAIAnalysisTaskQueue, MemoryAIAnalysisWorkerQueue
from c2hunter_controller.ai_worker import AIAnalysisWorker
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository
from c2hunter_controller.schemas import FlowRecord


def numeric_fixture(tmp_path, language="en", report_override=None, maximum=False):
    packets = records(
        frame(),
        frame(flags=18, seq=500, ack=101, reverse=True),
        frame(flags=24, seq=101, payload=b"abc"),
        frame(flags=24, seq=101, payload=b"abc"),
    )
    report = analyze_network_report(
        [FlowRecord.model_validate(p).model_dump(mode="json") for p in packets]
    )
    if report_override is not None:
        report = report_override
    identity = report["issues"][0]["id"]
    ref = {
        "kind": "measurement",
        "issue_id": identity,
        "example_index": 0,
        "metric": "observed_rtt_ms",
        "direction": None,
        "statistic": "mean",
    }
    output = {
        "schema_version": "network-interpretation-v2",
        "kind": "MODEL_INTERPRETATION",
        "language": language,
        "summary": "AI says 1100 ms",
        "summary_numeric_refs": [ref],
        "possible_causes": [],
        "prioritized_checks": [],
        "correlations": [],
        "limitations": ["Not a confirmed diagnosis"],
    }
    if maximum:
        from c2hunter_controller.network_ai import build_network_input_v2

        bundle = build_network_input_v2(report, language)
        ids = [i["id"] for i in bundle["issues"]]
        count_ref = {"kind": "issue_count", "issue_id": ids[-1], "field": "event_count"}
        refs = [
            count_ref,
            {**count_ref, "field": "affected_flow_count"},
            {**count_ref, "field": "affected_host_count"},
        ]
        output.update(
            summary="😀" * 1200,
            summary_numeric_refs=[
                ref,
                {"kind": "summary_count", "field": "scanned_records"},
                {"kind": "summary_count", "field": "flow_count"},
            ],
            possible_causes=[
                {
                    "hypothesis": "😀" * 1200,
                    "uncertainty": "😀" * 1200,
                    "issue_ids": ids,
                    "numeric_refs": refs if i < 7 else [],
                }
                for i in range(10)
            ],
            prioritized_checks=[
                {"priority": "HIGH", "check": "😀" * 1200, "issue_ids": ids, "numeric_refs": []}
                for _ in range(10)
            ],
            correlations=[
                {"interpretation": "😀" * 1200, "issue_ids": ids, "numeric_refs": []}
                for _ in range(10)
            ],
            limitations=["😀" * 1200] * 12,
        )
    path = tmp_path / f"numeric-{language}.sqlite3"
    repository = SQLiteRepository(path)
    job = {
        "id": "numeric-job",
        "dataset_id": "numeric-dataset",
        "status": "COMPLETED",
        "analysis": {"module": "network_anomaly"},
        "network_anomaly": report,
        "created_at": "2026-10-27T00:00:00Z",
    }
    repository.save_job(job)
    job = deepcopy(repository.get_job("numeric-job"))
    transport = Transport(output)
    gateway = OllamaGateway(
        base_url="http://127.0.0.1:11434", model="scripted", http_client=transport
    )
    gateway.ready = lambda: True
    queue = MemoryAIAnalysisTaskQueue()
    settings = Settings(environment="test", ai_analysis_enabled=True)
    client = TestClient(create_app(settings, repository, ai_gateway=gateway, ai_task_queue=queue))
    body = {
        "idempotency_key": "numeric-" + language,
        "analysis_kind": "NETWORK_ANOMALY",
        "language": language,
    }
    created = client.post("/api/v1/analysis-jobs/numeric-job/ai-runs", json=body)
    assert created.status_code == 201, created.text
    run = created.json()
    worker_queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": "numeric"}])
    service = AIAnalysisService(repository, gateway)
    assert AIAnalysisWorker(worker_queue, service).run_once()
    assert worker_queue.acked == ["numeric"]
    reopened = SQLiteRepository(path)
    stored = reopened.get_ai_run(run["id"])
    assert stored["status"] == "COMPLETED", stored
    assert reopened.get_job("numeric-job") == job
    fresh = TestClient(create_app(settings, reopened, ai_gateway=gateway, ai_task_queue=queue))
    detail = fresh.get("/api/v1/ai-runs/" + run["id"])
    assert detail.status_code == 200, detail.text
    return {
        "report": report,
        "job": job,
        "run": detail.json(),
        "raw": detail.text,
        "client": fresh,
        "repository": reopened,
        "transport": transport,
        "body": body,
    }


def test_real_numeric_vertical(tmp_path):
    fixture = numeric_fixture(tmp_path)
    run = fixture["run"]
    assert run["network_input"]["schema_version"] == "network-ai-input-v2"
    assert run["prompt_version"] == "2.0"
    assert run["network_interpretation"]["summary"] == "AI says 1100 ms"
    assert run["network_numeric_evidence"]["items"][0]["value"] == "100.0"
    assert run["network_numeric_evidence"]["items"][0]["unit"] == "ms"
    assert len(fixture["transport"].calls) == 1
    before = deepcopy(fixture["repository"].get_ai_run(run["id"]))
    for response in (
        fixture["client"].get("/api/v1/analysis-jobs/numeric-job/ai-runs"),
        fixture["client"].post("/api/v1/analysis-jobs/numeric-job/ai-runs", json=fixture["body"]),
        fixture["client"].post(
            "/api/v1/ai-runs/" + run["id"] + "/cancel", json={"reason": "terminal"}
        ),
    ):
        assert response.status_code == 200, response.text
        value = response.json()
        if "items" in value:
            value = value["items"][0]
        assert value["network_numeric_evidence"] == run["network_numeric_evidence"]
    assert fixture["repository"].get_ai_run(run["id"]) == before
    assert json.loads(fixture["raw"])["network_numeric_evidence"] == run["network_numeric_evidence"]


def test_custom_gateway_cannot_rewrite_immutable_input(tmp_path):
    f = numeric_fixture(tmp_path)
    repo = f["repository"]
    original = repo.get_ai_run(f["run"]["id"])
    queued = {**deepcopy(original), "id": "custom", "idempotency_key": "custom", "status": "QUEUED"}
    queued.pop("network_interpretation")
    repo.create_ai_run(queued)

    class Custom:
        def interpret_network_cancellable(self, bundle, *, should_cancel):
            bundle["issues"][0]["observed_measurements"][0]["measurements"][
                "observed_rtt_ms"
            ].update(min=1100.0, max=1100.0, mean=1100.0)
            return original["network_interpretation"]

    final = AIAnalysisService(repo, Custom()).execute("custom")
    assert final["network_input"] == original["network_input"]


def test_all_public_routes_recompute_cache_and_fail_whole_response(tmp_path):
    f = numeric_fixture(tmp_path)
    repo, client, run = f["repository"], f["client"], f["run"]

    def corrupt(value):
        # Terminal repository saves are deliberately immutable. Simulate disk
        # corruption below that API, on this invocation-owned SQLite database.
        import sqlite3

        with sqlite3.connect(tmp_path / "numeric-en.sqlite3") as connection:
            connection.execute(
                "UPDATE ai_analysis_runs SET data=? WHERE run_id=?", (json.dumps(value), run["id"])
            )
        assert repo.get_ai_run(run["id"]) == value

    saved = repo.get_ai_run(run["id"])
    saved["network_numeric_evidence"] = {"value": "FORGED_SECRET"}
    corrupt(saved)
    before = deepcopy(repo.get_ai_run(run["id"]))
    assert (
        client.get("/api/v1/ai-runs/" + run["id"]).json()["network_numeric_evidence"]
        == run["network_numeric_evidence"]
    )
    assert repo.get_ai_run(run["id"]) == before
    saved["network_input"]["issues"][0]["observed_measurements"][0]["measurements"][
        "metric_quality"
    ] = None
    corrupt(saved)
    for response in (
        client.get("/api/v1/ai-runs/" + run["id"]),
        client.get("/api/v1/analysis-jobs/numeric-job/ai-runs"),
        client.post("/api/v1/analysis-jobs/numeric-job/ai-runs", json=f["body"]),
        client.post("/api/v1/ai-runs/" + run["id"] + "/cancel", json={"reason": "test"}),
    ):
        assert response.status_code == 503, response.text
        error = response.json()["error"]
        assert error["code"] == "NETWORK_EVIDENCE_INVALID"
        assert error["message"] == "Saved network evidence could not be validated."
        assert error.get("details") is None
        assert "FORGED_SECRET" not in response.text
    assert len(f["transport"].calls) == 1


def test_unsupported_bindings_ack_without_provider_and_legacy_terminal_survives(tmp_path):
    from test_network_ai import legacy_v1_response

    from c2hunter_controller.historical_ai_http import public_run
    from c2hunter_controller.network_ai import NETWORK_PROMPT_HASH, build_network_input

    f = numeric_fixture(tmp_path)
    original = f["repository"].get_ai_run(f["run"]["id"])
    repo = f["repository"]
    legacy = {
        **deepcopy(original),
        "id": "legacy",
        "idempotency_key": "legacy",
        "prompt_version": "1.0",
        "prompt_hash": NETWORK_PROMPT_HASH,
        "input_schema_version": "network-ai-input-v1",
        "output_schema_version": "network-interpretation-v1",
        "network_input": build_network_input(f["report"], "en"),
        "network_interpretation": legacy_v1_response("en"),
        "network_numeric_evidence": {"forged": True},
    }
    assert "network_numeric_evidence" not in public_run(legacy)
    repo.create_ai_run(legacy)
    for index, change in enumerate(
        (
            {"prompt_hash": "wrong"},
            {"prompt_version": "1.0"},
            {"language": "ko"},
            {"output_schema_version": "network-interpretation-v1"},
            {"network_input": legacy["network_input"]},
            {
                k: legacy[k]
                for k in (
                    "prompt_version",
                    "prompt_hash",
                    "input_schema_version",
                    "output_schema_version",
                    "network_input",
                )
            },
        )
    ):
        run = {
            **deepcopy(original),
            **change,
            "id": f"bad-{index}",
            "idempotency_key": f"bad-{index}",
            "status": "QUEUED",
        }
        run.pop("network_interpretation")
        repo.create_ai_run(run)
        queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": run["id"]}])
        gateway = OllamaGateway(base_url="http://unused", model="test", http_client=f["transport"])
        assert AIAnalysisWorker(queue, AIAnalysisService(repo, gateway)).run_once()
        stored = repo.get_ai_run(run["id"])
        assert (
            stored["status"] == "FAILED"
            and stored["error_code"] == "NETWORK_INPUT_CONTRACT_UNSUPPORTED"
        )
        assert queue.acked == [run["id"]]
        assert "network_numeric_evidence" not in public_run(stored)
    assert len(f["transport"].calls) == 1


def test_oversize_envelope_repaired_inside_existing_gateway_and_floor_before_io(tmp_path):
    from test_network_ai_diagnostics import ScriptedTransport

    from c2hunter_controller.network_ai import canonical_network_input
    from c2hunter_controller.network_numeric_evidence import EvidenceIdentity, envelope

    f = numeric_fixture(tmp_path)
    repo = f["repository"]
    original = repo.get_ai_run(f["run"]["id"])
    b = original["network_input"]
    identity = EvidenceIdentity("large", "numeric-job", "")
    floor = len(canonical_network_input(envelope(b, identity, [])).encode())
    run = {
        **deepcopy(original),
        "id": "large",
        "idempotency_key": "large",
        "status": "QUEUED",
        "dataset_id": "x" * (32768 - floor),
    }
    run.pop("network_interpretation")
    repo.create_ai_run(run)
    valid = deepcopy(original["network_interpretation"])
    valid["summary_numeric_refs"] = []
    transport = ScriptedTransport(json.dumps(original["network_interpretation"]), json.dumps(valid))
    gateway = OllamaGateway(base_url="http://unused", model="test", http_client=transport)
    service = AIAnalysisService(repo, gateway)
    completed = service.execute("large")
    assert completed["status"] == "COMPLETED"
    assert len(transport.calls) == 2
    assert "SCHEMA" in transport.calls[-1]["body"]["messages"][-2]["content"]
    assert "select fewer" in transport.calls[-1]["body"]["messages"][-2]["content"].lower()
    run.update(id="large2", idempotency_key="large2", dataset_id=run["dataset_id"] + "x")
    repo.create_ai_run(run)
    assert service.execute("large2")["error_code"] == "NETWORK_INPUT_CONTRACT_UNSUPPORTED"
    assert len(transport.calls) == 2
