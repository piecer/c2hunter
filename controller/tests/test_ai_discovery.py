from __future__ import annotations

from copy import deepcopy

import pytest


def _candidate(peer: str, *, score: int = 0, anomaly: float | None = None) -> dict:
    value = {
        "id": f"candidate-{peer}",
        "candidate_ip": peer,
        "score": score,
        "prefilter_score": 10,
        "evidence": [{"type": "TEST", "description": "Observed behavior", "metrics": {}}],
    }
    if anomaly is not None:
        value["behavior_anomaly_score"] = anomaly
    return value


def test_shadow_reserves_rule_free_candidate_without_changing_source_scores() -> None:
    from c2hunter_controller.ai_discovery import select_shadow_candidates

    rules = [_candidate(f"198.51.100.{i}", score=90) for i in range(1, 7)]
    behavior = [_candidate("203.0.113.9", anomaly=15.0)]
    original = deepcopy((rules, behavior))

    selected, inventory, summary = select_shadow_candidates(rules, behavior, limit=5)

    assert "203.0.113.9" in {item["candidate_ip"] for item in selected}
    assert len(selected) == 5
    assert summary["candidate_pool_count"] == 7
    assert summary["selected_count"] == 5
    assert summary["omitted_count"] == 2
    assert summary["rule_free_selected_count"] == 1
    assert sum(item["selected"] for item in inventory) == 5
    assert inventory[0]["reason"] == "DISCOVERY_RESERVED"
    assert (rules, behavior) == original


def test_shadow_api_persists_bounded_selection_inventory_and_preserves_job() -> None:
    from fastapi.testclient import TestClient

    from c2hunter_controller.ai_analysis import FakeGateway
    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.repositories import MemoryRepository

    repository = MemoryRepository()
    repository.jobs["job"] = {
        "id": "job",
        "status": "COMPLETED",
        "created_at": "2026-10-09T00:00:00Z",
    }
    repository.save_candidates(
        "job", [_candidate(f"198.51.100.{i}", score=90) for i in range(1, 7)]
    )
    original = deepcopy(repository.get_candidates("job"))
    client = TestClient(
        create_app(
            Settings(environment="test", ai_analysis_enabled=True),
            repository,
            ai_gateway=FakeGateway(),
        )
    )
    response = client.post(
        "/api/v1/analysis-jobs/job/ai-runs",
        json={"idempotency_key": "shadow", "discovery_mode": "shadow", "candidate_limit": 1},
    )
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["status"] == "COMPLETED"
    assert run["discovery_mode"] == "shadow"
    assert run["selection_summary"]["omitted_count"] == 5
    assert "selection_inventory" not in run
    assessment = client.get(f"/api/v1/ai-runs/{run['id']}/assessments").json()["items"][0]
    assert assessment["discovery_origin"] == "RULE"
    assert assessment["behavior_anomaly_score"] is None
    assert any(
        item["type"] == "BEHAVIOR_COVERAGE" for item in assessment["evidence_bundle"]["evidence"]
    )
    first = client.get(f"/api/v1/ai-runs/{run['id']}/selection?offset=0&limit=2")
    assert first.status_code == 200
    page = first.json()
    assert len(page["items"]) == 2
    assert page["total"] == 6
    assert page["next_offset"] == 2
    second = client.get(f"/api/v1/ai-runs/{run['id']}/selection?offset=2&limit=2").json()
    assert not (
        {item["candidate_id"] for item in page["items"]}
        & {item["candidate_id"] for item in second["items"]}
    )
    assert repository.get_candidates("job") == original
    assert repository.get_job("job")["status"] == "COMPLETED"


def test_c2_remote_model_requires_explicit_consent_before_enqueue() -> None:
    from fastapi.testclient import TestClient

    from c2hunter_controller.ai_analysis import FakeGateway
    from c2hunter_controller.ai_queueing import MemoryAIAnalysisTaskQueue
    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.repositories import MemoryRepository

    repo = MemoryRepository()
    repo.jobs["job"] = {"id": "job", "status": "COMPLETED"}
    repo.save_candidates("job", [_candidate("198.51.100.1", score=80)])
    queue = MemoryAIAnalysisTaskQueue()
    client = TestClient(
        create_app(
            Settings(
                environment="test",
                ai_analysis_enabled=True,
                ai_model_provider="openai-compatible",
                ai_model_base_url="https://model.example",
            ),
            repo,
            ai_gateway=FakeGateway(),
            ai_task_queue=queue,
        )
    )
    request = {"idempotency_key": "remote", "discovery_mode": "shadow"}
    denied = client.post("/api/v1/analysis-jobs/job/ai-runs", json=request)
    assert denied.status_code == 409
    assert denied.json()["error"]["code"] == "AI_REMOTE_CONSENT_REQUIRED"
    assert queue.depth() == 0
    assert repo.list_ai_runs("job") == []
    allowed = client.post(
        "/api/v1/analysis-jobs/job/ai-runs", json={**request, "allow_remote": True}
    )
    assert allowed.status_code == 201
    assert queue.depth() == 1


@pytest.mark.parametrize("changed", [{"discovery_mode": "legacy"}, {"candidate_limit": 2}])
def test_shadow_idempotency_rejects_different_selection_request(changed: dict) -> None:
    from c2hunter_controller.ai_analysis import AIAnalysisError, AIAnalysisService, FakeGateway
    from c2hunter_controller.repositories import MemoryRepository

    repo = MemoryRepository()
    repo.jobs["job"] = {"id": "job", "status": "COMPLETED"}
    repo.save_candidates("job", [_candidate("198.51.100.1", score=80)])
    service = AIAnalysisService(repo, FakeGateway())
    request = dict(
        analysis_job_id="job",
        idempotency_key="same",
        candidate_limit=1,
        created_by="analyst",
        discovery_mode="shadow",
    )
    initial, created = service.create_run(**request)
    assert created
    with pytest.raises(AIAnalysisError, match="idempotency"):
        service.create_run(**{**request, **changed})
    assert repo.get_ai_run(initial["id"]) == initial


def test_shadow_rejects_oversize_input_before_parsing_or_persisting() -> None:
    from c2hunter_controller.ai_analysis import AIAnalysisError, AIAnalysisService, FakeGateway
    from c2hunter_controller.ai_discovery import MAX_DISCOVERY_INPUT_FLOWS
    from c2hunter_controller.repositories import MemoryRepository

    repo = MemoryRepository()
    repo.jobs["job"] = {
        "id": "job",
        "status": "COMPLETED",
        "flow_records": [{}] * (MAX_DISCOVERY_INPUT_FLOWS + 1),
    }
    service = AIAnalysisService(repo, FakeGateway())
    with pytest.raises(AIAnalysisError, match="input.*limit"):
        service.create_run(
            analysis_job_id="job",
            idempotency_key="large",
            candidate_limit=1,
            created_by="analyst",
            discovery_mode="shadow",
        )
    assert repo.list_ai_runs("job") == []


@pytest.mark.parametrize("limit", [1, 2, 3, 4, 5])
def test_shadow_selection_is_deduplicated_bounded_and_preserves_operational_kind(
    limit: int,
) -> None:
    from c2hunter_controller.ai_discovery import select_shadow_candidates

    rules = [_candidate("198.51.100.1", score=80), _candidate("198.51.100.2", score=70)]
    rules[1]["candidate_kind"] = "COMMUNICATION_STATUS"
    behavior = [
        _candidate("198.51.100.1", anomaly=9.0),
        _candidate("198.51.100.2", anomaly=10.0),
        _candidate("203.0.113.9", anomaly=8.0),
    ]
    selected, inventory, summary = select_shadow_candidates(rules, behavior, limit=limit)
    assert len({item["external_ip"] for item in inventory}) == len(inventory) == 3
    assert len(selected) == min(limit, 3)
    assert summary["candidate_pool_count"] == summary["selected_count"] + summary["omitted_count"]
    operational = next(item for item in inventory if item["external_ip"] == "198.51.100.2")
    assert operational["origin"] == "RULE"
    assert operational["anomaly_score"] is None
    assert selected[0]["candidate_ip"] == "203.0.113.9"


def rule_free_job() -> tuple[dict, str]:
    import runpy
    from dataclasses import asdict
    from pathlib import Path

    from c2hunter_analysis.detectors import run_detectors

    fixture = runpy.run_path(
        str(Path(__file__).parents[2] / "analysis/tests/test_behavior_discovery.py")
    )["rule_free_fixture"]
    context, target = fixture()
    assert run_detectors(context) == []
    return {
        "id": "behavior-job",
        "idempotency_key": "behavior-job",
        "status": "COMPLETED",
        "flow_records": [
            asdict(flow) | {"timestamp": flow.timestamp.isoformat()} for flow in context.flows
        ],
    }, target


def test_rule_free_discovery_reaches_worker_and_survives_sqlite_reopen(tmp_path) -> None:
    from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway
    from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
    from c2hunter_controller.ai_worker import AIAnalysisWorker
    from c2hunter_controller.repositories import SQLiteRepository

    path = tmp_path / "discovery.sqlite3"
    repo = SQLiteRepository(path)
    job, target = rule_free_job()
    repo.create_job(job)
    original = deepcopy(repo.get_job(job["id"]))
    service = AIAnalysisService(repo, FakeGateway())
    run, _ = service.create_run(
        analysis_job_id=job["id"],
        idempotency_key="shadow-worker",
        candidate_limit=1,
        created_by="analyst",
        discovery_mode="shadow",
    )
    assert run["selection_summary"]["rule_free_selected_count"] == 1
    assert run["candidate_snapshots"][0]["candidate_ip"] == target
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": "receipt"}])
    worker = AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    assert worker.run_once(timeout=0)
    assert queue.acked == ["receipt"]
    repo.connection.close()
    reopened = SQLiteRepository(path)
    try:
        completed = reopened.get_ai_run(run["id"])
        assert completed["status"] == "COMPLETED", completed
        assert completed["selection_inventory"] == run["selection_inventory"]
        result = reopened.list_ai_assessments(run["id"])[0]
        assert result["discovery_origin"] == "BEHAVIOR"
        assert result["behavior_anomaly_score"] > 0
        bundle = result["evidence_bundle"]
        assert bundle["candidate"]["existing_c2hunter_score"] == 0
        types = {e["type"] for e in bundle["evidence"]}
        assert {"BEHAVIOR_RELATIVE_RECURRENCE", "BEHAVIOR_RELATIVE_RECORD_SIZE_STABILITY"} <= types
        assert "BEHAVIOR_COVERAGE" in types
        assert reopened.get_candidates(job["id"]) == []
        assert reopened.get_job(job["id"]) == original
    finally:
        reopened.connection.close()


def test_shadow_discovery_budget_warning_is_visible_without_partial_ranking() -> None:
    from c2hunter_analysis.behavior_discovery import MAX_INPUT_FLOWS

    from c2hunter_controller.ai_analysis import _shadow_candidate_selection

    job, _ = rule_free_job()
    job["flow_records"] = [job["flow_records"][0]] * (MAX_INPUT_FLOWS + 1)
    _, inventory, summary = _shadow_candidate_selection(job, [], 1)
    assert summary["discovery_candidate_count"] == 0
    assert any("INPUT_FLOW_BUDGET_EXCEEDED" in warning for warning in summary["warnings"])
    assert not any(item["origin"] == "BEHAVIOR" for item in inventory)


@pytest.mark.parametrize("value", [0, None, True, -1, float("inf")])
def test_shadow_rejects_invalid_observations_instead_of_inventing_packet_timing(value) -> None:
    from c2hunter_controller.ai_analysis import AIAnalysisError, _shadow_candidate_selection

    job, _ = rule_free_job()
    for record in job["flow_records"]:
        record["packet_count"] = value
    with pytest.raises(AIAnalysisError, match="observation"):
        _shadow_candidate_selection(job, [], 1)


@pytest.mark.parametrize("field", ["duration_seconds", "total_bytes", "timestamp"])
@pytest.mark.parametrize("mutation", ["absent", "null", "invalid"])
def test_shadow_requires_observed_duration_bytes_and_time(field: str, mutation: str) -> None:
    from c2hunter_controller.ai_analysis import AIAnalysisError, _shadow_candidate_selection

    job, _ = rule_free_job()
    for record in job["flow_records"]:
        if mutation == "absent":
            record.pop(field)
        else:
            record[field] = None if mutation == "null" else "not-an-observation"
    with pytest.raises(AIAnalysisError, match="observation"):
        _shadow_candidate_selection(job, [], 1)


def test_shadow_prefilter_never_ranks_aggregate_flushes_as_beacon_or_synchronization() -> None:
    from datetime import datetime, timedelta

    from c2hunter_controller.ai_analysis import (
        AIAnalysisService,
        FakeGateway,
        _ranked_candidate_snapshots,
        _shadow_candidate_selection,
    )
    from c2hunter_controller.repositories import MemoryRepository

    job, target = rule_free_job()
    start = datetime.fromisoformat(job["flow_records"][0]["timestamp"])
    template = next(row for row in job["flow_records"] if row["destination_ip"] == target)
    job["flow_records"] = [
        {
            **template,
            "source_ip": f"10.0.0.{host}",
            "packet_count": 20,
            "duration_seconds": 10,
            "timestamp": (start + timedelta(seconds=i * 60)).isoformat(),
        }
        for host in (1, 2, 3)
        for i in range(8)
    ]
    original = deepcopy(job)
    legacy = _ranked_candidate_snapshots(job, [], 1)[0]
    timing = {"AI_PREFILTER_SINGLE_HOST_BEACON", "AI_PREFILTER_SYNCHRONIZED_CLUSTER"}
    assert timing <= {e["type"] for e in legacy["evidence"]}
    selected, _, summary = _shadow_candidate_selection(job, [], 1)
    assert not timing & {e["type"] for e in selected[0]["evidence"]}
    removed_points = sum(e["contribution"] for e in legacy["evidence"] if e["type"] in timing)
    assert selected[0]["prefilter_score"] == legacy["prefilter_score"] - removed_points
    assert "AGGREGATED_FLOW_TIMING_UNAVAILABLE" in summary["warnings"]
    repo = MemoryRepository()
    repo.jobs[job["id"]] = job
    run, _ = AIAnalysisService(repo, FakeGateway()).create_and_execute(
        analysis_job_id=job["id"],
        idempotency_key="aggregate-safe",
        candidate_limit=1,
        created_by="analyst",
        discovery_mode="shadow",
    )
    assert run["status"] == "COMPLETED", run
    evidence = repo.list_ai_assessments(run["id"])[0]["evidence_bundle"]["evidence"]
    assert not timing & {e["type"] for e in evidence}
    assert job == original


@pytest.mark.parametrize("peer_count", [2048, 2049])
def test_shadow_generated_peer_admission_precedes_population_scoring(peer_count, monkeypatch):
    from ipaddress import IPv4Address

    import c2hunter_analysis.ai_candidates as prefilter

    from c2hunter_controller.ai_analysis import AIAnalysisError, _shadow_candidate_selection

    job, _ = rule_free_job()
    row = job["flow_records"][0]
    job["flow_records"] = [
        {**row, "destination_ip": str(IPv4Address(int(IPv4Address("198.18.0.1")) + index))}
        for index in range(peer_count)
    ]
    calls = []
    original = prefilter._robust_anomaly_factor

    def observed(*args):
        calls.append(len(args[2]))
        return original(*args)

    monkeypatch.setattr(prefilter, "_robust_anomaly_factor", observed)
    if peer_count == 2049:
        with pytest.raises(AIAnalysisError, match="admission limit"):
            _shadow_candidate_selection(job, [], 1)
        assert calls == []
    else:
        _, inventory, summary = _shadow_candidate_selection(job, [], 1)
        assert len(inventory) == summary["candidate_pool_count"] == peer_count
        assert len(calls) == peer_count


def test_shadow_propagates_observed_sensor_clock_uncertainty_into_ranking() -> None:
    from c2hunter_controller.ai_analysis import _shadow_candidate_selection

    job, _ = rule_free_job()
    clean, _, _ = _shadow_candidate_selection(job, [], 1)
    job["operations"] = {
        "warnings": ["CLOCK_SKEW"],
        "sensors": {"s1": {"status": "COMPLETED", "clock_offset_ms": 100000}},
    }
    before = deepcopy(job)
    selected, _, summary = _shadow_candidate_selection(job, [], 1)
    assert selected[0]["behavior_anomaly_score"] == clean[0]["behavior_anomaly_score"] - 10
    assert "CAPTURE_CLOCK_UNCERTAINTY" in summary["warnings"]
    assert any(
        e["type"] == "BEHAVIOR_CAPTURE_CLOCK_UNCERTAINTY" and e["contribution"] < 0
        for e in selected[0]["evidence"]
    )
    assert job == before
