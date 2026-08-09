from __future__ import annotations

from fastapi.testclient import TestClient

from c2hunter_controller.ai_analysis import FakeGateway
from c2hunter_controller.ai_queueing import MemoryAIAnalysisTaskQueue
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


def completed_job() -> dict[str, object]:
    return {
        "id": "job-1",
        "status": "COMPLETED",
        "created_at": "2026-08-09T00:00:00+00:00",
        "updated_at": "2026-08-09T00:01:00+00:00",
    }


def candidate() -> dict[str, object]:
    return {
        "id": "candidate-1",
        "job_id": "job-1",
        "candidate_ip": "203.0.113.9",
        "score": 82,
        "severity": "HIGH",
        "internal_hosts": ["10.0.0.2"],
        "protocols": ["TCP"],
        "ports": [443],
        "first_seen": "2026-08-09T00:00:00+00:00",
        "last_seen": "2026-08-09T00:01:00+00:00",
        "evidence": [
            {
                "detector": "PERIODIC_BEACON",
                "description": "regular outbound intervals",
                "contribution": 60,
                "metrics": {"interval_cv": 0.05},
            }
        ],
    }


def api() -> tuple[TestClient, MemoryRepository]:
    repository = MemoryRepository()
    repository.jobs["job-1"] = completed_job()
    repository.save_candidates("job-1", [candidate()])
    app = create_app(
        Settings(environment="test", ai_analysis_enabled=True),
        repository,
        ai_gateway=FakeGateway(),
    )
    return TestClient(app), repository


class InvalidGateway:
    provider = "invalid-test"
    model = "invalid-test"

    def assess(self, bundle: object) -> dict[str, object]:
        return {}


class DepthUnavailableQueue(MemoryAIAnalysisTaskQueue):
    def depth(self) -> int:
        raise RuntimeError("metrics backend unavailable")


def test_ai_run_api_completes_lists_and_exposes_validated_assessment() -> None:
    client, repository = api()

    created = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "api-key", "candidate_limit": 5},
    )
    duplicate = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "api-key", "candidate_limit": 5},
    )

    assert created.status_code == 201
    assert duplicate.status_code == 200
    run = created.json()
    assert run["id"] == duplicate.json()["id"]
    assert run["status"] == "COMPLETED"
    assert repository.get_job("job-1")["status"] == "COMPLETED"  # type: ignore[index]

    listing = client.get("/api/v1/analysis-jobs/job-1/ai-runs")
    detail = client.get(f"/api/v1/ai-runs/{run['id']}")
    assessments = client.get(f"/api/v1/ai-runs/{run['id']}/assessments")

    assert listing.status_code == detail.status_code == assessments.status_code == 200
    assert listing.json()["total"] == 1
    assert detail.json()["candidate_count"] == 1
    assessment = assessments.json()["items"][0]
    assert assessment["assessment"]["candidate"]["external_ip"] == "203.0.113.9"
    assert assessment["evidence_bundle"]["evidence"][0]["id"].startswith("E-C2H-")
    evidence_response = client.get(f"/api/v1/ai-assessments/{assessment['id']}/evidence-bundle")
    assert evidence_response.status_code == 200
    assert [event["kind"] for event in repository.audit_events] == [
        "ai-run-create",
        "ai-run-create",
        "ai-evidence-bundle-view",
    ]


def test_ai_failed_inline_run_returns_persisted_terminal_state() -> None:
    repository = MemoryRepository()
    repository.jobs["job-1"] = completed_job()
    repository.save_candidates("job-1", [candidate()])
    client = TestClient(
        create_app(
            Settings(environment="test", ai_analysis_enabled=True),
            repository,
            ai_gateway=InvalidGateway(),
        )
    )

    response = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "invalid-output", "candidate_limit": 1},
    )
    assert response.status_code == 201
    assert response.json()["status"] == "FAILED"
    assert response.json()["error_code"] == "MODEL_OUTPUT_INVALID"


def test_ai_run_api_rejects_non_completed_jobs_and_disabled_feature() -> None:
    client, repository = api()
    repository.jobs["job-1"]["status"] = "RUNNING"

    invalid = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "invalid", "candidate_limit": 5},
    )
    assert invalid.status_code == 409
    assert invalid.json()["error"]["code"] == "AI_RUN_NOT_ALLOWED"

    disabled = TestClient(
        create_app(Settings(environment="test", ai_analysis_enabled=False), repository)
    )
    response = disabled.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "disabled", "candidate_limit": 5},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "AI_ANALYSIS_DISABLED"


def test_ai_run_cancel_is_idempotent_for_terminal_run() -> None:
    client, _ = api()
    run = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "cancel-api", "candidate_limit": 5},
    ).json()

    first = client.post(f"/api/v1/ai-runs/{run['id']}/cancel", json={"reason": "operator"})
    second = client.post(f"/api/v1/ai-runs/{run['id']}/cancel", json={"reason": "again"})

    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == second.json()["status"] == "COMPLETED"


def test_analysis_job_delete_refuses_active_ai_run() -> None:
    client, repository = api()
    run, _created = repository.create_ai_run(
        {
            "id": "run-active",
            "analysis_job_id": "job-1",
            "idempotency_key": "active-delete",
            "created_at": "2026-08-09T00:02:00+00:00",
            "status": "ANALYZING",
        }
    )

    response = client.delete("/api/v1/analysis-jobs/job-1")

    assert run["status"] == "ANALYZING"
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "AI_RUN_ACTIVE"
    assert repository.get_job("job-1") is not None


def test_ai_run_api_enqueues_reference_without_model_payload() -> None:
    repository = MemoryRepository()
    repository.jobs["job-1"] = completed_job()
    repository.save_candidates("job-1", [candidate()])
    queue = MemoryAIAnalysisTaskQueue()
    client = TestClient(
        create_app(
            Settings(environment="test", ai_analysis_enabled=True),
            repository,
            ai_gateway=FakeGateway(),
            ai_task_queue=queue,
        )
    )

    response = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "queued", "candidate_limit": 5},
    )

    assert response.status_code == 201
    assert response.json()["status"] == "QUEUED"
    assert queue.run_ids == [response.json()["id"]]
    metrics = client.get("/api/v1/metrics").text
    assert "c2hunter_ai_queue_waiting_depth 1.0" in metrics


def test_ai_metrics_failure_does_not_fail_enqueue(
    monkeypatch: object,
) -> None:
    repository = MemoryRepository()
    repository.jobs["job-1"] = completed_job()
    repository.save_candidates("job-1", [candidate()])
    queue = DepthUnavailableQueue()
    application = create_app(
        Settings(environment="test", ai_analysis_enabled=True),
        repository,
        ai_gateway=FakeGateway(),
        ai_task_queue=queue,
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        application.state.ai_metrics["enqueue_latency"],
        "labels",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("metrics failure")),
    )
    client = TestClient(application)

    response = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "depth-unavailable", "candidate_limit": 1},
    )

    assert response.status_code == 201
    assert response.json()["status"] == "QUEUED"
    assert queue.run_ids == [response.json()["id"]]


def test_ai_artifact_api_lists_regenerates_and_reviews_drafts_without_publishing() -> None:
    client, repository = api()
    run = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "artifact-api", "candidate_limit": 5},
    ).json()
    assessment = client.get(f"/api/v1/ai-runs/{run['id']}/assessments").json()["items"][0]

    listing = client.get(f"/api/v1/ai-assessments/{assessment['id']}/artifacts")

    assert listing.status_code == 200
    assert listing.json()["total"] == 3
    artifacts = listing.json()["items"]
    misp = next(item for item in artifacts if item["artifact_type"] == "MISP_DRAFT")
    assert misp["content"]["Event"]["published"] is False

    detail = client.get(f"/api/v1/ai-artifacts/{misp['id']}")
    approved = client.post(
        f"/api/v1/ai-artifacts/{misp['id']}/approve",
        json={"note": "schema and provenance reviewed"},
    )
    conflict = client.post(
        f"/api/v1/ai-artifacts/{misp['id']}/reject",
        json={"note": "cannot reverse approval"},
    )
    regenerated = client.post(f"/api/v1/ai-assessments/{assessment['id']}/artifacts/regenerate")

    assert detail.status_code == 200
    assert approved.status_code == 200
    assert approved.json()["approved_status"] == "APPROVED"
    assert approved.json()["review_note"] == "schema and provenance reviewed"
    assert conflict.status_code == 409
    assert regenerated.status_code == 201
    assert regenerated.json()["total"] == 3
    assert len(repository.list_ai_artifacts(assessment["id"])) == 6
    assert [event["kind"] for event in repository.audit_events[-2:]] == [
        "ai-artifact-approved",
        "ai-artifacts-regenerate",
    ]


def test_ai_feedback_api_is_append_only_and_keeps_ai_verdict_separate() -> None:
    client, repository = api()
    run = client.post(
        "/api/v1/analysis-jobs/job-1/ai-runs",
        json={"idempotency_key": "feedback-api", "candidate_limit": 5},
    ).json()
    assessment = client.get(f"/api/v1/ai-runs/{run['id']}/assessments").json()["items"][0]
    original_ai_verdict = assessment["assessment"]["candidate"]["verdict"]

    created = client.post(
        f"/api/v1/ai-assessments/{assessment['id']}/feedback",
        json={
            "verdict": "CONFIRM_C2",
            "corrected_confidence": 0.95,
            "note": "Confirmed from passive endpoint telemetry",
        },
    )
    invalid = client.post(
        f"/api/v1/ai-assessments/{assessment['id']}/feedback",
        json={"verdict": "CONFIRM_BENIGN", "corrected_confidence": 2, "note": "invalid"},
    )
    listing = client.get(f"/api/v1/ai-assessments/{assessment['id']}/feedback")
    stored_assessment = repository.get_ai_assessment(assessment["id"])

    assert assessment["review_priority"] == 55
    assert assessment["review_priority_version"] == "review-priority-v1"
    assert created.status_code == 201
    assert listing.status_code == 200
    assert listing.json()["items"][0]["verdict"] == "CONFIRM_C2"
    assert invalid.status_code == 422
    assert stored_assessment is not None
    assert stored_assessment["assessment"]["candidate"]["verdict"] == original_ai_verdict
    assert repository.audit_events[-1]["kind"] == "ai-feedback-create"
