"""Candidate verdict, threat-intelligence, and MISP workflow tests."""

from __future__ import annotations

import threading
from typing import Any

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.integrations import IntegrationError
from c2hunter_controller.repositories import MemoryRepository


class FakeThreatIntelService:
    def __init__(self) -> None:
        self.lookups: list[str] = []

    def lookup_ip(self, ip_address: str) -> dict[str, Any]:
        self.lookups.append(ip_address)
        return {
            "ip_address": ip_address,
            "fetched_at": "2026-08-08T00:00:00+00:00",
            "summary": {
                "malicious": 7,
                "suspicious": 2,
                "abuse_confidence_score": 85,
            },
            "providers": {
                "virustotal": {"status": "OK", "malicious": 7, "suspicious": 2},
                "abuseipdb": {"status": "OK", "abuse_confidence_score": 85},
            },
        }


class FakeMispClient:
    def __init__(self) -> None:
        self.exports: list[tuple[str, str, str]] = []
        self.lookups: list[str] = []
        self.fail = False

    def lookup_ip(self, ip_address: str) -> dict[str, Any]:
        self.lookups.append(ip_address)
        return {
            "status": "OK",
            "attribute_count": 2,
            "event_count": 1,
            "matches": [{"attribute_id": "77", "event_id": "42", "type": "ip-src"}],
        }

    def add_ip_attribute(self, event_id: str, ip_address: str, comment: str) -> dict[str, Any]:
        if self.fail:
            raise IntegrationError("misp", "MISP service unavailable")
        self.exports.append((event_id, ip_address, comment))
        return {"attribute_id": "9001", "event_id": event_id, "value": ip_address}


def _client() -> tuple[TestClient, MemoryRepository, FakeThreatIntelService, FakeMispClient]:
    repository = MemoryRepository()
    repository.jobs["job-1"] = {"id": "job-1", "name": "candidate workflow"}
    repository.save_candidates(
        "job-1",
        [
            {
                "id": "candidate-1",
                "candidate_ip": "203.0.113.44",
                "score": 75,
                "severity": "HIGH",
                "evidence": [],
                "adjustments": [],
                "hosts": ["10.0.0.1", "10.0.0.2"],
                "sensors": ["sensor-1"],
            }
        ],
    )
    threat_intel = FakeThreatIntelService()
    misp = FakeMispClient()
    client = TestClient(
        create_app(
            Settings(environment="test", misp_default_event_id="42"),
            repository,
            threat_intel_service=threat_intel,
            misp_client=misp,
        )
    )
    return client, repository, threat_intel, misp


def test_candidate_verdict_history_is_persisted_without_mutating_detection_output() -> None:
    client, repository, _, _ = _client()

    confirmed = client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={
            "verdict": "CONFIRMED_C2",
            "confidence": "HIGH",
            "note": "다중 센서와 TI 평판이 일치함",
        },
    )
    false_positive = client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={
            "verdict": "FALSE_POSITIVE",
            "confidence": "CONFIRMED",
            "note": "승인된 외부 프록시로 확인됨",
        },
    )

    assert confirmed.status_code == 200
    assert confirmed.json()["current_verdict"]["verdict"] == "CONFIRMED_C2"
    assert confirmed.json()["current_action"]["status"] == "PENDING"
    assert (
        confirmed.json()["current_action"]["verdict_id"]
        == confirmed.json()["current_verdict"]["id"]
    )
    assert false_positive.status_code == 200
    body = false_positive.json()
    assert body["current_verdict"]["verdict"] == "FALSE_POSITIVE"
    assert len(body["verdict_history"]) == 2
    detector_candidate = repository.get_candidates("job-1")[0]
    assert "current_verdict" not in detector_candidate
    assert "verdict_history" not in detector_candidate
    assert "excluded" not in detector_candidate
    assert repository.list_candidate_decisions("candidate-1") == body["verdict_history"]


def test_malformed_legacy_candidate_verdict_is_ignored_in_public_workflow() -> None:
    client, repository, _, _ = _client()
    repository.save_candidate_decision(
        {
            "id": "legacy-bad-verdict",
            "candidate_id": "candidate-1",
            "job_id": "job-1",
            "candidate_ip": "203.0.113.44",
            "verdict": {"verdict": "CONFIRMED_C2"},
            "confidence": "HIGH",
            "note": "legacy malformed record",
            "created_by": "legacy",
            "created_at": "2026-08-08T00:00:00+00:00",
        }
    )
    repository.candidate_decisions["legacy-missing-id"] = {
        "candidate_id": "candidate-1",
        "job_id": "job-1",
        "candidate_ip": "203.0.113.44",
        "verdict": "CONFIRMED_C2",
        "confidence": "HIGH",
        "note": "legacy record without an id",
        "created_by": "legacy",
        "created_at": "2026-08-09T00:00:00+00:00",
    }
    repository.save_candidate_decision(
        {
            "id": "legacy-invalid-created-at",
            "candidate_id": "candidate-1",
            "job_id": "job-1",
            "candidate_ip": "203.0.113.44",
            "verdict": "CONFIRMED_C2",
            "confidence": "HIGH",
            "note": "legacy record with an invalid timestamp",
            "created_by": "legacy",
            "created_at": "not-a-timestamp",
        }
    )

    response = client.get("/api/v1/candidates/candidate-1")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body.get("verdict_history", []) == []
    assert "current_verdict" not in body
    assert body["workflow_status"] == "NEEDS_REVIEW"


def test_confirmed_candidate_action_progress_and_completion_are_audited() -> None:
    client, repository, _, _ = _client()
    confirmed = client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "verified"},
    ).json()

    in_progress = client.post(
        "/api/v1/candidates/candidate-1/actions",
        json={"status": "IN_PROGRESS", "note": "EDR에서 호스트 격리 중"},
    )
    completed = client.post(
        "/api/v1/candidates/candidate-1/actions",
        json={"status": "COMPLETED", "note": "호스트 격리 및 IOC 차단 완료"},
    )
    persisted = client.get("/api/v1/candidates/candidate-1")

    assert in_progress.status_code == 200, in_progress.text
    assert in_progress.json()["workflow_status"] == "ACTION_IN_PROGRESS"
    assert completed.status_code == 200, completed.text
    body = completed.json()
    assert body["workflow_status"] == "ACTION_COMPLETED"
    assert body["current_verdict"]["verdict"] == "CONFIRMED_C2"
    assert body["current_action"]["status"] == "COMPLETED"
    assert body["current_action"]["completed_at"] == body["current_action"]["created_at"]
    assert body["current_action"]["created_by"] == "system"
    assert persisted.status_code == 200, persisted.text
    assert persisted.json()["workflow_status"] == "ACTION_COMPLETED"
    assert persisted.json()["current_action"] == body["current_action"]
    assert [item["status"] for item in body["action_history"]] == [
        "PENDING",
        "IN_PROGRESS",
        "COMPLETED",
    ]
    assert all(
        item["verdict_id"] == confirmed["current_verdict"]["id"] for item in body["action_history"]
    )
    assert repository.list_candidate_actions("candidate-1") == body["action_history"]


def test_candidate_action_requires_current_confirmed_c2_verdict() -> None:
    client, _, _, _ = _client()

    response = client.post(
        "/api/v1/candidates/candidate-1/actions",
        json={"status": "COMPLETED", "note": "should not be accepted"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CANDIDATE_NOT_CONFIRMED"


def test_new_confirmed_verdict_starts_a_new_action_cycle() -> None:
    client, _, _, _ = _client()
    first = client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "first incident"},
    ).json()
    client.post(
        "/api/v1/candidates/candidate-1/actions",
        json={"status": "COMPLETED", "note": "first incident resolved"},
    )
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "UNDER_REVIEW", "confidence": "MEDIUM", "note": "new evidence"},
    )

    second = client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "second incident"},
    ).json()

    assert second["current_verdict"]["id"] != first["current_verdict"]["id"]
    assert second["current_action"]["status"] == "PENDING"
    assert second["current_action"]["verdict_id"] == second["current_verdict"]["id"]
    assert second["workflow_status"] == "ACTION_REQUIRED"


def test_candidate_list_filters_current_verdict_and_keeps_false_positives_manageable() -> None:
    client, _, _, _ = _client()

    unreviewed = client.get("/api/v1/candidates?verdict=UNREVIEWED").json()
    assert unreviewed["total"] == 1
    assert unreviewed["workflow_counts"] == {
        "needs_review": 1,
        "in_review": 0,
        "action_required": 0,
        "action_in_progress": 0,
        "action_completed": 0,
        "false_positive": 0,
        "done": 0,
    }
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "verified"},
    )
    confirmed = client.get("/api/v1/candidates?verdict=CONFIRMED_C2").json()
    assert confirmed["total"] == 1
    assert confirmed["workflow_counts"]["action_required"] == 1
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "FALSE_POSITIVE", "confidence": "HIGH", "note": "trusted proxy"},
    )

    false_positives = client.get("/api/v1/candidates?verdict=FALSE_POSITIVE")

    assert false_positives.status_code == 200
    assert false_positives.json()["total"] == 1
    assert false_positives.json()["workflow_counts"]["false_positive"] == 1
    assert false_positives.json()["workflow_counts"]["done"] == 1
    assert client.get("/api/v1/candidates?verdict=INVALID").status_code == 422


def test_candidate_list_filters_response_workflow_independently_from_verdict() -> None:
    client, _, _, _ = _client()
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "verified"},
    )

    required = client.get("/api/v1/candidates?workflow_status=ACTION_REQUIRED")
    client.post(
        "/api/v1/candidates/candidate-1/actions",
        json={"status": "COMPLETED", "note": "isolated and blocked"},
    )
    completed = client.get("/api/v1/candidates?workflow_status=ACTION_COMPLETED")

    assert required.status_code == 200
    assert required.json()["total"] == 1
    assert completed.status_code == 200
    assert completed.json()["total"] == 1
    assert completed.json()["items"][0]["current_verdict"]["verdict"] == "CONFIRMED_C2"
    assert client.get("/api/v1/candidates?workflow_status=INVALID").status_code == 422


def test_candidate_threat_intelligence_lookup_is_persisted() -> None:
    client, repository, threat_intel, misp = _client()

    response = client.post("/api/v1/candidates/candidate-1/threat-intelligence/lookups")

    assert response.status_code == 200
    assert response.json()["summary"]["abuse_confidence_score"] == 85
    assert threat_intel.lookups == ["203.0.113.44"]
    assert misp.lookups == ["203.0.113.44"]
    assert response.json()["providers"]["misp"]["attribute_count"] == 2
    assert response.json()["summary"]["misp_event_count"] == 1
    assert response.json()["origin"] == "MANUAL"
    detector_candidate = repository.get_candidates("job-1")[0]
    assert "threat_intelligence" not in detector_candidate
    stored = repository.list_candidate_ti_lookups("candidate-1")[0]
    assert stored["providers"]["virustotal"]["malicious"] == 7


def test_new_candidates_are_automatically_enriched_when_integrations_are_configured() -> None:
    repository = MemoryRepository()
    threat_intel = FakeThreatIntelService()
    misp = FakeMispClient()
    app = create_app(
        Settings(environment="test", candidate_auto_enrichment_limit=1),
        repository,
        threat_intel_service=threat_intel,
        misp_client=misp,
    )
    repository.jobs["job-1"] = {"id": "job-1", "name": "automatic enrichment"}
    candidates = [
        {"id": "candidate-high", "candidate_ip": "203.0.113.44", "score": 90},
        {"id": "candidate-low", "candidate_ip": "203.0.113.45", "score": 60},
    ]
    repository.save_candidates("job-1", candidates)

    app.state.schedule_candidate_enrichment("job-1", candidates)
    app.state.wait_for_candidate_enrichment()

    assert threat_intel.lookups == ["203.0.113.44"]
    assert misp.lookups == ["203.0.113.44"]
    stored = repository.list_candidate_ti_lookups("candidate-high")[-1]
    assert stored["status"] == "COMPLETED"
    assert stored["origin"] == "AUTO"
    assert stored["providers"]["misp"]["event_count"] == 1
    assert repository.list_candidate_ti_lookups("candidate-low") == []


def test_automatic_enrichment_records_unexpected_provider_failure() -> None:
    class BrokenThreatIntelService:
        def lookup_ip(self, ip_address: str) -> dict[str, Any]:
            del ip_address
            raise RuntimeError("provider implementation bug with sensitive details")

    repository = MemoryRepository()
    app = create_app(
        Settings(environment="test"),
        repository,
        threat_intel_service=BrokenThreatIntelService(),
    )
    candidate = {"id": "candidate-broken", "candidate_ip": "203.0.113.44", "score": 90}
    repository.save_candidates("job-broken", [candidate])

    app.state.schedule_candidate_enrichment("job-broken", [candidate])
    app.state.wait_for_candidate_enrichment()

    stored = repository.list_candidate_ti_lookups("candidate-broken")[-1]
    assert stored["status"] == "FAILED"
    assert stored["providers"]["internal"]["error"] == "candidate enrichment failed"
    assert "sensitive details" not in str(stored)


def test_automatic_enrichment_queue_capacity_does_not_block_analysis() -> None:
    class BlockingThreatIntelService:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()

        def lookup_ip(self, ip_address: str) -> dict[str, Any]:
            self.started.set()
            assert self.release.wait(timeout=5)
            return {"ip_address": ip_address, "providers": {}, "summary": {}}

    repository = MemoryRepository()
    threat_intel = BlockingThreatIntelService()
    app = create_app(
        Settings(
            environment="test",
            candidate_auto_enrichment_limit=2,
            candidate_auto_enrichment_workers=1,
            candidate_auto_enrichment_queue_capacity=1,
        ),
        repository,
        threat_intel_service=threat_intel,
    )
    candidates = [
        {"id": "candidate-first", "candidate_ip": "203.0.113.44", "score": 90},
        {"id": "candidate-overflow", "candidate_ip": "203.0.113.45", "score": 80},
    ]
    repository.save_candidates("job-capacity", candidates)

    app.state.schedule_candidate_enrichment("job-capacity", candidates)

    assert threat_intel.started.wait(timeout=1)
    overflow = repository.list_candidate_ti_lookups("candidate-overflow")[-1]
    assert overflow["status"] == "FAILED"
    assert overflow["providers"]["internal"]["error"] == (
        "automatic enrichment queue capacity exceeded"
    )
    threat_intel.release.set()
    app.state.wait_for_candidate_enrichment()
    assert repository.list_candidate_ti_lookups("candidate-first")[-1]["status"] == "COMPLETED"


def test_misp_export_requires_confirmed_candidate() -> None:
    client, _, _, misp = _client()

    response = client.post(
        "/api/v1/candidates/candidate-1/misp-exports",
        json={"event_id": "42", "comment": "C2Hunter candidate"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CANDIDATE_NOT_CONFIRMED"
    assert misp.exports == []


def test_confirmed_candidate_exports_ip_src_to_misp_once() -> None:
    client, repository, _, misp = _client()
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={
            "verdict": "CONFIRMED_C2",
            "confidence": "CONFIRMED",
            "note": "분석가 확인",
        },
    )

    first = client.post(
        "/api/v1/candidates/candidate-1/misp-exports",
        json={"event_id": "42", "comment": "C2Hunter confirmed C2"},
    )
    duplicate = client.post(
        "/api/v1/candidates/candidate-1/misp-exports",
        json={"event_id": "42", "comment": "duplicate retry"},
    )

    assert first.status_code == 200
    assert first.json()["status"] == "EXPORTED"
    assert first.json()["attribute_type"] == "ip-src"
    assert duplicate.status_code == 200
    assert duplicate.json()["status"] == "ALREADY_EXPORTED"
    assert misp.exports == [("42", "203.0.113.44", "C2Hunter confirmed C2")]
    detector_candidate = repository.get_candidates("job-1")[0]
    assert "misp_exports" not in detector_candidate
    stored = repository.list_candidate_misp_actions("candidate-1")
    assert len(stored) == 1
    assert stored[0]["attribute_id"] == "9001"
    assert stored[0]["idempotency_key"] == "candidate-1:42"


def test_misp_export_uses_configured_default_event() -> None:
    client, _, _, misp = _client()
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "verified"},
    )

    response = client.post("/api/v1/candidates/candidate-1/misp-exports", json={})

    assert response.status_code == 200
    assert response.json()["event_id"] == "42"
    assert misp.exports == [("42", "203.0.113.44", "C2Hunter confirmed C2 candidate")]


def test_candidate_workflow_rejects_unknown_candidate() -> None:
    client, _, _, _ = _client()

    verdict = client.post(
        "/api/v1/candidates/missing/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "not found"},
    )
    lookup = client.post("/api/v1/candidates/missing/threat-intelligence/lookups")

    assert verdict.status_code == 404
    assert lookup.status_code == 404


def test_misp_failure_is_recorded_without_remote_response_data() -> None:
    client, repository, _, misp = _client()
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "verified"},
    )
    misp.fail = True

    response = client.post("/api/v1/candidates/candidate-1/misp-exports", json={"event_id": "42"})

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "MISP_EXPORT_FAILED"
    record = repository.list_candidate_misp_actions("candidate-1")[0]
    assert record["status"] == "FAILED"
    assert record["error"] == "MISP service unavailable"
    assert "response" not in record


def test_unconfigured_integrations_return_service_unavailable() -> None:
    _, repository, _, _ = _client()
    client = TestClient(create_app(Settings(environment="test"), repository))

    lookup = client.post("/api/v1/candidates/candidate-1/threat-intelligence/lookups")
    export = client.post("/api/v1/candidates/candidate-1/misp-exports", json={"event_id": "42"})

    assert lookup.status_code == 503
    assert lookup.json()["error"]["code"] == "THREAT_INTELLIGENCE_NOT_CONFIGURED"
    assert export.status_code == 503
    assert export.json()["error"]["code"] == "MISP_NOT_CONFIGURED"
