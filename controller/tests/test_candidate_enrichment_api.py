"""Candidate verdict, threat-intelligence, and MISP workflow tests."""

from __future__ import annotations

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
        self.fail = False

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
    assert false_positive.status_code == 200
    body = false_positive.json()
    assert body["current_verdict"]["verdict"] == "FALSE_POSITIVE"
    assert len(body["verdict_history"]) == 2
    detector_candidate = repository.get_candidates("job-1")[0]
    assert "current_verdict" not in detector_candidate
    assert "verdict_history" not in detector_candidate
    assert "excluded" not in detector_candidate
    assert repository.list_candidate_decisions("candidate-1") == body["verdict_history"]


def test_candidate_list_filters_current_verdict_and_keeps_false_positives_manageable() -> None:
    client, _, _, _ = _client()

    assert client.get("/api/v1/candidates?verdict=UNREVIEWED").json()["total"] == 1
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "CONFIRMED_C2", "confidence": "HIGH", "note": "verified"},
    )
    assert client.get("/api/v1/candidates?verdict=CONFIRMED_C2").json()["total"] == 1
    client.post(
        "/api/v1/candidates/candidate-1/verdicts",
        json={"verdict": "FALSE_POSITIVE", "confidence": "HIGH", "note": "trusted proxy"},
    )

    false_positives = client.get("/api/v1/candidates?verdict=FALSE_POSITIVE")

    assert false_positives.status_code == 200
    assert false_positives.json()["total"] == 1
    assert client.get("/api/v1/candidates?verdict=INVALID").status_code == 422


def test_candidate_threat_intelligence_lookup_is_persisted() -> None:
    client, repository, threat_intel, _ = _client()

    response = client.post("/api/v1/candidates/candidate-1/threat-intelligence/lookups")

    assert response.status_code == 200
    assert response.json()["summary"]["abuse_confidence_score"] == 85
    assert threat_intel.lookups == ["203.0.113.44"]
    detector_candidate = repository.get_candidates("job-1")[0]
    assert "threat_intelligence" not in detector_candidate
    stored = repository.list_candidate_ti_lookups("candidate-1")[0]
    assert stored["providers"]["virustotal"]["malicious"] == 7


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
