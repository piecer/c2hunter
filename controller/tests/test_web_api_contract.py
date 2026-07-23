from __future__ import annotations

from fastapi.testclient import TestClient
from test_analysis_job_api import api, payload, synthetic_flows

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


def test_openapi_exposes_every_top_level_web_route() -> None:
    schema = create_app(Settings(environment="test"), MemoryRepository()).openapi()

    assert schema["paths"]["/api/v1/auth/dev-login"]["post"]
    assert schema["paths"]["/api/v1/candidates"]["get"]
    assert schema["paths"]["/api/v1/candidates/{candidate_id}"]["get"]
    assert schema["paths"]["/api/v1/analysis-jobs/{job_id}/flows"]["get"]
    assert schema["paths"]["/api/v1/analysis-jobs/{job_id}/flow-labels"]["post"]
    assert schema["paths"]["/api/v1/payload-signatures"]["get"]
    assert schema["paths"]["/api/v1/payload-signatures/{signature_id}"]["patch"]


def test_development_login_is_disabled_by_default_and_explicit_when_enabled() -> None:
    disabled = TestClient(create_app(Settings(environment="test"), MemoryRepository()))
    response = disabled.post("/api/v1/auth/dev-login", json={"username": "analyst"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "DEV_LOGIN_DISABLED"

    enabled = TestClient(
        create_app(Settings(environment="test", dev_login_enabled=True), MemoryRepository())
    )
    first = enabled.post("/api/v1/auth/dev-login", json={"username": "analyst"})
    second = enabled.post("/api/v1/auth/dev-login", json={"username": "analyst"})
    assert first.status_code == 200
    assert first.json()["token_type"] == "bearer"
    assert first.json()["expires_in"] > 0
    assert first.json()["access_token"] != second.json()["access_token"]
    assert "development" in first.json()["limitations"].lower()


def test_global_candidate_routes_return_job_context_required_by_web_actions() -> None:
    client = api()
    job = client.post(
        "/api/v1/analysis-jobs", json=payload(flows=synthetic_flows(), key="web-contract")
    ).json()

    candidates = client.get("/api/v1/candidates")
    assert candidates.status_code == 200
    candidate = candidates.json()["items"][0]
    assert candidate["job_id"] == job["id"]
    assert candidate["distinct_internal_hosts"] == len(candidate["internal_hosts"])
    assert candidate["sensor_ids"] == candidate["sensors"]
    assert candidate["protocols"] == ["TCP"]
    assert candidate["ports"] == [4444]

    detail = client.get(f"/api/v1/candidates/{candidate['id']}")
    assert detail.status_code == 200
    assert detail.json()["job_id"] == job["id"]
    assert detail.json()["traffic_series"]
    assert detail.json()["evidence_count"] == len(detail.json()["evidence"])


def test_cancel_accepts_the_web_reason_body_and_rejects_unknown_fields() -> None:
    client = api()
    job = client.post("/api/v1/analysis-jobs", json=payload(key="cancel-contract")).json()

    response = client.post(
        f"/api/v1/analysis-jobs/{job['id']}/cancel",
        json={"reason": "operator requested from web console"},
    )
    assert response.status_code == 200

    other = client.post("/api/v1/analysis-jobs", json=payload(key="cancel-extra")).json()
    invalid = client.post(
        f"/api/v1/analysis-jobs/{other['id']}/cancel",
        json={"reason": "operator", "unexpected": True},
    )
    assert invalid.status_code == 422
