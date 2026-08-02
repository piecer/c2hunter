from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient
from test_analysis_job_api import api, payload, synthetic_flows

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


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


def test_analyst_api_requires_a_server_validated_bearer_token() -> None:
    client = TestClient(
        create_app(
            Settings(environment="production", api_auth_required=True),
            MemoryRepository(),
        )
    )

    missing = client.get("/api/v1/dashboard")
    invalid = client.get("/api/v1/dashboard", headers={"Authorization": "Bearer not-a-real-token"})

    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "AUTH_TOKEN_REQUIRED"
    assert invalid.status_code == 401
    assert invalid.json()["error"]["code"] == "INVALID_AUTH_TOKEN"
    assert client.get("/api/v1/health").status_code == 200


def test_development_login_token_is_accepted_by_protected_routes() -> None:
    client = TestClient(
        create_app(
            Settings(
                environment="development",
                api_auth_required=True,
                dev_login_enabled=True,
            ),
            MemoryRepository(),
        )
    )
    login = client.post("/api/v1/auth/dev-login", json={"username": "analyst"})

    response = client.get(
        "/api/v1/dashboard",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )

    assert login.status_code == 200
    assert login.json()["role"] == "ADMIN"
    assert response.status_code == 200


def test_static_tokens_enforce_viewer_and_analyst_roles() -> None:
    viewer_token = "viewer-token-for-contract-test"
    analyst_token = "analyst-token-for-contract-test"
    client = TestClient(
        create_app(
            Settings(
                environment="production",
                api_auth_required=True,
                viewer_token_sha256=token_hash(viewer_token),
                analyst_token_sha256=token_hash(analyst_token),
            ),
            MemoryRepository(),
        )
    )

    assert (
        client.get(
            "/api/v1/dashboard", headers={"Authorization": f"Bearer {viewer_token}"}
        ).status_code
        == 200
    )
    forbidden = client.post(
        "/api/v1/analysis-jobs",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={},
    )
    analyst = client.post(
        "/api/v1/analysis-jobs",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={},
    )

    assert forbidden.status_code == 403
    assert forbidden.json()["error"]["code"] == "INSUFFICIENT_ROLE"
    assert analyst.status_code == 422


def test_development_login_is_rate_limited() -> None:
    client = TestClient(
        create_app(
            Settings(
                environment="development",
                api_auth_required=True,
                dev_login_enabled=True,
                rate_limit_window_seconds=60,
                dev_login_rate_limit=1,
            ),
            MemoryRepository(),
        )
    )

    assert client.post("/api/v1/auth/dev-login", json={"username": "first"}).status_code == 200
    limited = client.post("/api/v1/auth/dev-login", json={"username": "second"})

    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert limited.headers["retry-after"]


def test_analysis_job_creation_is_rate_limited_per_principal() -> None:
    admin_token = "admin-token-for-rate-limit-test"
    client = TestClient(
        create_app(
            Settings(
                environment="production",
                api_auth_required=True,
                admin_token_sha256=token_hash(admin_token),
                analysis_job_rate_limit=1,
            ),
            MemoryRepository(),
        )
    )
    headers = {"Authorization": f"Bearer {admin_token}"}

    assert client.post("/api/v1/analysis-jobs", headers=headers, json={}).status_code == 422
    limited = client.post("/api/v1/analysis-jobs", headers=headers, json={})

    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"


def test_global_candidate_routes_return_job_context_required_by_web_actions() -> None:
    client = api()
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="web-contract"),
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
