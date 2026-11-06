"""Transport/auth failures never transfer source or invoke the provider."""

import json

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_http_runtime import (
    BASE,
    CAPS,
    HEADERS,
    configured,
    request_from,
    settings,
    wait_for,
)
from tests.test_ai_investigation_loop import adaptive, structured_provider


def test_cancel_body_is_bounded_before_mutation():
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    with structured_provider(adaptive) as (gateway, _):
        app = create_app(
            settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
        )
        with TestClient(app) as client:
            preview = client.post(
                BASE + "/source-preview", json={"target_ip": "2001:db8::1"}, headers=HEADERS
            ).json()
            created = client.post(BASE, json=request_from(preview), headers=HEADERS).json()
            path = BASE + "/" + created["id"]
            response = client.post(path + "/cancel", content=b" " * 16385, headers=HEADERS)
            assert response.status_code == 413, response.text
            assert client.get(path, headers=HEADERS).json()["status"] != "CANCELLED"
    repo.close()


@pytest.mark.parametrize("auth_required", [True, False])
def test_all_routes_authenticate_analyst_before_expensive_work(monkeypatch, auth_required):
    repo = MemoryRepository()
    config = settings().model_copy(update={"api_auth_required": auth_required})
    with structured_provider(adaptive) as (gateway, calls):
        app = create_app(config, repo, ai_gateway=configured(gateway))
        service = app.state.investigation_service
        for name in ("page", "get", "lookup", "cancel", "saved_input", "steps", "evidence"):
            monkeypatch.setattr(
                service.store, name, lambda *_a, **_k: pytest.fail("private work before auth")
            )
        monkeypatch.setattr(
            repo, "read_investigation_source", lambda *_a, **_k: pytest.fail("source before auth")
        )
        paths = [
            ("GET", CAPS),
            ("POST", BASE),
            ("POST", BASE + "/source-preview"),
            ("GET", BASE),
            ("GET", BASE + "/run"),
            ("GET", BASE + "/run/steps"),
            ("GET", BASE + "/run/evidence/id"),
            ("POST", BASE + "/run/cancel"),
        ]
        with TestClient(app) as client:
            for method, path in paths:
                assert client.request(method, path, content=b"[" * 17000).status_code == 401
                result = client.request(
                    method, path, content=b"[" * 17000, headers={"Authorization": "Bearer viewer"}
                )
                assert result.status_code == 403 and result.json()["error"]["details"] is None
        assert calls == []
    repo.close()


def test_request_bytes_schema_faults_and_safe_storage_errors(monkeypatch):
    repo = MemoryRepository()
    with structured_provider(adaptive) as (gateway, calls):
        app = create_app(settings(), repo, ai_gateway=configured(gateway))
        service = app.state.investigation_service
        monkeypatch.setattr(
            repo,
            "read_investigation_source",
            lambda *_a, **_k: pytest.fail("source before validation"),
        )
        with TestClient(app) as client:
            for content in (b" " * 16385, "가" * 5500):
                response = client.post(BASE + "/source-preview", content=content, headers=HEADERS)
                assert response.status_code == 413
            for payload in ({"target_ip": "x"}, {"target_ip": "1.2.3.4", "owner_id": "bob"}):
                response = client.post(BASE + "/source-preview", json=payload, headers=HEADERS)
                assert response.status_code == 422
                assert response.json()["error"]["details"] is None
            for query in ("limit=0", "limit=6", "after=bogus", "limit=1.0"):
                assert client.get(BASE + "?" + query, headers=HEADERS).status_code == 422
            from c2hunter_controller.ai_investigation_store import InvestigationStorageError

            def fault(*_a, **_k):
                raise InvestigationStorageError("password=private-dsn-and-token")

            monkeypatch.setattr(service, "page", fault)
            response = client.get(BASE, headers=HEADERS)
            assert response.status_code == 503
            assert "private-dsn" not in response.text
            assert response.json()["error"]["code"] == "STORAGE_UNAVAILABLE"
        assert calls == []
    repo.close()


def test_real_sessions_bind_subject_job_run_and_saved_descendants(monkeypatch):
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    with structured_provider(adaptive) as (gateway, calls):
        app = create_app(
            settings(dev_login_enabled=True),
            repo,
            ai_gateway=configured(gateway),
            local_ai_worker_enabled=True,
        )
        with TestClient(app) as client:

            def login(name):
                response = client.post("/api/v1/auth/dev-login", json={"username": name})
                assert response.status_code == 200, response.text
                return {"Authorization": "Bearer " + response.json()["access_token"]}

            alice = login("analyst-alice")
            alice_again = login("analyst-alice")
            bob = login("bob")
            preview = client.post(
                BASE + "/source-preview", json={"target_ip": "2001:db8::1"}, headers=alice
            ).json()
            request = request_from(preview)
            posted = client.post(BASE, json=request, headers=alice)
            assert posted.status_code == 202, posted.text
            path = BASE + "/" + posted.json()["id"]
            saved = wait_for(
                lambda: (
                    r
                    if (r := client.get(path, headers=alice).json())["status"] == "COMPLETED"
                    else None
                )
            )
            eid = saved["result"]["support"][0]["evidence_ids"][0]
            assert client.get(path, headers=alice_again).json() == saved
            for method, descendant in (
                ("GET", ""),
                ("GET", "/steps"),
                ("GET", "/evidence/" + eid),
                ("POST", "/cancel"),
            ):
                assert client.request(method, path + descendant, headers=bob).status_code == 404
                assert (
                    client.request(
                        method, (path + descendant).replace("/job/", "/other/"), headers=alice
                    ).status_code
                    == 404
                )
            assert client.get(BASE, headers=bob).json() == {"items": [], "next_cursor": None}
            assert (
                client.post(
                    BASE, headers=alice, json={**request, "question": "different"}
                ).status_code
                == 409
            )
            text = json.dumps(saved)
            for secret in (
                "lease_token",
                "snapshot_json",
                "worker_id",
                "analyst-alice",
                "authorization",
            ):
                assert secret not in text
            assert len(calls) == 3
    repo.close()


def test_response_limit_is_actual_utf8_bytes_before_headers(monkeypatch):
    repo = MemoryRepository()
    with structured_provider(adaptive) as (gateway, _):
        app = create_app(settings(), repo, ai_gateway=configured(gateway))

        class Oversized:
            def model_dump(self, **_):
                return {"text": "가" * 90000}

        monkeypatch.setattr(
            app.state.investigation_service, "page", lambda *_a, **_k: [Oversized()]
        )
        with TestClient(app) as client:
            response = client.get(BASE, headers=HEADERS)
            assert response.status_code == 503, response.text[:200]
            assert response.json()["error"]["code"] == "RESPONSE_TOO_LARGE"
            assert len(response.content) < 262144
    repo.close()


def test_security_error_request_id_cannot_bypass_response_byte_bound():
    app = create_app(settings(), MemoryRepository())
    with TestClient(app) as client:
        response = client.get(CAPS, headers={"x-request-id": "x" * 300000})
        assert response.status_code == 401
        assert len(response.content) <= 262144
        assert len(response.json()["error"]["request_id"]) <= 200


def test_chunked_body_bound_and_exact_byte_boundary(monkeypatch):
    from c2hunter_controller.ai_investigation_schema import InvestigationRequest

    app = create_app(settings(), MemoryRepository())
    monkeypatch.setattr(
        InvestigationRequest,
        "model_validate_json",
        lambda *_a, **_k: pytest.fail("decode overflow"),
    )
    with TestClient(app) as client:
        response = client.post(BASE, content=iter([b"[" * 8192, b"[" * 8193]), headers=HEADERS)
        assert response.status_code == 413
        # Exact ceiling is admitted to schema validation, not mistaken for overflow.
        response = client.post(BASE + "/source-preview", content=b" " * 16384, headers=HEADERS)
        assert response.status_code == 422


def test_pagination_uses_real_lookahead_and_complete_prefixes():
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    with structured_provider(adaptive) as (gateway, _):
        app = create_app(
            settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
        )
        with TestClient(app) as client:
            preview = client.post(
                BASE + "/source-preview", json={"target_ip": "2001:db8::1"}, headers=HEADERS
            ).json()
            expected = []
            for index in range(7):
                response = client.post(
                    BASE, headers=HEADERS, json=request_from(preview, str(index))
                )
                assert response.status_code == 202, response.text
                identifier = response.json()["id"]
                expected.append(identifier)
                assert (
                    client.post(BASE + "/" + identifier + "/cancel", headers=HEADERS).status_code
                    == 200
                )
            after = ""
            actual = []
            for _ in range(5):
                response = client.get(BASE, headers=HEADERS, params={"limit": 2, "after": after})
                assert response.status_code == 200, response.text
                page = response.json()
                assert set(page) == {"items", "next_cursor"}
                actual.extend(item["id"] for item in page["items"])
                if page["next_cursor"] is None:
                    break
                assert page["next_cursor"] == actual[-1]
                after = page["next_cursor"]
            assert actual == sorted(expected)
    repo.close()
