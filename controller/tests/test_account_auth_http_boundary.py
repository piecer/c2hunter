import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_account_auth_http import ORIGIN, PASSWORD, configured_app, login

from c2hunter_controller.app import create_app
from c2hunter_controller.auth_models import AuthError
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.config import Settings


def test_missing_store_readiness_and_no_creation(tmp_path: Path):
    path = tmp_path / "absent" / "auth.sqlite3"
    app = create_app(
        Settings(
            environment="test",
            api_auth_required=True,
            account_auth_enabled=True,
            auth_public_origin=ORIGIN,
            auth_database_path=str(path),
        )
    )
    with TestClient(app, base_url=ORIGIN) as client:
        for target in ("/api/v1/auth/csrf", "/api/v1/analysis-jobs", "/api/v1/ready"):
            response = client.get(target)
            assert response.status_code == 503, (target, response.text)
        assert client.get("/api/v1/health").status_code == 200
    assert not path.exists()


def test_explicit_legacy_bootstrap_and_missing_origin(tmp_path: Path):
    legacy = create_app(
        Settings(
            environment="test",
            account_auth_enabled=False,
            api_auth_required=True,
            dev_login_enabled=True,
        )
    )
    with TestClient(legacy, base_url=ORIGIN) as client:
        assert client.get("/api/v1/auth/csrf").json() == {
            "csrf_token": None,
            "account_login_enabled": False,
            "setup_required": False,
            "dev_login_enabled": True,
        }
        assert client.post("/api/v1/auth/login", json={}).status_code == 404
    app = create_app(
        Settings(
            environment="test",
            account_auth_enabled=True,
            api_auth_required=True,
            auth_public_origin="",
            auth_database_path=str(tmp_path / "unused" / "auth.sqlite3"),
        )
    )
    with TestClient(app, base_url=ORIGIN) as client:
        assert client.get("/api/v1/auth/csrf").json()["error"]["code"] == "ACCOUNT_SETUP_REQUIRED"
        assert client.get("/api/v1/health").status_code == 200


def test_closed_policy_bearer_and_ambiguous_credentials(tmp_path: Path):
    store = AuthStore(sqlite_path=tmp_path / "security" / "auth.sqlite3")
    store.initialize()
    store.bootstrap("admin", PASSWORD)
    app = create_app(
        Settings(
            environment="test",
            api_auth_required=True,
            account_auth_enabled=True,
            auth_public_origin=ORIGIN,
            admin_token_sha256=hashlib.sha256(b"service").hexdigest(),
        ),
        auth_store=store,
    )
    effects = []

    @app.get("/api/v1/unreviewed")
    def unreviewed():
        effects.append(True)
        return {}

    with TestClient(app, base_url=ORIGIN) as client:
        client.headers["authorization"] = "Bearer service"
        assert client.get("/api/v1/unreviewed").status_code == 403
        assert not effects
        assert client.get("/api/v1/admin/users").status_code == 403
        me = client.get("/api/v1/auth/me")
        assert me.json()["auth_kind"] == "bearer"
        assert me.json()["principal"]["subject"] == "static-admin"
        assert me.json()["user"] is None
        del client.headers["authorization"]
        login(client)
        assert (
            client.get("/api/v1/auth/me", headers={"authorization": "Bearer invalid"}).status_code
            == 401
        )
        token = client.cookies.get("c2hunter_session")
        assert (
            client.get(
                "/api/v1/auth/me",
                headers={"cookie": f"c2hunter_session={token}; c2hunter_session={token}"},
            ).status_code
            == 401
        )
        assert (
            client.get(
                "/api/v1/auth/me",
                headers=[("authorization", "Bearer service"), ("authorization", "Bearer invalid")],
            ).status_code
            == 401
        )


@pytest.mark.parametrize(
    "headers,code",
    [
        ({"origin": "https://attacker.example"}, "ORIGIN_INVALID"),
        ({"host": "attacker.example"}, "ORIGIN_INVALID"),
        ({"x-csrf-token": "invalid"}, "CSRF_INVALID"),
    ],
)
def test_browser_denials(tmp_path: Path, headers, code):
    app, _ = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        response = client.post(
            "/api/v1/admin/users",
            headers=headers,
            json={"username": "never", "password": PASSWORD, "role": "ADMIN"},
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == code
        assert client.get("/api/v1/admin/users").json()["total"] == 1


def test_body_bounds_and_safe_validation(tmp_path: Path):
    app, _ = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        response = client.post("/api/v1/admin/users", content=b"{" + b"x" * 16384)
        assert response.status_code == 413
        for payload in (
            {"username": "new", "password": PASSWORD, "role": "admin"},
            {"username": "new", "password": PASSWORD, "role": 3},
            {"username": "new", "password": PASSWORD, "role": "ADMIN", "actor": "forged"},
        ):
            response = client.post("/api/v1/admin/users", json=payload)
            assert response.status_code == 422
            assert PASSWORD not in response.text
        assert client.get("/api/v1/admin/audit?since=NaN").status_code == 422
        assert client.get("/api/v1/admin/users?limit=201").status_code == 422
        assert client.get("/api/v1/admin/users?limit=2&limit=3").status_code == 422


def test_audit_outage_prevents_work_and_terminal_unknown(tmp_path: Path, monkeypatch):
    app, store = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        original = store.record_event

        def unavailable(*args, **kwargs):
            raise AuthError("SECURITY_UNAVAILABLE")

        monkeypatch.setattr(store, "record_event", unavailable)
        response = client.post("/api/v1/allowlist", json={"type": "IP", "value": "1.1.1.1"})
        assert response.status_code == 503
        assert client.get("/api/v1/allowlist").json()["items"] == []
        assert client.get("/api/v1/unregistered").status_code == 503
        monkeypatch.setattr(store, "record_event", original)


def test_login_always_requires_prelogin_proof(tmp_path: Path):
    store = AuthStore(sqlite_path=tmp_path / "security" / "auth.sqlite3")
    store.initialize()
    store.bootstrap("admin", PASSWORD)
    app = create_app(
        Settings(
            environment="test",
            api_auth_required=True,
            account_auth_enabled=True,
            auth_public_origin=ORIGIN,
            admin_token_sha256=hashlib.sha256(b"service").hexdigest(),
        ),
        auth_store=store,
    )
    with TestClient(app, base_url=ORIGIN) as client:
        response = client.post(
            "/api/v1/auth/login",
            headers={"authorization": "Bearer service"},
            json={"username": "admin", "password": PASSWORD},
        )
        assert response.status_code in {401, 403}
        assert "c2hunter_session" not in client.cookies


def test_rotation_and_expired_cookie_can_recover(tmp_path: Path):
    app, store = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        first = login(client)
        old = client.cookies.get("c2hunter_session")
        second = login(client)
        assert first.json()["session_id"] != second.json()["session_id"]
        with pytest.raises(AuthError):
            store.authenticate(old)
        assert client.post("/api/v1/auth/sessions/revoke", json={}).status_code == 204
        client.cookies.set("c2hunter_session", old, domain="testserver.local", path="/")
        login(client)


@pytest.mark.parametrize("role_name", ["VIEWER", "ANALYST"])
def test_all_higher_role_routes_deny_before_handlers(tmp_path: Path, role_name):
    import re

    from c2hunter_controller.auth_policy import RULES
    from c2hunter_controller.security import Role

    app, store = configured_app(tmp_path)
    admin = store.login("admin", PASSWORD)
    role = Role[role_name]
    store.create_user(admin.token, "restricted", PASSWORD, role)
    temporary = store.login("restricted", PASSWORD)
    store.change_password(temporary.token, PASSWORD, "replacement secret password")
    with TestClient(app, base_url=ORIGIN) as client:
        login(client, "restricted", "replacement secret password")
        checked = 0
        for rule in RULES:
            if rule.minimum_role is None or rule.minimum_role <= role:
                continue
            path = re.sub(r"\{[^}]+\}", "a" * 32, rule.template)
            response = client.request(rule.method, path, json={})
            assert response.status_code == 403, (rule.method, path, response.text)
            assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"
            checked += 1
        assert checked > 0
        assert app.state.repository.list_jobs() == []


def test_transaction_revalidation_denial_is_audited(tmp_path: Path, monkeypatch):
    app, store = configured_app(tmp_path)
    original = store.update_user

    def revoke_before_update(token, user_id, **kwargs):
        store.revoke_sessions(token)
        return original(token, user_id, **kwargs)

    with TestClient(app, base_url=ORIGIN) as client:
        me = login(client).json()
        monkeypatch.setattr(store, "update_user", revoke_before_update)
        response = client.patch(f"/api/v1/admin/users/{me['user']['id']}", json={"active": True})
        assert response.status_code == 401
        client.cookies.clear()
        login(client)
        events = client.get("/api/v1/admin/audit?action=access.denied").json()["items"]
        assert any(event["target"] == "/api/v1/admin/users/{user_id}" for event in events)


def test_external_get_audit_precedes_fake_provider(tmp_path: Path, monkeypatch):
    _, store = configured_app(tmp_path)
    app = create_app(
        Settings(
            environment="test",
            api_auth_required=True,
            account_auth_enabled=True,
            auth_public_origin=ORIGIN,
            ai_analysis_enabled=True,
        ),
        auth_store=store,
    )
    calls = []
    gateway = app.state.ai_analysis_service.gateway
    monkeypatch.setattr(
        gateway, "interpret_network_cancellable", lambda *a, **kw: None, raising=False
    )
    monkeypatch.setattr(gateway, "ready", lambda: calls.append("ready") or True)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        original = store.record_event

        def unavailable(*args, **kwargs):
            raise AuthError("SECURITY_UNAVAILABLE")

        monkeypatch.setattr(store, "record_event", unavailable)
        response = client.get("/api/v1/ai-capabilities")
        assert response.status_code == 503
        assert calls == []
        monkeypatch.setattr(store, "record_event", original)
        assert client.get("/api/v1/ai-capabilities").status_code == 200
        assert calls == ["ready"]


def test_nonascii_prelogin_proof_is_denied(tmp_path: Path):
    app, _ = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        client.get("/api/v1/auth/csrf")
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": PASSWORD},
            headers=[(b"origin", ORIGIN.encode()), (b"x-csrf-token", b"\xff")],
        )
        assert response.status_code == 403


def test_hash_admission_limit_is_durable(tmp_path: Path):
    from c2hunter_controller.auth_http_routes import _HASH_ADMISSION

    app, _ = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as admin, TestClient(app, base_url=ORIGIN) as anon:
        login(admin)
        csrf = anon.get("/api/v1/auth/csrf").json()["csrf_token"]
        assert _HASH_ADMISSION.acquire(blocking=False)
        assert _HASH_ADMISSION.acquire(blocking=False)
        try:
            response = anon.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": PASSWORD},
                headers={"origin": ORIGIN, "x-csrf-token": csrf},
            )
            assert response.status_code == 429
        finally:
            _HASH_ADMISSION.release()
            _HASH_ADMISSION.release()
        events = admin.get("/api/v1/admin/audit?action=auth.login_limited").json()["items"]
        assert len(events) == 1


def test_expensive_admission_before_thread_queue(tmp_path: Path):
    from c2hunter_controller.auth_http_routes import _HASH_ADMISSION

    app, _ = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        csrf = client.get("/api/v1/auth/csrf").json()["csrf_token"]
        assert _HASH_ADMISSION.acquire(blocking=False)
        assert _HASH_ADMISSION.acquire(blocking=False)
        try:
            response = client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": PASSWORD},
                headers={"origin": ORIGIN, "x-csrf-token": csrf},
            )
            assert response.status_code == 429
        finally:
            _HASH_ADMISSION.release()
            _HASH_ADMISSION.release()
