from pathlib import Path

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.config import Settings

ORIGIN = "https://testserver"
PASSWORD = "correct horse battery staple"


def configured_app(tmp_path: Path):
    store = AuthStore(sqlite_path=tmp_path / "security" / "auth.sqlite3")
    store.initialize()
    store.bootstrap("admin", PASSWORD)
    settings = Settings(
        environment="test",
        account_auth_enabled=True,
        api_auth_required=True,
        auth_public_origin=ORIGIN,
    )
    return create_app(settings, auth_store=store), store


def login(client: TestClient, username="admin", password=PASSWORD):
    csrf = client.get("/api/v1/auth/csrf")
    assert csrf.status_code == 200, csrf.text
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
        headers={"origin": ORIGIN, "x-csrf-token": csrf.json()["csrf_token"]},
    )
    assert response.status_code == 200, response.text
    client.headers.update({"origin": ORIGIN, "x-csrf-token": response.json()["csrf_token"]})
    return response


def test_real_login_me_cookie_and_protected_read(tmp_path: Path):
    app, store = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        assert client.get("/api/v1/analysis-jobs").status_code == 401
        response = login(client)
        assert response.json()["user"]["role"] == "ADMIN"
        assert "token" not in response.json()
        cookie = response.headers["set-cookie"]
        for attribute in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
            assert attribute in cookie
        me = client.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert me.json()["auth_kind"] == "session"
        assert me.json()["identity_scope"] == "user:" + me.json()["user"]["id"]
        assert me.json()["audit_available"] is True
        assert client.get("/api/v1/analysis-jobs").status_code == 200
        assert me.headers["cache-control"] == "no-store"
        assert me.headers["x-frame-options"] == "DENY"
    assert app.state.auth_store is store


def test_admin_and_self_service_lifecycle(tmp_path: Path):
    app, _ = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as admin, TestClient(app, base_url=ORIGIN) as viewer:
        login(admin)
        created = admin.post(
            "/api/v1/admin/users",
            json={"username": "alice", "password": PASSWORD, "role": "VIEWER"},
        )
        assert created.status_code == 201, created.text
        user_id = created.json()["id"]
        assert created.json()["must_change_password"] is True
        login(viewer, "alice")
        assert viewer.get("/api/v1/auth/me").status_code == 200
        for path in ("/api/v1/analysis-jobs", "/api/v1/auth/sessions", "/api/v1/auth/activity"):
            assert viewer.get(path).json()["error"]["code"] == "PASSWORD_CHANGE_REQUIRED"
        changed = viewer.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": "another strong password"},
        )
        assert changed.status_code == 204, changed.text
        assert viewer.get("/api/v1/auth/me").status_code == 401
        login(viewer, "alice", "another strong password")
        assert viewer.get("/api/v1/auth/sessions").json()["total"] == 1
        assert viewer.get("/api/v1/admin/users").status_code == 403
        denied = viewer.post("/api/v1/analysis-jobs", json={})
        assert denied.status_code == 403
        own = viewer.get("/api/v1/auth/activity").json()
        assert all(item["actor_id"] == user_id for item in own["items"])
        assert admin.get("/api/v1/admin/users").json()["total"] == 2
        audit = admin.get("/api/v1/admin/audit").json()
        assert audit["total"] > own["total"]
        export = admin.post("/api/v1/admin/audit/export", json={"limit": 2})
        assert export.status_code == 200, export.text
        assert len(export.text.splitlines()) == 2
        assert export.headers["x-next-offset"] == "2"
        updated = admin.patch(f"/api/v1/admin/users/{user_id}", json={"active": False})
        assert updated.status_code == 200, updated.text
        assert viewer.get("/api/v1/auth/me").status_code == 401
        assert (
            admin.post(
                f"/api/v1/admin/users/{user_id}/reset-password", json={"password": PASSWORD}
            ).status_code
            == 204
        )
        assert (
            admin.post(f"/api/v1/admin/users/{user_id}/revoke-sessions", json={}).status_code == 204
        )
        assert admin.post("/api/v1/auth/logout", json={}).status_code == 204
        assert admin.get("/api/v1/auth/me").status_code == 401
