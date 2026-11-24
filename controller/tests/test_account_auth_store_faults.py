import json
import secrets
import sqlite3
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import test_account_auth_store as support

from c2hunter_controller.auth_passwords import Passwords
from c2hunter_controller.security import Role

PASSWORD = support.PASSWORD
module = support.module
store = support.store
admin = support.admin


def test_session_cross_process_readback_and_revoke(store, admin):
    code = """import json,sys
from c2hunter_controller.auth_store import AuthStore
p=json.loads(sys.stdin.read()); s=AuthStore(sqlite_path=p['path'])
a=s.authenticate(p['token']); print(json.dumps(a.user.to_dict()))
s.logout(p['token'])
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        input=json.dumps({"path": str(store.sqlite_path), "token": admin.token}),
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
    )
    assert json.loads(result.stdout) == admin.user.to_dict()
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        store.authenticate(admin.token)


@pytest.mark.parametrize("operation", ["create", "reset"])
def test_admin_session_rechecked_after_hash(store, admin, operation):
    entered, release = threading.Event(), threading.Event()

    class Paused(Passwords):
        def hash(self, password):
            hashed = super().hash(password)
            entered.set()
            assert release.wait(10)
            return hashed

    other = module().AuthStore(sqlite_path=store.sqlite_path, passwords=Paused())

    def act():
        with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
            if operation == "create":
                other.create_user(admin.token, "alice", PASSWORD, Role.ADMIN)
            else:
                other.reset_password(admin.token, admin.user.id, PASSWORD + " reset")

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(act)
        try:
            assert entered.wait(10)
            store.logout(admin.token)
        finally:
            release.set()
        future.result(timeout=10)
    fresh = store.login("admin", PASSWORD)
    assert store.list_users(fresh.token)["total"] == 1


def test_throttle_capacity_and_exact_rolling_expiry(store, admin):
    now = [100000.0]
    store.clock = lambda: now[0]
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute("DELETE FROM auth_throttle")
        db.executemany(
            "INSERT INTO auth_throttle VALUES (?,?,?)",
            [(str(i), json.dumps([[now[0], "attempt"]]), now[0]) for i in range(10000)],
        )
    with pytest.raises(module().AuthError, match="RATE_LIMIT_EXCEEDED"):
        store.login("unknown", PASSWORD)
    with sqlite3.connect(store.sqlite_path) as db:
        assert db.execute("SELECT count(*) FROM auth_throttle").fetchone()[0] == 10000
    now[0] += 900
    assert store.login("admin", PASSWORD)
    for _ in range(10):
        with pytest.raises(module().AuthError, match="INVALID_CREDENTIALS"):
            store.login("bad", PASSWORD)
    with pytest.raises(module().AuthError, match="RATE_LIMIT_EXCEEDED"):
        store.login("bad", PASSWORD)
    now[0] += 900
    with pytest.raises(module().AuthError, match="INVALID_CREDENTIALS"):
        store.login("bad", PASSWORD)


def test_password_busy_login_and_malformed_inputs_are_safe(store, admin):
    with store.passwords.slot(), store.passwords.slot():
        with pytest.raises(module().AuthError, match="RATE_LIMIT_EXCEEDED"):
            store.login("admin", PASSWORD)
    for username, password in [
        ("?raw secret", PASSWORD),
        ("admin", "short"),
        ("admin", "\ud800" * 12),
    ]:
        with pytest.raises(module().AuthError, match="INVALID_CREDENTIALS"):
            store.login(username, password)
    for token in ["", "x" * 500, "\ud800"]:
        with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
            store.authenticate(token)
    with pytest.raises(module().AuthError, match="INVALID_PASSWORD"):
        store.bootstrap("second", "short")


def test_revoke_scope_all_noop_update_and_ordering(store, admin):
    user = store.create_user(admin.token, "z", PASSWORD, Role.VIEWER)
    first = store.login("z", PASSWORD)
    store.change_password(first.token, PASSWORD, PASSWORD + " changed")
    first = store.login("z", PASSWORD + " changed")
    second = store.login("z", PASSWORD + " changed")
    assert not store.revoke_sessions(first.token, session_id=admin.session_id)
    assert store.authenticate(admin.token)
    assert store.list_sessions(first.token, limit=1)["total"] == 2
    assert store.list_sessions(first.token, offset=1)["items"][0]["id"] == first.session_id
    store.revoke_user_sessions(admin.token, user.id)
    with pytest.raises(module().AuthError):
        store.authenticate(second.token)
    first = store.login("z", PASSWORD + " changed")
    store.update_user(admin.token, user.id, active=True)
    with pytest.raises(module().AuthError):
        store.authenticate(first.token)
    assert [u["username"] for u in store.list_users(admin.token)["items"]] == ["admin", "z"]
    assert store.revoke_sessions(admin.token)
    with pytest.raises(module().AuthError):
        store.authenticate(admin.token)


def test_audit_pagination_stable_ties_pending_cursor_and_invalid_metadata(store, admin):
    from c2hunter_controller.auth_models import Actor

    store.clock = lambda: 100000.0
    # Use a fresh session at the injected timestamp, not an expired existing one.
    current = store.login("admin", PASSWORD)
    ids = []
    for _ in range(3):
        ids.append(store.record_event(current.actor, "http.operation", "/jobs", "started"))
    page = store.list_audit(current.token, action="http.operation", limit=2)
    assert [i["id"] for i in page["items"]] == sorted(ids, reverse=True)[:2]
    assert page["total"] == 3
    for bad in [
        dict(request_id="raw secret"),
        dict(source_ip="bad"),
        dict(status=99),
        dict(job_id="secret"),
        dict(details={"reason": "arbitrary"}),
    ]:
        with pytest.raises(module().AuthError, match="INVALID_AUDIT"):
            store.record_event(current.actor, "http.operation", "/jobs", "started", **bad)
    with pytest.raises(module().AuthError, match="INVALID_AUDIT"):
        store.record_event(
            Actor("secret", None, None, "session"), "http.operation", "/jobs", "started"
        )
    for _ in range(3):
        store.reserve_job(
            "analysis", str(uuid.uuid4()), current.actor, str(uuid.uuid4()), secrets.token_hex(16)
        )
    first = store.pending_job_links(2)
    second = store.pending_job_links(2, first["next_cursor"])
    assert len(first["items"]) == 2 and len(second["items"]) == 1
    assert second["next_cursor"] is None
    assert not {item.id for item in first["items"]} & {item.id for item in second["items"]}
    with pytest.raises(module().AuthError):
        store.pending_job_links(1001)
    with pytest.raises(module().AuthError):
        store.pending_job_links(cursor="bad")


@pytest.mark.parametrize("operation", ["update", "reset", "change", "revoke", "logout", "local"])
def test_atomic_account_mutation_rolls_back_on_audit_fault(store, admin, operation):
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute(
            "CREATE TRIGGER deny_audit BEFORE INSERT ON auth_audit BEGIN "
            "SELECT RAISE(ABORT,'denied'); END"
        )
    with pytest.raises(module().AuthError, match="SECURITY_UNAVAILABLE"):
        if operation == "update":
            store.update_user(admin.token, admin.user.id, active=True)
        elif operation == "reset":
            store.reset_password(admin.token, admin.user.id, PASSWORD + " reset")
        elif operation == "change":
            store.change_password(admin.token, PASSWORD, PASSWORD + " change")
        elif operation == "revoke":
            store.revoke_sessions(admin.token)
        elif operation == "logout":
            store.logout(admin.token)
        else:
            store.local_reset_password("admin", PASSWORD + " local")
    assert store.authenticate(admin.token).user == admin.user
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute("DROP TRIGGER deny_audit")
    assert not store.login("admin", PASSWORD).user.must_change_password


def test_invalid_mutations_durable_denial_and_validation_bounds(store, admin):
    with pytest.raises(module().AuthError, match="INVALID_CREDENTIALS"):
        store.change_password(admin.token, PASSWORD + " wrong", PASSWORD + " new")
    with pytest.raises(module().AuthError, match="INVALID_CREDENTIALS"):
        store.change_password(admin.token, "short", PASSWORD + " new")
    with store.passwords.slot(), store.passwords.slot():
        with pytest.raises(module().AuthError, match="RATE_LIMIT_EXCEEDED"):
            store.change_password(admin.token, PASSWORD, PASSWORD + " new")
        with pytest.raises(module().AuthError, match="RATE_LIMIT_EXCEEDED"):
            store.create_user(admin.token, "new", PASSWORD, Role.VIEWER)
    with pytest.raises(module().AuthError, match="USER_EXISTS"):
        store.create_user(admin.token, "ADMIN", PASSWORD, Role.ADMIN)
    with pytest.raises(module().AuthError, match="INVALID_ROLE"):
        store.create_user(admin.token, "new", PASSWORD, "ROOT")
    for kwargs in [{}, {"active": 1}, {"role": "ADMIN"}]:
        with pytest.raises(module().AuthError, match="INVALID_UPDATE"):
            store.update_user(admin.token, admin.user.id, **kwargs)
    with pytest.raises(module().AuthError, match="USER_NOT_FOUND"):
        store.update_user(admin.token, "f" * 32, active=True)
    with pytest.raises(module().AuthError, match="USER_NOT_FOUND"):
        store.local_reset_password("missing", PASSWORD)
    for kwargs in [dict(limit=201), dict(offset=10000001), dict(limit=True)]:
        with pytest.raises(module().AuthError, match="INVALID_PAGINATION"):
            store.list_users(admin.token, **kwargs)
    assert store.authenticate(admin.token)
    assert (
        len(
            store.list_audit(admin.token, action="account.password_change", outcome="denied")[
                "items"
            ]
        )
        == 2
    )
