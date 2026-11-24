import importlib
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

PASSWORD = "Correct horse battery!"


def module():
    return importlib.import_module("c2hunter_controller.auth_store")


@pytest.fixture
def store(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return module().AuthStore(sqlite_path=private / "auth.sqlite3")


def test_explicit_initialization_private_modes_and_persistent_bootstrap(store):
    assert not store.ready()
    assert not store.sqlite_path.exists()
    with pytest.raises(module().AuthError, match="ACCOUNT_SETUP_REQUIRED"):
        store.bootstrap("Admin", PASSWORD)
    store.initialize()
    key = store.hmac_key()
    assert len(key) == 32
    user = store.bootstrap("Admin", PASSWORD)
    assert user.to_dict() == dict(
        id=user.id, username="admin", role="ADMIN", active=True, must_change_password=False
    )
    restarted = module().AuthStore(sqlite_path=store.sqlite_path)
    assert restarted.ready()
    assert restarted.hmac_key() == key
    with pytest.raises(module().AuthError, match="USER_EXISTS"):
        restarted.bootstrap("second", PASSWORD)
    with sqlite3.connect(store.sqlite_path) as db:
        assert db.execute("SELECT count(*) FROM auth_audit").fetchone()[0] == 2
        assert (
            db.execute("SELECT password_hash FROM auth_users")
            .fetchone()[0]
            .startswith("$argon2id$")
        )
    assert os.stat(store.sqlite_path).st_mode & 0o777 == 0o600


def test_initialization_rejects_insecure_directory_and_symlink(tmp_path):
    insecure = tmp_path / "bad"
    insecure.mkdir(mode=0o755)
    bad = module().AuthStore(sqlite_path=insecure / "db")
    with pytest.raises(module().AuthError):
        bad.initialize()
    assert not (insecure / "db").exists()
    secure = tmp_path / "secure"
    secure.mkdir(mode=0o700)
    (secure / "link").symlink_to(insecure / "db")
    with pytest.raises(module().AuthError):
        module().AuthStore(sqlite_path=secure / "link").initialize()


def test_concurrent_bootstrap_exactly_one_winner(store):
    store.initialize()

    def bootstrap(name):
        try:
            return store.bootstrap(name, PASSWORD).username
        except module().AuthError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(bootstrap, ["first", "second"]))
    assert results.count("USER_EXISTS") == 1


def test_login_rotation_digest_persistence_idle_and_absolute_expiry(store):
    store.initialize()
    user = store.bootstrap("Admin", PASSWORD)
    now = [100000.0]
    store.clock = lambda: now[0]
    first = store.login("ADMIN", PASSWORD, source_ip="127.0.0.1")
    assert first.user == user
    assert first.identity_scope == "user:" + user.id
    assert first.token != first.session_id
    assert store.authenticate(first.token).session_id == first.session_id
    second = store.login("admin", PASSWORD, prior_token=first.token)
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        store.authenticate(first.token)
    restarted = module().AuthStore(sqlite_path=store.sqlite_path, clock=store.clock)
    assert restarted.authenticate(second.token).user.id == user.id
    with sqlite3.connect(store.sqlite_path) as db:
        serialized = repr(db.execute("SELECT * FROM auth_sessions").fetchall())
    assert second.token not in serialized
    now[0] += 1800
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        restarted.authenticate(second.token)
    third = store.login("admin", PASSWORD)
    for _ in range(24):
        now[0] += 1799
        store.authenticate(third.token)
    now[0] += 24
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        store.authenticate(third.token)


def test_persistent_throttling_uniform_denial_and_audit_failure(store):
    store.initialize()
    store.bootstrap("admin", PASSWORD)
    for _ in range(10):
        with pytest.raises(module().AuthError, match="INVALID_CREDENTIALS"):
            store.login("unknown", PASSWORD, source_ip="127.0.0.1")
    restarted = module().AuthStore(sqlite_path=store.sqlite_path)
    with pytest.raises(module().AuthError, match="RATE_LIMIT_EXCEEDED"):
        restarted.login("admin", PASSWORD, source_ip="127.0.0.1")
    with sqlite3.connect(store.sqlite_path) as db:
        failures = db.execute(
            "SELECT actor_id,actor_name,auth_kind FROM auth_audit "
            "WHERE action='auth.login' AND outcome='failed'"
        ).fetchall()
        assert failures == [(None, None, "unauthenticated")] * 10
        db.execute(
            "CREATE TRIGGER deny_audit BEFORE INSERT ON auth_audit BEGIN "
            "SELECT RAISE(ABORT,'denied'); END"
        )
    with pytest.raises(module().AuthError, match="SECURITY_UNAVAILABLE"):
        restarted.login("other", PASSWORD)
    with sqlite3.connect(store.sqlite_path) as db:
        assert db.execute("SELECT count(*) FROM auth_sessions").fetchone()[0] == 0


@pytest.fixture
def admin(store):
    store.initialize()
    store.bootstrap("admin", PASSWORD)
    return store.login("admin", PASSWORD)


def test_account_mutations_forced_change_sessions_and_last_admin(store, admin):
    role = importlib.import_module("c2hunter_controller.security").Role
    created = store.create_user(admin.token, "Alice", PASSWORD, role.ANALYST)
    assert created.must_change_password
    alice = store.login("alice", PASSWORD)
    with pytest.raises(module().AuthError, match="PASSWORD_CHANGE_REQUIRED"):
        store.list_sessions(alice.token)
    store.change_password(alice.token, PASSWORD, PASSWORD + " new")
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        store.authenticate(alice.token)
    alice = store.login("alice", PASSWORD + " new")
    assert not alice.user.must_change_password
    assert store.list_sessions(alice.token)["total"] == 1
    assert store.list_sessions(alice.token)["items"][0]["current"] is True
    with pytest.raises(module().AuthError, match="INSUFFICIENT_ROLE"):
        store.list_users(alice.token)
    assert store.list_users(admin.token)["total"] == 2
    store.update_user(admin.token, created.id, role=role.VIEWER)
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        store.authenticate(alice.token)
    store.reset_password(admin.token, created.id, PASSWORD)
    assert store.login("alice", PASSWORD).user.must_change_password
    with pytest.raises(module().AuthError, match="LAST_ADMIN"):
        store.update_user(admin.token, admin.user.id, active=False)
    store.revoke_sessions(admin.token, session_id=admin.session_id)
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        store.authenticate(admin.token)


@pytest.mark.parametrize("change", ["reset", "disable", "role"])
@pytest.mark.parametrize("operation", ["login", "password"])
def test_paused_verification_generation_fence(store, admin, change, operation):
    import threading

    from c2hunter_controller.auth_passwords import Passwords
    from c2hunter_controller.security import Role

    user = store.create_user(admin.token, "alice", PASSWORD, Role.ANALYST)
    session = store.login("alice", PASSWORD)
    entered, release = threading.Event(), threading.Event()

    class Paused(Passwords):
        def verify(self, encoded, password):
            result = super().verify(encoded, password)
            entered.set()
            assert release.wait(10)
            return result

    other = module().AuthStore(sqlite_path=store.sqlite_path, passwords=Paused())

    def work():
        with pytest.raises(module().AuthError) as error:
            if operation == "login":
                other.login("alice", PASSWORD)
            else:
                other.change_password(session.token, PASSWORD, PASSWORD + " overwritten")
        return error.value.code

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(work)
        try:
            assert entered.wait(10)
            if change == "reset":
                store.reset_password(admin.token, user.id, PASSWORD + " reset")
            elif change == "disable":
                store.update_user(admin.token, user.id, active=False)
            else:
                store.update_user(admin.token, user.id, role=Role.VIEWER)
        finally:
            release.set()
        assert future.result(timeout=10) == (
            "INVALID_CREDENTIALS" if operation == "login" else "AUTH_REQUIRED"
        )
    with sqlite3.connect(store.sqlite_path) as db:
        row = db.execute("SELECT password_hash FROM auth_users WHERE id=?", (user.id,)).fetchone()
    assert not Passwords().verify(row[0], PASSWORD + " overwritten")


def test_mutation_audit_rollback_and_admin_recheck(store, admin):
    from c2hunter_controller.security import Role

    with sqlite3.connect(store.sqlite_path) as db:
        db.execute(
            "CREATE TRIGGER deny_audit BEFORE INSERT ON auth_audit BEGIN "
            "SELECT RAISE(ABORT,'denied'); END"
        )
    with pytest.raises(module().AuthError, match="SECURITY_UNAVAILABLE"):
        store.create_user(admin.token, "alice", PASSWORD, Role.VIEWER)
    assert store.list_users(admin.token)["total"] == 1
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute("DROP TRIGGER deny_audit")
    store.logout(admin.token)
    with pytest.raises(module().AuthError, match="AUTH_REQUIRED"):
        store.create_user(admin.token, "alice", PASSWORD, Role.VIEWER)


def test_concurrent_last_admin_updates(store, admin):
    from c2hunter_controller.security import Role

    second = store.create_user(admin.token, "second", PASSWORD, Role.ADMIN)
    session = store.login("second", PASSWORD)
    store.change_password(session.token, PASSWORD, PASSWORD + " changed")
    session = store.login("second", PASSWORD + " changed")

    def disable(pair):
        token, user_id = pair
        try:
            store.update_user(token, user_id, active=False)
            return "ok"
        except module().AuthError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(disable, [(admin.token, admin.user.id), (session.token, second.id)])
        )
    assert sorted(outcomes) == ["LAST_ADMIN", "ok"]
