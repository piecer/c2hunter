import importlib
import os
import sqlite3

import pytest
import test_account_auth_store as support

PASSWORD = support.PASSWORD
module = support.module
store = support.store
admin = support.admin


@pytest.mark.parametrize(
    "fault", ["key", "sessions", "throttle", "links", "audit-column", "user-column"]
)
def test_readiness_rejects_incomplete_schema_without_repair(store, fault):
    store.initialize()
    with sqlite3.connect(store.sqlite_path) as db:
        statements = {
            "key": "DELETE FROM auth_meta WHERE key='hmac_key'",
            "sessions": "DROP TABLE auth_sessions",
            "throttle": "DROP TABLE auth_throttle",
            "links": "DROP TABLE auth_job_links",
            "audit-column": "ALTER TABLE auth_audit RENAME COLUMN details TO missing",
            "user-column": "ALTER TABLE auth_users RENAME COLUMN generation TO missing",
        }
        db.execute(statements[fault])
    assert not store.ready()
    with pytest.raises(module().AuthError, match="ACCOUNT_SETUP_REQUIRED"):
        store.bootstrap("admin", PASSWORD)


def test_schema_version_is_independent_and_repeated_init_preserves_key(store):
    store.initialize()
    key = store.hmac_key()
    store.initialize()
    assert store.hmac_key() == key
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute("UPDATE auth_meta SET value='999' WHERE key='version'")
    assert not store.ready()
    with pytest.raises(module().AuthError, match="ACCOUNT_SETUP_REQUIRED"):
        store.initialize()


def test_sqlite_rejects_readonly_hardlink_symlink_and_foreign_owner(store, monkeypatch):
    store.initialize()
    store.sqlite_path.chmod(0o400)
    assert not store.ready()
    store.sqlite_path.chmod(0o600)
    hardlink = store.sqlite_path.with_name("hardlink")
    os.link(store.sqlite_path, hardlink)
    assert not store.ready()
    hardlink.unlink()
    schema = importlib.import_module("c2hunter_controller.auth_schema")
    real_uid = os.getuid()
    monkeypatch.setattr(schema.os, "getuid", lambda: real_uid + 1)
    assert not store.ready()


def test_postgres_adapter_connection_failure_never_falls_back(tmp_path, monkeypatch):
    schema = importlib.import_module("c2hunter_controller.auth_schema")
    calls = []

    def unavailable(dsn, **kwargs):
        calls.append((dsn, kwargs))
        raise schema.psycopg.OperationalError("sensitive dsn detail")

    monkeypatch.setattr(schema.psycopg, "connect", unavailable)
    pg = module().AuthStore(database_url="postgresql://unavailable/auth")
    assert not pg.ready()
    with pytest.raises(module().AuthError, match="SECURITY_UNAVAILABLE") as error:
        pg.initialize()
    assert "sensitive" not in str(error.value)
    assert len(calls) == 2
    assert calls[0][1]["connect_timeout"] == 5
    assert pg.sqlite_path is None
    with pytest.raises(ValueError):
        module().AuthStore(database_url="memory://")
    with pytest.raises(ValueError):
        module().AuthStore(database_url="postgresql://x", sqlite_path=tmp_path / "db")
    assert list(tmp_path.iterdir()) == []


def test_private_sqlite_sidecar_symlink_refused_before_connection(store, tmp_path):
    store.initialize()
    outside = tmp_path / "outside"
    outside.write_text("untouched")
    store.sqlite_path.with_name(store.sqlite_path.name + "-journal").symlink_to(outside)
    assert not store.ready()
    assert outside.read_text() == "untouched"


@pytest.mark.parametrize("value", [" " * 64, "z" * 64, "00" * 31, "00" * 33])
def test_readiness_rejects_malformed_shared_key(store, value):
    store.initialize()
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute("UPDATE auth_meta SET value=? WHERE key='hmac_key'", (value,))
    assert not store.ready()
    with pytest.raises(module().AuthError, match="ACCOUNT_SETUP_REQUIRED"):
        store.hmac_key()
