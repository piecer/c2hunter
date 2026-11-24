"""Readiness regressions; PG cases require an explicitly owned disposable fixture."""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from c2hunter_controller.auth_models import AuthError
from c2hunter_controller.auth_schema import SQL
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.security import Role

# Independently derived from runtime DML, not the readiness implementation.
WRITES = {
    "auth_users": ("INSERT", "UPDATE"),
    "auth_sessions": ("INSERT", "UPDATE", "DELETE"),
    "auth_audit": ("INSERT",),
    "auth_throttle": ("INSERT", "UPDATE", "DELETE"),
    "auth_job_links": ("INSERT", "UPDATE"),
}
COLUMNS = {
    ("auth_users", "INSERT"): (
        "id",
        "username",
        "role",
        "active",
        "must_change_password",
        "password_hash",
        "generation",
    ),
    ("auth_users", "UPDATE"): (
        "role",
        "active",
        "must_change_password",
        "password_hash",
        "generation",
    ),
    ("auth_sessions", "INSERT"): (
        "id",
        "digest",
        "user_id",
        "generation",
        "created_at",
        "last_seen_at",
        "expires_at",
    ),
    ("auth_sessions", "UPDATE"): ("last_seen_at",),
    ("auth_audit", "INSERT"): (
        "id",
        "timestamp",
        "actor_id",
        "actor_name",
        "actor_role",
        "auth_kind",
        "action",
        "target",
        "outcome",
        "request_id",
        "source_ip",
        "status",
        "job_id",
        "details",
    ),
    ("auth_throttle", "INSERT"): ("key", "entries", "updated_at"),
    ("auth_throttle", "UPDATE"): ("entries", "updated_at"),
    ("auth_job_links", "INSERT"): (
        "id",
        "family",
        "resource_id",
        "actor_id",
        "actor_name",
        "actor_role",
        "auth_kind",
        "request_id",
        "intent_id",
    ),
    ("auth_job_links", "UPDATE"): ("terminal_status", "event_id"),
}


@dataclass
class OwnedPostgres:
    dsn: str
    role: str
    extra_roles: list[str] = field(default_factory=list)

    def execute(self, statement: sql.SQL | sql.Composed | str) -> None:
        with psycopg.connect(self.dsn) as connection:
            connection.execute(statement)

    def role_dsn(self, options: str = "") -> str:
        parts = conninfo_to_dict(self.dsn)
        host = parts["host"]
        assert isinstance(host, str)
        return (
            f"postgresql://{self.role}@/{parts['dbname']}?host={quote(host, safe='')}"
            f"&options={quote(options, safe='')}"
        )

    def grant_runtime(self, *, columns: bool = False, grantee: str | None = None) -> None:
        recipient = sql.Identifier(grantee or self.role)
        self.execute(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(recipient))
        for table, privileges in WRITES.items():
            for privilege in privileges:
                rights: sql.Composable = sql.SQL(privilege)
                if columns and privilege != "DELETE":
                    rights += sql.SQL(" ({})").format(
                        sql.SQL(",").join(map(sql.Identifier, COLUMNS[table, privilege]))
                    )
                self.execute(
                    sql.SQL("GRANT {} ON {} TO {}").format(rights, sql.Identifier(table), recipient)
                )


@pytest.fixture
def pg() -> Iterator[OwnedPostgres]:
    base = os.environ.get("C2HUNTER_READINESS_TEST_DSN")
    if not base:
        pytest.skip("requires explicitly owned disposable PostgreSQL fixture")
    parts = conninfo_to_dict(base)
    # Never silently fall back to a deployment database or network endpoint.
    host = parts["host"]
    assert isinstance(host, str) and host.startswith("/") and parts["dbname"] == "postgres"
    name = "readiness_" + secrets.token_hex(12)
    role = "readiness_role_" + secrets.token_hex(12)
    with psycopg.connect(base, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    owned: OwnedPostgres | None = None
    try:
        with psycopg.connect(base, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
        dsn = f"postgresql://{parts['user']}@/{name}?host={quote(host, safe='')}"
        owned = OwnedPostgres(dsn, role)
        AuthStore(database_url=dsn).initialize()
        yield owned
    finally:
        with psycopg.connect(base, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
            connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
            for extra in owned.extra_roles if owned is not None else []:
                connection.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(extra)))


@pytest.mark.parametrize("source", ["dsn", "role"])
def test_readonly_postgres_must_not_report_ready(pg: OwnedPostgres, source: str) -> None:
    store = AuthStore(database_url=pg.dsn)
    password = "Generated readiness password " + secrets.token_hex(16)
    store.bootstrap("admin", password)
    login = store.login("admin", password)
    assert store.ready() is True
    if source == "dsn":
        readonly_dsn = pg.dsn + "&options=" + quote("-c default_transaction_read_only=on", safe="")
    else:
        pg.grant_runtime()
        pg.execute(
            sql.SQL("ALTER ROLE {} SET default_transaction_read_only=on").format(
                sql.Identifier(pg.role)
            )
        )
        readonly_dsn = pg.role_dsn()
    with psycopg.connect(readonly_dsn) as connection:
        assert connection.execute("SHOW transaction_read_only").fetchone() == ("on",)
    readonly = AuthStore(database_url=readonly_dsn)
    ready = readonly.ready()
    with pytest.raises(AuthError) as failure:
        readonly.authenticate(login.token)
    assert (failure.value.code, failure.value.status) == ("SECURITY_UNAVAILABLE", 503)
    assert ready is False
    assert store.ready() is True
    assert store.authenticate(login.token).user.id == login.user.id


def test_sqlite_readiness_keeps_explicit_initialization(tmp_path: Path) -> None:
    private = tmp_path / "auth"
    private.mkdir(mode=0o700)
    store = AuthStore(sqlite_path=private / "auth.sqlite3")
    assert store.ready() is False
    assert store.sqlite_path is not None and not store.sqlite_path.exists()
    store.initialize()
    assert store.ready() is True
    with store.db.transaction() as connection:
        before = list(connection.execute("SELECT * FROM auth_audit"))
    assert store.ready() is True
    with store.db.transaction() as connection:
        assert list(connection.execute("SELECT * FROM auth_audit")) == before


@pytest.mark.parametrize(
    ("table", "privilege"),
    [(table, privilege) for table, privileges in WRITES.items() for privilege in privileges],
)
def test_each_required_write_privilege_is_required(
    pg: OwnedPostgres, table: str, privilege: str
) -> None:
    pg.grant_runtime()
    store = AuthStore(database_url=pg.role_dsn())
    assert store.ready() is True
    pg.execute(
        sql.SQL("REVOKE {} ON {} FROM {}").format(
            sql.SQL(privilege), sql.Identifier(table), sql.Identifier(pg.role)
        )
    )
    with psycopg.connect(pg.role_dsn()) as connection:
        # A comma-list is OR: SELECT still succeeds while this write does not.
        assert connection.execute(
            "SELECT has_table_privilege(%s, %s), has_table_privilege(%s, 'SELECT')",
            (table, privilege, table),
        ).fetchone() == (False, True)
    assert store.ready() is False
    pg.grant_runtime()
    assert store.ready() is True


@pytest.mark.parametrize("table", ["auth_meta", *WRITES])
def test_each_required_read_privilege_is_required(pg: OwnedPostgres, table: str) -> None:
    pg.grant_runtime()
    pg.execute(
        sql.SQL("REVOKE SELECT ON {} FROM {}").format(
            sql.Identifier(table), sql.Identifier(pg.role)
        )
    )
    assert AuthStore(database_url=pg.role_dsn()).ready() is False


@pytest.mark.parametrize(
    ("table", "privilege", "column"),
    [(table, privilege, column) for (table, privilege), cols in COLUMNS.items() for column in cols],
)
def test_each_required_column_privilege_is_required(
    pg: OwnedPostgres, table: str, privilege: str, column: str
) -> None:
    pg.grant_runtime(columns=True)
    store = AuthStore(database_url=pg.role_dsn())
    assert store.ready() is True
    pg.execute(
        sql.SQL("REVOKE {} ({}) ON {} FROM {}").format(
            sql.SQL(privilege),
            sql.Identifier(column),
            sql.Identifier(table),
            sql.Identifier(pg.role),
        )
    )
    with psycopg.connect(pg.role_dsn()) as connection:
        assert connection.execute(
            "SELECT has_column_privilege(%s, %s, %s)", (table, column, privilege)
        ).fetchone() == (False,)
    assert store.ready() is False


@pytest.mark.parametrize("mode", ["direct", "inherited", "set-role"])
def test_least_privilege_role_can_use_runtime_operations(pg: OwnedPostgres, mode: str) -> None:
    if mode == "inherited":
        group = pg.role + "_group"
        pg.execute(sql.SQL("CREATE ROLE {}").format(sql.Identifier(group)))
        pg.extra_roles.append(group)
        pg.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(group), sql.Identifier(pg.role)))
        pg.grant_runtime(columns=True, grantee=group)
    else:
        pg.grant_runtime(columns=True)
    dsn = pg.role_dsn()
    if mode == "set-role":
        dsn = pg.dsn + "&options=" + quote("-c role=" + pg.role, safe="")
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT current_user").fetchone() == (pg.role,)
        assert connection.execute(
            "SELECT has_table_privilege('auth_users', 'DELETE'), "
            "has_table_privilege('auth_audit', 'UPDATE'), "
            "has_table_privilege('auth_meta', 'INSERT'), "
            "has_schema_privilege('public', 'CREATE')"
        ).fetchone() == (False, False, False, False)
    store = AuthStore(database_url=dsn)
    assert store.ready() is True
    password = "Generated readiness password " + secrets.token_hex(16)
    store.bootstrap("admin", password)
    admin = store.login("admin", password)
    assert store.authenticate(admin.token).user.id == admin.user.id
    user = store.create_user(admin.token, "member", password, Role.VIEWER)
    store.update_user(admin.token, user.id, role=Role.ANALYST)
    store.reset_password(admin.token, user.id, password + " reset")
    member = store.login("member", password + " reset")
    store.change_password(member.token, password + " reset", password + " changed")
    store.revoke_user_sessions(admin.token, user.id)
    resource = secrets.token_hex(16)
    store.reserve_job("analysis", resource, admin.actor, str(uuid4()), secrets.token_hex(16))
    assert store.finish_job("analysis", resource, "COMPLETED") == "complete"
    assert store.export_audit(admin.token).total > 0
    store.logout(admin.token)
    assert store.ready() is True
    # Check the effective role, including a SET ROLE session whose login is superuser.
    grantee = pg.extra_roles[0] if mode == "inherited" else pg.role
    pg.execute(
        sql.SQL("REVOKE UPDATE (last_seen_at) ON auth_sessions FROM {}").format(
            sql.Identifier(grantee)
        )
    )
    assert store.ready() is False


def test_readiness_is_bounded_observation_not_a_write(
    pg: OwnedPostgres, monkeypatch: pytest.MonkeyPatch
) -> None:
    pg.grant_runtime()
    statements: list[str] = []
    original = SQL.execute

    def observe(self: SQL, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        statements.append(statement)
        assert statement.lstrip().split()[0].upper() in {"SELECT", "SHOW"}
        return original(self, statement, parameters)

    monkeypatch.setattr(SQL, "execute", observe)
    with psycopg.connect(pg.dsn) as connection:
        before = connection.execute("SELECT * FROM auth_audit").fetchall()
    store = AuthStore(database_url=pg.role_dsn())
    assert store.ready() is True
    assert len(statements) <= 10
    with psycopg.connect(pg.dsn) as connection:
        assert connection.execute("SELECT * FROM auth_audit").fetchall() == before
