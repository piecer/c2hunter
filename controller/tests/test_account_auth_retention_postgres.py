"""Real PostgreSQL retention parity and maintenance-only privilege boundaries."""

import asyncio

import pytest
import test_account_auth_readiness as readiness
from psycopg import sql
from test_account_auth_retention import NOW, event, rows
from test_account_auth_retention import (
    test_oldest_first_maximum_and_ties as check_bound,
)
from test_account_auth_retention import (
    test_protected_links_and_unresolved_intents_do_not_starve_eligible_rows as check_protection,
)
from test_account_auth_retention import (
    test_resolved_http_intent_is_eligible_but_unknown_or_unmatched_is_not as check_resolution,
)
from test_account_auth_retention import test_strict_default_cutoff_and_atomic_count as check_cutoff
from test_account_auth_retention_runtime import application

from c2hunter_controller.auth_models import AuthError
from c2hunter_controller.auth_store import AuthStore

pg = readiness.pg


@pytest.fixture
def store(pg):
    return AuthStore(database_url=pg.dsn, clock=lambda: NOW)


@pytest.mark.parametrize("check", [check_cutoff, check_bound, check_protection, check_resolution])
def test_real_postgres_retains_sqlite_contract(store, check):
    check(store)


def test_postgres_audit_insert_failure_rolls_back_delete(store):
    event(store, 1)
    before = rows(store)
    with store.db.transaction() as db:
        db.execute(
            "CREATE FUNCTION deny_prune() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'private failure sentinel'; END $$"
        )
        db.execute(
            "CREATE TRIGGER deny_prune BEFORE INSERT ON auth_audit "
            "FOR EACH ROW WHEN (NEW.action='audit.prune') EXECUTE FUNCTION deny_prune()"
        )
    with pytest.raises(AuthError, match="^SECURITY_UNAVAILABLE$"):
        store.prune_audit()
    assert rows(store) == before
    with store.db.transaction() as db:
        db.execute("DROP TRIGGER deny_prune ON auth_audit")
    assert store.prune_audit() == 1


@pytest.mark.parametrize("columns", [False, True])
def test_maintenance_delete_is_not_a_core_readiness_requirement(pg, store, columns, caplog):
    pg.grant_runtime(columns=columns)
    runtime = AuthStore(database_url=pg.role_dsn(), clock=lambda: NOW)
    event(store, 1)
    before = rows(store)
    assert runtime.ready() is True
    with pytest.raises(AuthError, match="^SECURITY_UNAVAILABLE$"):
        runtime.prune_audit()
    assert rows(store) == before
    assert runtime.ready() is True
    app = application(runtime)

    async def run():
        async with app.router.lifespan_context(app):
            owner = app.state.auth_retention
            assert owner.last_error == "AUDIT_RETENTION_FAILED"
            assert runtime.ready() is True
        assert owner.task.done()

    asyncio.run(run())
    assert "Audit retention maintenance failed" in caplog.text
    assert "permission denied" not in caplog.text
    pg.execute(sql.SQL("GRANT DELETE ON auth_audit TO {}").format(sql.Identifier(pg.role)))
    assert runtime.prune_audit() == 1
    assert runtime.ready() is True
    assert not [r for r in rows(store) if r["timestamp"] == 1]


def test_readonly_postgres_retention_refused_without_schema_repair(pg, store):
    event(store, 1)
    before = rows(store)
    pg.grant_runtime()
    pg.execute(sql.SQL("GRANT DELETE ON auth_audit TO {}").format(sql.Identifier(pg.role)))
    readonly = AuthStore(database_url=pg.role_dsn("-c default_transaction_read_only=on"))
    with pytest.raises(AuthError, match="^SECURITY_UNAVAILABLE$"):
        readonly.prune_audit()
    assert rows(store) == before


def test_postgres_indexes_and_actual_bounded_delete_plan(store, monkeypatch):
    from c2hunter_controller.auth_schema import SQL

    with store.db.transaction() as db:
        indexes = {
            r["indexname"]
            for r in db.execute("SELECT indexname FROM pg_indexes WHERE schemaname='public'")
        }
    assert {
        "auth_job_intent",
        "auth_audit_http_terminal",
        "auth_job_pending",
        "auth_audit_order",
    } <= indexes
    original = SQL.execute
    plans = []

    def observe(db, statement, parameters=()):
        if statement.startswith("DELETE FROM auth_audit"):
            plans.append(original(db, "EXPLAIN (FORMAT JSON) " + statement, parameters).fetchone())
        return original(db, statement, parameters)

    monkeypatch.setattr(SQL, "execute", observe)
    check_bound(store)
    assert len(plans) == 3
    print(plans)
