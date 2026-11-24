"""Real storage retention: strict age, bounded deletion and durable evidence."""

import json
import uuid

import pytest

from c2hunter_controller.auth_models import Actor
from c2hunter_controller.auth_store import AuthStore

DAY = 86400
NOW = 200 * DAY


@pytest.fixture
def store(tmp_path):
    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite", clock=lambda: NOW)
    auth.initialize()
    return auth


def event(store, timestamp, *, outcome="succeeded", request_id=None):
    with store.db.transaction() as sql:
        identity = store._audit(
            sql, Actor(), "http.operation", "/api/v1/jobs", outcome, request_id=request_id
        )
        sql.execute("UPDATE auth_audit SET timestamp=? WHERE id=?", (timestamp, identity))
    return identity


def rows(store):
    with store.db.transaction() as sql:
        return [dict(row) for row in sql.execute("SELECT * FROM auth_audit ORDER BY timestamp,id")]


def test_strict_default_cutoff_and_atomic_count(store):
    cutoff = NOW - 180 * DAY
    old = event(store, cutoff - 0.001)
    boundary = event(store, cutoff)
    recent = event(store, cutoff + 0.001)
    assert store.prune_audit() == 1
    remaining = rows(store)
    assert old not in {row["id"] for row in remaining}
    assert {boundary, recent} <= {row["id"] for row in remaining}
    prune = [row for row in remaining if row["action"] == "audit.prune"]
    assert len(prune) == 1
    assert prune[0]["auth_kind"] == "system"
    assert prune[0]["outcome"] == "succeeded"
    assert json.loads(prune[0]["details"]) == {"count": 1}


def test_protected_links_and_unresolved_intents_do_not_starve_eligible_rows(store):
    request = str(uuid.uuid4())
    intent = event(store, 1, outcome="started", request_id=request)
    # Even a resolved HTTP intent is protected when a job references it.
    event(store, 2, request_id=request)
    store.reserve_job("analysis", "a" * 32, Actor(), request, intent)
    store.finish_job("analysis", "a" * 32, "COMPLETED")
    pending_intent = event(store, 1, outcome="started", request_id=str(uuid.uuid4()))
    store.reserve_job("analysis", "b" * 32, Actor(), str(uuid.uuid4()), pending_intent)
    with store.db.transaction() as sql:
        sql.execute("UPDATE auth_audit SET timestamp=1 WHERE action='job.lifecycle'")
        links = [dict(row) for row in sql.execute("SELECT * FROM auth_job_links ORDER BY id")]
        # Older protected rows must not consume the 1000 eligible-row allowance.
        for _ in range(1005):
            identity = store._audit(sql, Actor(), "http.operation", "/api/v1/jobs", "started")
            sql.execute("UPDATE auth_audit SET timestamp=1 WHERE id=?", (identity,))
    before = rows(store)
    protected = {row["id"] for row in before if row["outcome"] == "started"}
    protected.update(row["event_id"] for row in links if row["event_id"])
    assert store.prune_audit() == 1  # Only the unlinked HTTP completion.
    assert protected <= {row["id"] for row in rows(store)}
    with store.db.transaction() as sql:
        assert [
            dict(row) for row in sql.execute("SELECT * FROM auth_job_links ORDER BY id")
        ] == links
    assert store.finish_job("analysis", "a" * 32, "COMPLETED") == "complete"
    assert store.job_audit_status("analysis", "b" * 32) == "pending"


def test_resolved_http_intent_is_eligible_but_unknown_or_unmatched_is_not(store):
    request = str(uuid.uuid4())
    resolved = event(store, 1, outcome="started", request_id=request)
    terminal = event(store, 2, request_id=request)
    unknown_request = str(uuid.uuid4())
    unknown = event(store, 1, outcome="started", request_id=unknown_request)
    event(store, 2, outcome="unknown", request_id=unknown_request)
    unmatched = event(store, 1, outcome="started", request_id=str(uuid.uuid4()))
    assert store.prune_audit() == 3
    remaining = {row["id"] for row in rows(store)}
    assert {unknown, unmatched} <= remaining
    assert not {resolved, terminal} & remaining


def test_oldest_first_maximum_and_ties(store):
    with store.db.transaction() as sql:
        identities = []
        for timestamp in [10] * 1002 + [9, 11]:
            identity = store._audit(sql, Actor(), "http.operation", "/api/v1/jobs", "succeeded")
            sql.execute("UPDATE auth_audit SET timestamp=? WHERE id=?", (timestamp, identity))
            identities.append((timestamp, identity))
    expected = {identity for _, identity in sorted(identities)[:1000]}
    assert store.prune_audit() == 1000
    remaining = {row["id"] for row in rows(store)}
    assert not expected & remaining
    assert {identity for _, identity in sorted(identities)[1000:]} <= remaining
    assert store.prune_audit() == 4
    assert store.prune_audit() == 0
    counts = [
        json.loads(row["details"])["count"] for row in rows(store) if row["action"] == "audit.prune"
    ]
    assert sorted(counts) == [0, 4, 1000]  # Reference writes an event even for zero deletions.


def test_audit_insert_failure_rolls_back_deletion(store):
    from c2hunter_controller.auth_models import AuthError

    event(store, 1)
    before = rows(store)
    with store.db.transaction() as sql:
        sql.execute(
            "CREATE TRIGGER deny_prune BEFORE INSERT ON auth_audit "
            "WHEN NEW.action='audit.prune' BEGIN SELECT RAISE(ABORT,'private sentinel'); END"
        )
    with pytest.raises(AuthError, match="^SECURITY_UNAVAILABLE$"):
        store.prune_audit()
    assert rows(store) == before
    with store.db.transaction() as sql:
        sql.execute("DROP TRIGGER deny_prune")
    assert store.prune_audit() == 1


@pytest.mark.parametrize("days", [0, -1, 3651, True, 1.5, "180", None])
def test_invalid_days_refused_before_storage(store, days):
    before = rows(store)
    with pytest.raises(ValueError, match="retention"):
        store.prune_audit(days)
    assert rows(store) == before


def test_retention_indexes_only_explicit_init_and_real_query_plan(store, monkeypatch):
    from c2hunter_controller.auth_schema import SQL

    expected = {"auth_job_intent", "auth_audit_http_terminal"}
    with store.db.transaction() as sql:
        indexes = {
            row["name"] for row in sql.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
    assert expected <= indexes
    captured = []
    original = SQL.execute

    def observe(sql, statement, parameters=()):
        if statement.startswith("DELETE FROM auth_audit"):
            captured.extend(original(sql, "EXPLAIN QUERY PLAN " + statement, parameters).fetchall())
        return original(sql, statement, parameters)

    monkeypatch.setattr(SQL, "execute", observe)
    event(store, 1)
    store.prune_audit()
    plan = "\n".join(row["detail"] for row in captured)
    for name in (*expected, "auth_audit_order", "auth_job_pending"):
        assert name in plan
    assert "SCAN j" not in plan and "SCAN terminal" not in plan
    with store.db.transaction() as sql:
        sql.execute("DROP INDEX auth_job_intent")
        sql.execute("DROP INDEX auth_audit_http_terminal")
    assert store.ready()
    assert store.prune_audit() == 0
    with store.db.transaction() as sql:
        indexes = {
            row["name"] for row in sql.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
    assert not expected & indexes
    store.initialize()
    with store.db.transaction() as sql:
        indexes = {
            row["name"] for row in sql.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
    assert expected <= indexes
