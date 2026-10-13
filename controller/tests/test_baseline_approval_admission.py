"""Closed input, revision precedence, and custody at new public boundaries."""

import sqlite3
from typing import Any
from uuid import uuid4

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


@pytest.mark.parametrize("mutation", ["reason", "note", "unknown", "dict", "bool-revision"])
def test_request_precopy_validation(approval_repo: Any, monkeypatch: Any, mutation: str) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    if mutation == "reason":
        request = request.model_copy(update={"reason": "x" * 513})
    elif mutation == "note":
        request = request.model_copy(
            update={"quality_review": request.quality_review.model_copy(update={"note": "x" * 513})}
        )
    elif mutation == "unknown":
        request = request.model_copy(update={"unknown": object()})
    elif mutation == "dict":
        request = request.to_mapping()
    else:
        request = request.model_copy(update={"expected_revision": True})

    def forbidden(*args: Any, **kw: Any) -> Any:
        raise AssertionError("precopy admission crossed forbidden boundary")

    monkeypatch.setattr(bs, "publication_connection", forbidden)
    monkeypatch.setattr(bs, "memory_publish", forbidden)
    monkeypatch.setattr(g, "_unmodel", forbidden)
    with pytest.raises(ValueError) as caught:
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert not isinstance(caught.value, bs.BaselineStorageError)


@pytest.mark.parametrize(
    "frozen,stale,code",
    [
        (False, False, "BASELINE_CONTROL_LIMIT"),
        (True, False, "BASELINE_FROZEN"),
        (True, True, "BASELINE_REVISION_CONFLICT"),
    ],
)
def test_saturation_order(
    approval_repo: Any, monkeypatch: Any, frozen: bool, stale: bool, code: str
) -> None:
    repo = approval_repo
    view, _ = repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    if isinstance(repo, MemoryRepository):
        repo._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
            dict(view.to_mapping(), control_revision=2**63 - 1, frozen=frozen)
        )
    else:
        with bs.transaction(
            repo.connection, postgres=hasattr(repo, "database_url"), write=True
        ) as cur:
            bs._SQL(cur, hasattr(repo, "database_url")).execute(
                "UPDATE baseline_scopes SET control_revision=?,frozen=?", (2**63 - 1, int(frozen))
            )
    request = g.ApprovalRequest.from_mapping(
        dict(
            request.to_mapping(),
            expected_revision=0 if stale else 2**63 - 1,
            source_binding_sha256="0" * 64,
        )
    )

    def forbidden(*args: Any, **kw: Any) -> Any:
        raise AssertionError("saturation crossed ID/feature boundary")

    monkeypatch.setattr("uuid.uuid4", forbidden)
    monkeypatch.setattr(g, "produce_generation", forbidden)
    monkeypatch.setattr(bs.s, "source_from_binding", forbidden)
    with pytest.raises(bs.BaselineStorageError, match="^" + code + "$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert repo.get_baseline_scope(config().scope_id).control_revision == 2**63 - 1


@pytest.mark.parametrize("mutation", ["actor", "reason", "review", "revision", "binding", "source"])
def test_fingerprint_conflict_before_current_scope(
    approval_repo: Any, monkeypatch: Any, mutation: str
) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    actor = "reviewer"
    data = request.to_mapping()
    if mutation == "actor":
        actor = "other"
    elif mutation == "review":
        data["quality_review"]["note"] = "different review"
    else:
        field, value = {
            "reason": ("reason", "changed"),
            "revision": ("expected_revision", 7),
            "binding": ("source_binding_sha256", "0" * 64),
            "source": ("source_job_id", "other"),
        }[mutation]
        data[field] = value
    changed = g.ApprovalRequest.from_mapping(data)

    def forbidden(*args: Any, **kw: Any) -> Any:
        raise AssertionError("conflicting fingerprint decoded current scope")

    monkeypatch.setattr(bs, "memory_get", forbidden)
    monkeypatch.setattr(bs._SQL, "get", forbidden)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_IDEMPOTENCY_CONFLICT$"):
        repo.publish_baseline_source(config().scope_id, changed, actor, START)


@pytest.mark.parametrize("operation", ["publish", "page"])
@pytest.mark.parametrize("foreign", [True, False])
def test_transaction_custody(approval_repo: Any, operation: str, foreign: bool) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL caller transaction custody")
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    con = repo.connection
    pg = hasattr(repo, "database_url")
    if foreign:
        con.execute("CREATE TEMP TABLE approval_caller_sentinel(value INTEGER)")
        con.commit()
        con.execute("BEGIN")
        con.execute("INSERT INTO approval_caller_sentinel VALUES(17)")
    else:
        con.autocommit = True
    try:
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
            if operation == "publish":
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
            else:
                repo.page_baseline_sources(config().scope_id, str(uuid4()))
        if foreign:
            assert con.execute("SELECT value FROM approval_caller_sentinel").fetchone() == (17,)
            assert (con.info.transaction_status.name == "INTRANS") if pg else con.in_transaction
        else:
            assert con.autocommit is True
    finally:
        if foreign:
            con.rollback()
        else:
            con.autocommit = False if pg else sqlite3.LEGACY_TRANSACTION_CONTROL
