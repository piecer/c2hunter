"""Acquired typed-seam lifetime, custody, replay and cleanup regressions.

Inherited compatible behavior is regression coverage, not new RED/TDD proof.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as read
from c2hunter_controller.baseline_admission import BaselineAdmission, BaselineLease
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_baseline_approval_contract import prepare
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


def assert_free(permit: BaselineAdmission) -> None:
    def check() -> None:
        with BaselineLease(permit) as lease:
            assert lease.acquire()

    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(check).result(5)


def assert_held(permit: BaselineAdmission) -> None:
    with BaselineLease(permit) as lease:
        assert not lease.acquire()


def test_lease_through_maps_commit_and_readback(approval_repo: Any, monkeypatch: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "reviewer", START)
    request = prepare(repo)
    permit = BaselineAdmission()
    seen = []
    if isinstance(repo, MemoryRepository):
        original = MemoryRepository.__setattr__

        def assign(target: Any, name: str, value: Any) -> None:
            if target is repo and name in {
                "_baseline_scopes",
                "_baseline_generations",
                "_baseline_operations",
            }:
                assert_held(permit)
                seen.append(name)
            original(target, name, value)

        monkeypatch.setattr(MemoryRepository, "__setattr__", assign)
    else:
        original = bs._publication_transaction.__exit__
        replay = bs._PublicationSQL.replay

        def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
            if owner.write:
                assert_held(permit)
                seen.append("before-commit")
            value = original(owner, kind, error, tb)
            if owner.write:
                assert_held(permit)
                seen.append("after-commit")
            return value

        def lookup(db: Any, *a: Any, **kw: Any) -> Any:
            if seen:
                assert_held(permit)
                seen.append("readback")
            return replay(db, *a, **kw)

        monkeypatch.setattr(bs._publication_transaction, "__exit__", boundary)
        monkeypatch.setattr(bs._PublicationSQL, "replay", lookup)
    result = repo.publish_baseline_source(
        config().scope_id, request, "reviewer", START, admission=permit
    )
    assert result.created
    assert seen == (
        ["_baseline_scopes", "_baseline_generations", "_baseline_operations"]
        if isinstance(repo, MemoryRepository)
        else ["before-commit", "after-commit", "readback"]
    )
    assert_free(permit)


def test_busy_no_source_producer_ids_or_dml_then_replay(
    approval_repo: Any, monkeypatch: Any
) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "reviewer", START)
    request = prepare(repo)
    permit = BaselineAdmission()
    before = repo.get_baseline_scope(config().scope_id)
    calls = []

    def forbidden(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        raise AssertionError("source/producer/publication forbidden")

    lease = BaselineLease(permit)
    assert lease.acquire()
    with monkeypatch.context() as m:
        for name in ["_memory_acquire", "_sqlite_acquire", "_postgres_acquire"]:
            m.setattr(read, name, forbidden)
        m.setattr(g, "produce_generation", forbidden)
        m.setattr(bs, "_stage_publication", forbidden)
        execute = bs._SQL.execute

        def sql(db: Any, statement: str, *a: Any, **kw: Any) -> Any:
            assert not statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
            return execute(db, statement, *a, **kw)

        m.setattr(bs._SQL, "execute", sql)
        try:
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
                repo.publish_baseline_source(
                    config().scope_id, request, "reviewer", START, admission=permit
                )
            assert calls == [] and repo.get_baseline_scope(config().scope_id) == before
            assert repo.page_baseline_control_events(config().scope_id).total == 0
        finally:
            lease.close()
    result = repo.publish_baseline_source(
        config().scope_id, request, "reviewer", START, admission=permit
    )
    repo.delete_job(request.source_job_id)
    assert lease.acquire()
    try:
        replay = repo.publish_baseline_source(
            config().scope_id, request, "reviewer", START, admission=permit
        )
        assert not replay.created and replay.receipt == result.receipt
        changed = g.ApprovalRequest.from_mapping(dict(request.to_mapping(), reason="changed"))
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_IDEMPOTENCY_CONFLICT$"):
            repo.publish_baseline_source(
                config().scope_id, changed, "reviewer", START, admission=permit
            )
    finally:
        lease.close()
    assert_free(permit)


def test_actual_foreign_transaction_retained_sentinel_and_free_lease(approval_repo: Any) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL transaction custody only")
    repo.create_baseline_scope(config(), "reviewer", START)
    request = prepare(repo)
    con = repo.connection
    con.execute("CREATE TEMP TABLE http_custody(value INTEGER)")
    con.commit()
    con.execute("BEGIN")
    con.execute("INSERT INTO http_custody VALUES(17)")
    permit = BaselineAdmission()
    try:
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
            repo.publish_baseline_source(
                config().scope_id, request, "reviewer", START, admission=permit
            )
        assert con.execute("SELECT value FROM http_custody").fetchall() == [(17,)]
        assert (
            con.in_transaction
            if isinstance(repo, SQLiteRepository)
            else con.info.transaction_status.name == "INTRANS"
        )
        assert_free(permit)
    finally:
        con.rollback()


def test_producer_exception_preserves_identity_and_releases(
    approval_repo: Any, monkeypatch: Any
) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "reviewer", START)
    request = prepare(repo)
    permit = BaselineAdmission()
    marker = TypeError("owned programmer error")
    fired = []

    def fail(**kw: Any) -> Any:
        assert_held(permit)
        fired.append(True)
        raise marker

    with monkeypatch.context() as m:
        m.setattr(g, "produce_generation", fail)
        with pytest.raises(TypeError) as error:
            repo.publish_baseline_source(
                config().scope_id, request, "reviewer", START, admission=permit
            )
        assert error.value is marker and fired == [True]
    assert_free(permit)
    assert repo.publish_baseline_source(
        config().scope_id, request, "reviewer", START, admission=permit
    ).created


@pytest.mark.parametrize("fault", ["cleanup", "commit-ack", "read-rollback", "readback"])
def test_acquired_seam_retained_fault_contracts(
    approval_repo: Any, monkeypatch: Any, fault: str
) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL fault contract only")
    from tests import test_baseline_approval_ownership as ownership
    from tests import test_baseline_approval_transaction_repair as transaction

    permit = BaselineAdmission()
    monkeypatch.setattr(
        repo, "publish_baseline_source", partial(repo.publish_baseline_source, admission=permit)
    )
    if fault == "cleanup":
        ownership.test_failed_cleanup_quarantines_facade(repo, monkeypatch)
    elif fault == "readback":
        transaction.test_postcommit_digest_mismatch_is_storage_error(repo, monkeypatch)
    else:
        ownership.test_ambiguous_or_failed_teardown_disposes(repo, monkeypatch, fault)
    assert_free(permit)
