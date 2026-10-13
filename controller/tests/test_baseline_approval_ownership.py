"""Cleanup-failed ownership must not be reused or silently reopened."""

from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import MemoryRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


def test_failed_cleanup_quarantines_facade(approval_repo: Any, monkeypatch: Any) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL-owned connection quarantine")
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    real = repo.connection
    pg = hasattr(repo, "database_url")
    primary = TypeError("owned primary")
    fired = []
    closed = []

    class Connection:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        def rollback(self) -> None:
            if fired:
                raise RuntimeError("cleanup failure")
            real.rollback()

        def close(self) -> None:
            closed.append(True)
            raise RuntimeError("close failed without closing")

    proxy = Connection()
    if pg:
        repo._connection = proxy
    else:
        repo.connection = proxy

    def fail(**kw: Any) -> Any:
        fired.append(True)
        raise primary

    monkeypatch.setattr(bs.g, "produce_generation", fail)
    try:
        with pytest.raises(TypeError) as caught:
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert caught.value is primary and closed == [True]
        for method, args in [
            (repo.publish_baseline_source, (config().scope_id, request, "reviewer", START)),
            (repo.page_baseline_sources, (config().scope_id, config().scope_id)),
        ]:
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                method(*args)
        assert fired == [True] and closed == [True]
    finally:
        real.rollback()
        if pg:
            repo._connection = real
        else:
            repo.connection = real


@pytest.mark.parametrize("point", ["commit-ack", "read-rollback"])
def test_ambiguous_or_failed_teardown_disposes(
    approval_repo: Any, monkeypatch: Any, point: str
) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL connection disposal")
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    real = repo.connection
    pg = hasattr(repo, "database_url")
    primary = RuntimeError("owned uncertain teardown")
    fired, closed = [], []

    class Connection:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        def commit(self) -> None:
            real.commit()
            if point == "commit-ack" and not fired:
                fired.append(True)
                raise primary

        def rollback(self) -> None:
            real.rollback()
            if point == "read-rollback" and not fired:
                fired.append(True)
                raise primary

        def close(self) -> None:
            closed.append(True)
            real.close()

    proxy = Connection()
    if pg:
        repo._connection = proxy
    else:
        repo.connection = proxy
    try:
        with pytest.raises(RuntimeError) as caught:
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert caught.value is primary and fired == [True] and closed == [True]
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        from contextlib import closing

        from tests.test_baseline_scope_faults import observer

        with closing(observer(repo)) as raw:
            assert raw.execute("SELECT control_revision FROM baseline_scopes").fetchone() == (
                1 if point == "commit-ack" else 0,
            )
    finally:
        if pg:
            repo._connection = real
        else:
            repo.connection = real
