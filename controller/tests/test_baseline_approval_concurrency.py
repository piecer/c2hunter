"""Real concurrent writers and supported shared-facade readers."""

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_baseline_approval_retention import operations, publish
from tests.test_baseline_approval_sql import durable
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


@pytest.mark.parametrize("race", ["same", "changed", "different-key"])
def test_concurrent_writers(approval_repo: Any, monkeypatch: Any, race: str) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    memory = isinstance(repo, MemoryRepository)
    peer = (
        repo
        if memory
        else PostgresRepository(repo.database_url, None)
        if hasattr(repo, "database_url")
        else SQLiteRepository(repo._path)
    )
    if not memory:
        assert peer.connection is not repo.connection
    barrier = threading.Barrier(2)
    seen = set()
    exit_ = bs._publication_transaction.__exit__

    def exited(owner: Any, *args: Any) -> Any:
        result = exit_(owner, *args)
        identity = id(owner.connection)
        if not owner.write and identity not in seen:
            seen.add(identity)
            barrier.wait(20)
        return result

    if not memory:
        monkeypatch.setattr(bs._publication_transaction, "__exit__", exited)
    other = (
        g.ApprovalRequest.from_mapping(dict(request.to_mapping(), idempotency_key="other"))
        if race == "different-key"
        else request
    )

    def call(target: Any, req: Any, actor: str) -> Any:
        if memory:
            barrier.wait(20)
        try:
            return target.publish_baseline_source(config().scope_id, req, actor, START)
        except bs.BaselineStorageError as error:
            return error.code

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(call, repo, request, "reviewer")
            b = pool.submit(call, peer, other, "other" if race == "changed" else "reviewer")
            results = [a.result(30), b.result(30)]
        created = [
            value for value in results if isinstance(value, g.PublicationResult) and value.created
        ]
        assert len(created) == 1
        if race == "same":
            assert all(isinstance(value, g.PublicationResult) for value in results)
            assert results[0].receipt == results[1].receipt
            assert sorted(value.created for value in results) == [False, True]
        else:
            assert (
                "BASELINE_IDEMPOTENCY_CONFLICT"
                if race == "changed"
                else "BASELINE_REVISION_CONFLICT"
            ) in results
        monkeypatch.setattr(bs._publication_transaction, "__exit__", exit_)
        assert len(operations(repo)) == 1
        assert repo.get_baseline_scope(config().scope_id).control_revision == 1
    finally:
        if not memory:
            peer.close()


@pytest.mark.parametrize("reader", ["get", "page", "preview", "sources"])
@pytest.mark.parametrize("fail", [False, True])
def test_same_facade_fence(approval_repo: Any, monkeypatch: Any, reader: str, fail: bool) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    publish(repo, 0)
    _, second = publish(repo, 1)
    request = fixtures.prepare(repo, 2)
    old = None if isinstance(repo, MemoryRepository) else durable(repo)
    paused, release, attempted, finished = (threading.Event() for _ in range(4))
    writer_id = []
    lock = repo._lock

    class Lock:
        def __enter__(self) -> Any:
            if writer_id and threading.get_ident() != writer_id[0]:
                attempted.set()
            lock.acquire()
            return self

        def __exit__(self, *args: Any) -> None:
            lock.release()

    repo._lock = Lock()
    marker = TypeError("owned paused publication")

    def pause() -> None:
        paused.set()
        assert release.wait(20)
        if fail:
            raise marker

    if isinstance(repo, MemoryRepository):
        original = bs.memory_publish

        def memory(*args: Any, **kw: Any) -> Any:
            result = original(*args, **kw)
            pause()
            return result

        monkeypatch.setattr(bs, "memory_publish", memory)
    else:
        execute = bs._SQL.execute

        def sql(db: Any, statement: str, values: tuple = ()) -> Any:
            result = execute(db, statement, values)
            if statement.startswith("DELETE FROM baseline_generations"):
                pause()
            return result

        monkeypatch.setattr(bs._SQL, "execute", sql)

    def write() -> Any:
        writer_id.append(threading.get_ident())
        try:
            return repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        except TypeError as error:
            assert error is marker
            return error

    def read() -> Any:
        try:
            if reader == "get":
                return repo.get_baseline_scope(config().scope_id)
            if reader == "page":
                return repo.page_baseline_scopes()
            if reader == "sources":
                return repo.page_baseline_sources(config().scope_id, second.receipt.generation_id)
            return repo.preview_baseline_source(
                config().scope_id, request.source_job_id, 2, "APPROVAL"
            )
        except bs.BaselineStorageError as error:
            assert not fail and reader == "preview" and error.code == "BASELINE_REVISION_CONFLICT"
            return error
        finally:
            finished.set()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(write)
            assert paused.wait(20)
            if old is not None:
                assert durable(repo) == old
            reading = pool.submit(read)
            assert attempted.wait(20)
            assert not finished.is_set()
            release.set()
            assert (writer.result(30) is marker) is fail
            reading.result(30)
        assert finished.is_set()
        assert repo.get_baseline_scope(config().scope_id).control_revision == (2 if fail else 3)
    finally:
        release.set()
        repo._lock = lock
