"""Deterministic writer/readback schedules with serial SQL initialization."""

import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import MemoryRepository
from tests.publication_fixtures import publication_adapter
from tests.test_baseline_control_boundaries import operation_rows, replace_operation
from tests.test_baseline_control_storage import (
    approval,
    control,
    invoke,
    raw_state,
    reopen,
    setup_references,
    store_source,
)
from tests.test_historical_source import START, config

adapter = publication_adapter


@pytest.mark.parametrize(
    "kind", ["same", "changed", "cross-control", "different-key", "approve-control"]
)
def test_actual_writer_races(adapter: Any, monkeypatch: Any, kind: str) -> None:
    repo = adapter
    view, _, _ = setup_references(repo, 0)
    peer = repo if isinstance(repo, MemoryRepository) else reopen(repo)
    requests = [control(0, "FREEZE", key="race"), control(0, "FREEZE", key="race")]
    if kind == "changed":
        requests[1] = requests[1].model_copy(update={"reason": "changed"})
    elif kind == "cross-control":
        requests[1] = control(0, "RETIRE", key="race")
    elif kind == "different-key":
        requests[1] = control(0, "FREEZE", key="other")
    elif kind == "approve-control":
        requests[1] = approval(repo, store_source(repo, 0), 0)
    start = Barrier(2)
    exited = set()
    actual = bs._publication_transaction.__exit__

    def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
        result = actual(owner, kind, error, tb)
        if not owner.write and id(owner.connection) not in exited:
            exited.add(id(owner.connection))
            start.wait(15)
        return result

    def call(client: Any, request: Any) -> Any:
        if isinstance(repo, MemoryRepository):
            start.wait(15)
        try:
            if hasattr(request, "source_job_id"):
                return client.publish_baseline_source(config().scope_id, request, "reviewer", START)
            return invoke(client, request)
        except bs.BaselineStorageError as error:
            return error.code

    try:
        with monkeypatch.context() as patch:
            if peer is not repo:
                patch.setattr(bs._publication_transaction, "__exit__", boundary)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [
                    pool.submit(call, client, request)
                    for client, request in zip((repo, peer), requests, strict=True)
                ]
                outcomes = [future.result(30) for future in futures]
        wins = [item for item in outcomes if not isinstance(item, str)]
        losses = [item for item in outcomes if isinstance(item, str)]
        if kind == "same":
            assert len(wins) == 2 and wins[0].receipt == wins[1].receipt
        else:
            assert len(wins) == 1
            assert losses == [
                "BASELINE_REVISION_CONFLICT"
                if kind in ("different-key", "approve-control")
                else "BASELINE_IDEMPOTENCY_CONFLICT"
            ]
        assert len(operation_rows(repo)) == 1
        assert repo.get_baseline_scope(config().scope_id).control_revision == 1
        if peer is not repo:
            assert len(exited) == 2
    finally:
        if peer is not repo:
            peer.close()


@pytest.mark.parametrize(
    "advance",
    [
        "REVOKE",
        "RETIRE",
        "FREEZE",
        "UNFREEZE",
        "APPROVE",
        "evict",
        "digest",
        "receipt",
        "same-revision",
    ],
)
def test_control_first_readback_current_view(adapter: Any, monkeypatch: Any, advance: str) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory returns staged DTO under one lock; no postcommit transaction")
    view, _, results = setup_references(repo)
    next_job = store_source(repo, 10)
    peer = reopen(repo)
    request = control(2, "ROLLBACK", results[0].receipt.generation_id)
    actual = bs._publication_transaction.__exit__
    fired, committed = [], []

    def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
        value = actual(owner, kind, error, tb)
        if owner.connection is repo.connection and owner.write and error is None:
            assert not fired
            fired.append(True)
            committed.append(operation_rows(peer)[-1])
            if advance in ("digest", "receipt"):
                row = list(committed[0])
                if advance == "digest":
                    row[3] = "0" * 64
                else:
                    receipt = json.loads(row[5])
                    receipt["occurred_at"] = "2020-01-01T00:00:00.000000Z"
                    row[5] = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
                    row[6] = hashlib.sha256(row[5].encode()).hexdigest()
                    row[7] = len(row[5].encode())
                replace_operation(peer, tuple(row))
            elif advance == "same-revision":
                from tests.test_baseline_approval_transaction_repair import independent

                with independent(peer) as con:
                    con.execute("UPDATE baseline_scopes SET frozen=0")
            elif advance == "evict":
                for rev in range(3, 67):
                    invoke(peer, control(rev, "FREEZE"))
            elif advance == "APPROVE":
                invoke(peer, control(3, "UNFREEZE"))
                next_req = approval(peer, next_job, 4)
                peer.publish_baseline_source(config().scope_id, next_req, "reviewer", START)
            else:
                invoke(peer, control(3, advance))
        return value

    try:
        with monkeypatch.context() as patch:
            patch.setattr(bs._publication_transaction, "__exit__", boundary)
            if advance in ("evict", "digest", "receipt", "same-revision"):
                with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                    invoke(repo, request)
            else:
                result = invoke(repo, request)
                assert result.receipt.to_mapping() == json.loads(committed[0][5])
                assert result.scope == peer.get_baseline_scope(config().scope_id)
                if advance in ("REVOKE", "RETIRE"):
                    assert result.scope.active is None
        assert fired == [True]
        assert repo.get_baseline_scope(config().scope_id).control_revision >= 3
        if advance not in ("evict", "digest", "receipt"):
            assert invoke(repo, request).receipt.to_mapping() == json.loads(committed[0][5])
    finally:
        peer.close()


def test_actual_unique_collision_one_recovery_no_id_retry(adapter: Any, monkeypatch: Any) -> None:
    repo = adapter
    setup_references(repo, 0)
    original = invoke(repo, control(0, "FREEZE"))
    before = raw_state(repo)
    ids, lookups = [], []
    actual = bs._PublicationSQL.control_replay

    def identity() -> Any:
        ids.append(True)
        return uuid.UUID(original.receipt.operation_id)

    def lookup(db: Any, *args: Any, **kw: Any) -> Any:
        lookups.append(True)
        return actual(db, *args, **kw)

    with monkeypatch.context() as patch:
        patch.setattr(uuid, "uuid4", identity)
        patch.setattr(bs._PublicationSQL, "control_replay", lookup)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            invoke(repo, control(1, "RETIRE"))
    assert ids == [True] and raw_state(repo) == before
    assert len(lookups) == (0 if isinstance(repo, MemoryRepository) else 3)


def test_publication_first_readback_erased_by_actual_control(
    adapter: Any, monkeypatch: Any
) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory publication result is installed under one lock")
    setup_references(repo, 0)
    request = approval(repo, store_source(repo, 0), 0)
    peer = reopen(repo)
    actual = bs._publication_transaction.__exit__
    fired = []

    def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
        value = actual(owner, kind, error, tb)
        if owner.connection is repo.connection and owner.write and error is None:
            fired.append(True)
            invoke(peer, control(1, "REVOKE"))
        return value

    try:
        with monkeypatch.context() as patch:
            patch.setattr(bs._publication_transaction, "__exit__", boundary)
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert fired == [True]
        result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert not result.created and result.receipt.revision == 1
        assert result.scope.state == "REVOKED" and result.scope.active is None
    finally:
        peer.close()


def test_supported_readers_wait_through_control_install(adapter: Any, monkeypatch: Any) -> None:
    from threading import Event, get_ident

    repo = adapter
    view, _, _ = setup_references(repo)
    entered, release, reader_attempt = Event(), Event(), Event()
    real_lock = repo._lock
    owner_thread = []
    results = []

    class Lock:
        def __enter__(self) -> Any:
            if owner_thread and get_ident() != owner_thread[0]:
                reader_attempt.set()
            return real_lock.__enter__()

        def __exit__(self, *args: Any) -> Any:
            return real_lock.__exit__(*args)

    repo._lock = Lock()
    actual = bs.memory_control if isinstance(repo, MemoryRepository) else bs._PublicationSQL.control

    def paused(*args: Any, **kw: Any) -> Any:
        value = actual(*args, **kw)
        entered.set()
        assert release.wait(20)
        return value

    def writer() -> Any:
        owner_thread.append(get_ident())
        return invoke(repo, control(view.control_revision, "REVOKE"))

    def reader() -> Any:
        result = repo.get_baseline_scope(config().scope_id)
        results.append(result)
        return result

    try:
        with monkeypatch.context() as patch:
            if isinstance(repo, MemoryRepository):
                patch.setattr(bs, "memory_control", paused)
            else:
                patch.setattr(bs._PublicationSQL, "control", paused)
            with ThreadPoolExecutor(max_workers=2) as pool:
                writing = pool.submit(writer)
                assert entered.wait(10)
                reading = pool.submit(reader)
                assert reader_attempt.wait(10) and not results
                release.set()
                result = writing.result(30)
                assert reading.result(30) == result.scope
    finally:
        release.set()
        repo._lock = real_lock
