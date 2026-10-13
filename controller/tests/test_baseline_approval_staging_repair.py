"""Remaining staging, DDL and generated-ID collision acceptance."""

import copy
import inspect
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from uuid import UUID, uuid4

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_baseline_approval_contract import prepare
from tests.test_baseline_approval_lifecycle_repair import full_snapshot
from tests.test_baseline_approval_oracle_repair import repo as repo_fixture
from tests.test_baseline_approval_retention import publish
from tests.test_baseline_scope_faults import receipt
from tests.test_historical_source import START, config

repo = repo_fixture


def memory_seed(repo: Any) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    publish(repo, 0)
    request, second = publish(repo, 1)
    for revision in range(3, 65):
        req = request.model_copy(
            update={"expected_revision": revision - 1, "idempotency_key": f"seed-{revision}"}
        )
        rec = second.receipt.model_copy(update={"revision": revision, "operation_id": str(uuid4())})
        digest = bs.approval_arguments(config().scope_id, req, "reviewer", START)[3]
        repo._baseline_operations[(config().scope_id, req.idempotency_key)] = bs._operation_row(
            config().scope_id, req, digest, rec
        )
    repo._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
        dict(second.scope.to_mapping(), control_revision=64)
    )


@pytest.mark.parametrize(
    "point",
    [
        "scope",
        "canonical",
        "hash",
        "generation-hash",
        "prune-sort",
        "verify-scope",
        "verify-operation",
    ],
)
def test_memory_additional_staging_occurrences(monkeypatch: Any, point: str) -> None:
    repo = MemoryRepository()
    memory_seed(repo)
    request = prepare(repo, 64)
    attrs = (
        "_baseline_scopes",
        "_baseline_generations",
        "_baseline_operations",
        "jobs",
        "candidates",
        "audit_events",
    )
    refs = tuple(getattr(repo, name) for name in attrs)
    before = copy.deepcopy(refs)
    target, name = {
        "scope": (g.ScopeView, "__init__"),
        "canonical": (bs.h, "canonical_json"),
        "hash": (bs.hashlib, "sha256"),
        "generation-hash": (bs.hashlib, "sha256"),
        "prune-sort": (bs, "sorted"),
        "verify-scope": (bs, "memory_get"),
        "verify-operation": (bs, "_operation"),
    }[point]
    actual = getattr(target, name, sorted)
    marker = TypeError("staging marker")
    inventory = []
    fired = []

    def scoped(args: Any) -> bool:
        frame = inspect.currentframe().f_back.f_back
        if point == "scope":
            return frame.f_code.co_name == "_stage_publication"
        if point == "generation-hash":
            return (
                frame.f_code.co_name == "generation_view"
                and frame.f_back.f_code.co_name == "_stage_publication"
            )
        if point in {"canonical", "hash"}:
            return frame.f_code.co_name == "_operation_row"
        if point == "verify-scope":
            return frame.f_code.co_name == "memory_publish" and args[0] is not refs[0]
        return frame.f_code.co_name == "memory_publish"

    def record(*args: Any, **kw: Any) -> Any:
        if scoped(args):
            inventory.append(True)
        return actual(*args, **kw)

    with monkeypatch.context() as patch:
        patch.setattr(target, name, record, raising=False)
        # Execute preparation only, with actual admitted source and staging. No installation.
        bs.memory_publish(
            *refs[:3],
            repo.jobs,
            repo.candidates,
            config().scope_id,
            request,
            "reviewer",
            START,
            bs.approval_arguments(config().scope_id, request, "reviewer", START)[3],
        )
    assert inventory
    for occurrence in range(len(inventory)):
        count = []

        def fail(*args: Any, count: list = count, occurrence: int = occurrence, **kw: Any) -> Any:
            if scoped(args):
                count.append(True)
                if len(count) - 1 == occurrence:
                    fired.append(occurrence)
                    raise marker
            return actual(*args, **kw)

        with monkeypatch.context() as patch:
            patch.setattr(target, name, fail, raising=False)
            with pytest.raises(TypeError) as caught:
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
            assert caught.value is marker
        assert tuple(getattr(repo, name) for name in attrs) == before
        assert all(getattr(repo, name) is ref for name, ref in zip(attrs, refs, strict=True))
    assert fired == list(range(len(inventory)))
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert (
            pool.submit(repo.publish_baseline_source, config().scope_id, request, "reviewer", START)
            .result(30)
            .created
        )
    assert len(repo._baseline_generations) == 2 and len(repo._baseline_operations) == 64
    receipt(
        dict(
            backend="memory",
            staging=point,
            occurrences=len(inventory),
            fired=len(fired),
            prestate=True,
            cross_thread_reuse=True,
        )
    )


@pytest.mark.parametrize("pointer", ["active", "previous"])
def test_generation_collision_no_reallocation(repo: Any, monkeypatch: Any, pointer: str) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    publish(repo, 0)
    _, result = publish(repo, 1)
    request = prepare(repo, 2)
    ids = [uuid4(), UUID(getattr(result.scope, pointer).generation_id)]
    allocated = []

    def identity() -> Any:
        allocated.append(True)
        return ids[len(allocated) - 1]

    monkeypatch.setattr("uuid.uuid4", identity)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert allocated == [True, True]
    assert repo.get_baseline_scope(config().scope_id) == result.scope


@pytest.mark.parametrize("target_index", [0, 1, 2, 3])
def test_sqlite_each_operation_ddl_table_index_failure(
    tmp_path: Any, monkeypatch: Any, target_index: int
) -> None:
    path = tmp_path / "ddl.sqlite"
    old = SQLiteRepository(path)
    old.create_baseline_scope(config(), "admin", START)
    publish(old, 0)
    old.connection.execute("DROP TABLE baseline_operations")
    old.connection.commit()
    before = full_snapshot(old)
    old.close()
    actual = sqlite3.connect
    events, opened, fired = [], [], []

    def connect(*args: Any, **kw: Any) -> Any:
        con = actual(*args, **kw)
        opened.append(con)

        def authorize(action: int, first: str, second: str, *_: Any) -> int:
            if (action == sqlite3.SQLITE_CREATE_TABLE and first == "baseline_operations") or (
                action == sqlite3.SQLITE_CREATE_INDEX and second == "baseline_operations"
            ):
                events.append((action, first, second))
                if len(events) - 1 == target_index:
                    fired.append(True)
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        con.set_authorizer(authorize)
        return con

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", connect)
        with pytest.raises(sqlite3.DatabaseError):
            SQLiteRepository(path)
    assert fired == [True] and len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute("SELECT 1")
    assert full_snapshot(old) == before
    reopened = SQLiteRepository(path)
    try:
        assert reopened.get_baseline_scope(config().scope_id).control_revision == 1
        after = full_snapshot(reopened)
        assert tuple(item for item in after if item[0] != "baseline_operations") == before
        indexes = reopened.connection.execute("PRAGMA index_list(baseline_operations)").fetchall()
        assert len(indexes) == 3 and all(row[2] == 1 for row in indexes)
        assert reopened.connection.execute(
            "SELECT count(*) FROM baseline_operations"
        ).fetchone() == (0,)
    finally:
        reopened.close()
    receipt(
        dict(
            backend="sqlite",
            ddl=events[-1],
            occurrence=target_index,
            fired=1,
            prior_full_snapshot=True,
            closed=True,
            reopen=True,
        )
    )
