"""Bounded retained operations and source manifests via real publications."""

import hashlib
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as r
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


def publish(repo: Any, index: int) -> tuple:
    request = fixtures.prepare(repo, index)
    return request, repo.publish_baseline_source(config().scope_id, request, "reviewer", START)


def operations(repo: Any) -> list:
    if isinstance(repo, MemoryRepository):
        return sorted(repo._baseline_operations.values(), key=lambda row: row[1])
    with bs._publication_transaction(
        repo.connection, postgres=isinstance(repo, PostgresRepository)
    ) as cursor:
        return (
            bs._SQL(cursor, isinstance(repo, PostgresRepository))
            .execute(
                "SELECT scope_id,revision,idempotency_key,request_sha256,"
                "operation_id,receipt_json,receipt_sha256,receipt_byte_size "
                "FROM baseline_operations ORDER BY revision"
            )
            .fetchall()
        )


def test_retained_replay_after_source_and_generation_loss(
    approval_repo: Any, monkeypatch: Any
) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request, first = publish(repo, 0)
    _, second = publish(repo, 1)
    _, third = publish(repo, 2)
    assert third.scope.previous == second.scope.active
    repo.delete_job(request.source_job_id)
    before = operations(repo)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("retained replay accessed source/producer/IDs")

    for name in ("_memory_acquire", "_sqlite_acquire", "_postgres_acquire"):
        monkeypatch.setattr(r, name, forbidden)
    monkeypatch.setattr(g, "produce_generation", forbidden)
    monkeypatch.setattr("uuid.uuid4", forbidden)
    replay = repo.publish_baseline_source(
        config().scope_id, request, "reviewer", START + timedelta(days=2)
    )
    assert not replay.created and replay.receipt == first.receipt and replay.scope == third.scope
    assert operations(repo) == before
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_GENERATION_RETIRED$"):
        repo.page_baseline_sources(config().scope_id, first.receipt.generation_id)
    page = repo.page_baseline_sources(config().scope_id, third.receipt.generation_id, 1, 1)
    assert (
        page.total == 3
        and page.next_offset == 2
        and page.items[0].source_receipt_id == second.receipt.operation_id
    )
    assert (
        repo.page_baseline_sources(config().scope_id, third.receipt.generation_id, 16, 20).items
        == ()
    )


def test_operation_retention_64_65(approval_repo: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    first_request, first = publish(repo, 0)
    for index in range(1, 65):
        _, result = publish(repo, index)
        rows = operations(repo)
        assert [row[1] for row in rows] == list(range(max(1, index - 62), index + 2))
        assert result.scope.control_revision == index + 1
    assert len(rows) == 64 and rows[0][1] == 2
    assert repo.page_baseline_sources(config().scope_id, result.receipt.generation_id).total == 16
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_REVISION_CONFLICT$"):
        repo.publish_baseline_source(config().scope_id, first_request, "reviewer", START)
    repo.delete_job(first_request.source_job_id)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_SOURCE_NOT_FOUND$"):
        repo.publish_baseline_source(config().scope_id, first_request, "reviewer", START)
    assert operations(repo) == rows


@pytest.mark.parametrize(
    "mutation",
    [
        "actor",
        "source",
        "binding",
        "revision",
        "request-digest",
        "unknown-action",
        "json",
        "size",
        "hash",
    ],
)
def test_operation_linkage_corruption(approval_repo: Any, mutation: str) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request, result = publish(repo, 0)
    row = list(operations(repo)[0])
    value = result.receipt.to_mapping()
    if mutation in ("actor", "source", "binding", "revision", "unknown-action"):
        field, change = {
            "actor": ("actor", "other"),
            "source": ("source_job_id", "other"),
            "binding": ("source_binding_sha256", "0" * 64),
            "revision": ("revision", 2),
            "unknown-action": ("action", "FREEZE"),
        }[mutation]
        value[field] = change
        if mutation == "revision":
            row[1] = 2
        row[5] = h.canonical_json(value)
    elif mutation == "request-digest":
        row[3] = "0" * 64
    elif mutation == "json":
        row[5] = "{}"
    row[6] = hashlib.sha256(row[5].encode()).hexdigest()
    row[7] = len(row[5].encode())
    if mutation == "size":
        row[7] += 1
    if mutation == "hash":
        row[6] = "0" * 64
    if isinstance(repo, MemoryRepository):
        repo._baseline_operations[(config().scope_id, request.idempotency_key)] = tuple(row)
    else:
        pg = isinstance(repo, PostgresRepository)
        with bs.transaction(repo.connection, postgres=pg, write=True) as cursor:
            db = bs._SQL(cursor, pg)
            db.execute("DELETE FROM baseline_operations")
            db.execute("INSERT INTO baseline_operations VALUES(?,?,?,?,?,?,?,?)", tuple(row))
    expected = (
        "BASELINE_IDEMPOTENCY_CONFLICT"
        if mutation == "request-digest"
        else "BASELINE_STORAGE_UNAVAILABLE"
    )
    with pytest.raises(bs.BaselineStorageError, match="^" + expected + "$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)


@pytest.mark.parametrize(
    "offset,limit", [(True, 1), (1.0, 1), (-1, 1), (17, 1), (0, False), (0, 0), (0, 21), ("0", 20)]
)
def test_page_arguments_before_query(
    approval_repo: Any, offset: Any, limit: Any, monkeypatch: Any
) -> None:
    def forbidden(*a: Any, **kw: Any) -> Any:
        raise AssertionError("query before input admission")

    monkeypatch.setattr(bs, "memory_get", forbidden)
    monkeypatch.setattr(bs._SQL, "execute", forbidden)
    with pytest.raises(ValueError) as caught:
        approval_repo.page_baseline_sources(config().scope_id, str(uuid4()), offset, limit)
    assert not isinstance(caught.value, bs.BaselineStorageError)
