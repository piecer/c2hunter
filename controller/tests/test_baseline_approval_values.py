"""Stored-envelope byte gates, immutable DTOs, and Memory map admission."""

import hashlib
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_baseline_approval_retention import publish
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


@pytest.mark.parametrize("extra", [0, 1])
def test_actual_receipt_bytes_before_decode(
    approval_repo: Any, monkeypatch: Any, extra: int
) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request, _ = publish(repo, 0)
    raw = '{"unknown":"' + "x" * (4096 + extra - len('{"unknown":""}')) + '"}'
    assert len(raw.encode()) == 4096 + extra
    digest = hashlib.sha256(raw.encode()).hexdigest()
    if isinstance(repo, MemoryRepository):
        key = (config().scope_id, request.idempotency_key)
        row = list(repo._baseline_operations[key])
        row[5:] = [raw, digest, min(4096, len(raw.encode()))]
        repo._baseline_operations[key] = tuple(row)
    else:
        con = repo.connection
        pg = hasattr(repo, "database_url")
        if pg:
            from psycopg import sql

            checks = con.execute(
                "SELECT conname,pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid='baseline_operations'::regclass AND contype='c'"
            ).fetchall()
            for name, definition in checks:
                if "octet_length(receipt_json)" in definition:
                    con.execute(
                        sql.SQL("ALTER TABLE baseline_operations DROP CONSTRAINT {}").format(
                            sql.Identifier(name)
                        )
                    )
        else:
            con.execute("PRAGMA ignore_check_constraints=ON")
        con.execute(
            "UPDATE baseline_operations SET receipt_json="
            + (
                "%s,receipt_sha256=%s,receipt_byte_size=%s"
                if pg
                else "?,receipt_sha256=?,receipt_byte_size=?"
            ),
            (raw, digest, min(4096, len(raw.encode()))),
        )
        con.commit()
    called = []
    original = g.ApprovalReceipt.model_validate_json

    def decode(*args: Any, **kw: Any) -> Any:
        called.append(True)
        return original(*args, **kw)

    monkeypatch.setattr(g.ApprovalReceipt, "model_validate_json", decode)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert len(called) == (0 if extra else 1)


@pytest.mark.parametrize("bad_key", [(), ("x",), 7])
def test_memory_malformed_operation_key(bad_key: Any) -> None:
    repo = MemoryRepository()
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    repo._baseline_operations[bad_key] = ()
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)


def test_result_and_source_page_closed(approval_repo: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    _, result = publish(repo, 0)
    page = repo.page_baseline_sources(config().scope_id, result.receipt.generation_id)
    for value in (result, page):
        cls = type(value)
        assert cls.from_mapping(value.to_mapping()) == value
        with pytest.raises(ValueError):
            cls.from_mapping(dict(value.to_mapping(), unknown=0))
        for field in cls.model_fields:
            raw = value.to_mapping()
            del raw[field]
            with pytest.raises(ValueError):
                cls.from_mapping(raw)
        with pytest.raises(ValueError):
            value.model_validate(value.model_copy(update={"unknown": object()}))
    with pytest.raises(ValueError):
        result.receipt.actor = "changed"
    with pytest.raises(ValueError):
        page.items[0].quality_review.note = "changed"
    with pytest.raises(ValueError):
        g.PublicationResult.from_mapping(dict(result.to_mapping(), created=1))
