"""Defensive corruption/MAX seeds are not public billion-operation histories."""

import hashlib
import json
import uuid
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.publication_fixtures import publication_adapter
from tests.test_baseline_approval_transaction_repair import independent
from tests.test_baseline_control_storage import control, invoke, raw_state, setup_references
from tests.test_historical_source import config

adapter = publication_adapter


def replace_operation(repo: Any, row: tuple) -> None:
    if isinstance(repo, MemoryRepository):
        repo._baseline_operations[(row[0], row[2])] = row
    else:
        with independent(repo) as con:
            marker = "?" if isinstance(repo, SQLiteRepository) else "%s"
            con.execute(
                "DELETE FROM baseline_operations WHERE scope_id="
                + marker
                + " AND idempotency_key="
                + marker,
                (row[0], row[2]),
            )
            con.execute(
                "INSERT INTO baseline_operations VALUES(" + ",".join([marker] * 8) + ")", row
            )


def operation_rows(repo: Any) -> list[tuple]:
    raw = raw_state(repo)[2]
    return sorted(raw.values() if isinstance(raw, dict) else raw, key=lambda row: row[1])


@pytest.mark.parametrize(
    "mutation",
    [
        "actor",
        "revision",
        "target",
        "action",
        "hybrid",
        "digest",
        "hash",
        "size",
        "duplicate",
        "depth",
        "json",
        "4096",
    ],
)
def test_stored_control_corruption_and_conflict_precedence(adapter: Any, mutation: str) -> None:
    repo = adapter
    setup_references(repo, 0)
    req = control(0, "FREEZE")
    result = invoke(repo, req)
    row = list(operation_rows(repo)[0])
    value = result.receipt.to_mapping()
    if mutation in ("actor", "revision", "target", "action", "hybrid"):
        if mutation == "actor":
            value["actor"] = "foreign"
        elif mutation == "revision":
            value["revision"] = row[1] = 2
        elif mutation == "target":
            value["generation_id"] = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
        elif mutation == "action":
            value["action"] = "unknown"
        else:
            value.update(source_job_id="extra", source_binding_sha256="0" * 64)
        row[5] = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    elif mutation == "digest":
        row[3] = "0" * 64
    elif mutation == "duplicate":
        row[5] = row[5][:-1] + ',"action":"FREEZE"}'
    elif mutation == "depth":
        row[5] = "[" * 17 + "0" + "]" * 17
    elif mutation == "json":
        row[5] = "{"
    elif mutation == "4096":
        row[5] = '"' + "x" * 4094 + '"'
    row[6] = hashlib.sha256(row[5].encode()).hexdigest()
    row[7] = len(row[5].encode())
    if mutation == "hash":
        row[6] = "0" * 64
    if mutation == "size":
        row[7] += 1
    replace_operation(repo, tuple(row))
    before = raw_state(repo)
    expected = (
        "BASELINE_IDEMPOTENCY_CONFLICT" if mutation == "digest" else "BASELINE_STORAGE_UNAVAILABLE"
    )
    with pytest.raises(bs.BaselineStorageError, match="^" + expected + "$"):
        invoke(repo, req)
    # Page has no original request; actor/digest changes are not detectable there.
    if mutation not in ("actor", "digest"):
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.page_baseline_control_events(config().scope_id)
    assert raw_state(repo) == before


def test_page_hidden_payload_is_not_scanned(adapter: Any) -> None:
    repo = adapter
    view, _, _ = setup_references(repo, 0)
    for _ in range(21):
        view = invoke(repo, control(view.control_revision, "FREEZE")).scope
    row = list(operation_rows(repo)[0])
    row[5] = "{"
    replace_operation(repo, tuple(row))
    page = repo.page_baseline_control_events(config().scope_id, 0, 20)
    assert len(page.items) == 20 and page.total == 21 and page.earliest_retained_revision == 1
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.page_baseline_control_events(config().scope_id, 20, 20)


@pytest.mark.parametrize(
    "offset,limit", [(True, 1), (1.0, 1), ("0", 1), (-1, 1), (65, 1), (0, False), (0, 0), (0, 21)]
)
def test_page_input_before_any_owner(
    adapter: Any, monkeypatch: Any, offset: Any, limit: Any
) -> None:
    def forbidden(*args: Any, **kw: Any) -> Any:
        raise AssertionError("owner admitted invalid page")

    monkeypatch.setattr(bs, "publication_connection", forbidden)
    monkeypatch.setattr(bs, "memory_events", forbidden)
    with pytest.raises(ValueError) as caught:
        adapter.page_baseline_control_events(config().scope_id, offset, limit)
    assert not isinstance(caught.value, bs.BaselineStorageError)


def test_revision_saturation_is_defensive_and_replay_precedes_it(
    adapter: Any, monkeypatch: Any
) -> None:
    repo = adapter
    setup_references(repo, 0)
    req = control(0, "FREEZE")
    original = invoke(repo, req)
    if isinstance(repo, MemoryRepository):
        repo._baseline_scopes[config().scope_id] = original.scope.model_copy(
            update={"control_revision": 2**63 - 1}
        )
    else:
        with independent(repo) as con:
            con.execute("UPDATE baseline_scopes SET control_revision=9223372036854775807")
    before = raw_state(repo)

    def forbidden(*args: Any, **kw: Any) -> Any:
        raise AssertionError("UUID before cap")

    monkeypatch.setattr(uuid, "uuid4", forbidden)
    assert invoke(repo, req).receipt == original.receipt
    for revision, code in (
        (0, "BASELINE_REVISION_CONFLICT"),
        (2**63 - 1, "BASELINE_CONTROL_LIMIT"),
    ):
        with pytest.raises(bs.BaselineStorageError, match="^" + code + "$"):
            invoke(
                repo, control(revision, "ROLLBACK", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "new")
            )
    assert raw_state(repo) == before


def test_target_mismatch_and_rollback_consumption(adapter: Any) -> None:
    repo = adapter
    view, _, results = setup_references(repo)
    before = raw_state(repo)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_GENERATION_MISMATCH$"):
        invoke(repo, control(view.control_revision, "ROLLBACK", results[1].receipt.generation_id))
    assert raw_state(repo) == before
    req = control(view.control_revision, "ROLLBACK", results[0].receipt.generation_id)
    result = invoke(repo, req)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_ROLLBACK_UNAVAILABLE$"):
        invoke(
            repo,
            control(result.scope.control_revision, "ROLLBACK", results[1].receipt.generation_id),
        )
    erased = invoke(repo, control(result.scope.control_revision, "REVOKE"))
    replay = invoke(repo, req)
    assert replay.receipt == result.receipt and replay.scope == erased.scope


@pytest.mark.parametrize("fault", ["count65", "4097", "current-doc"])
def test_defensive_storage_gates_no_success_prefix(
    adapter: Any, monkeypatch: Any, fault: str
) -> None:
    repo = adapter
    view, _, _ = setup_references(repo, 2 if fault == "current-doc" else 0)
    request = control(view.control_revision, "FREEZE")
    invoke(repo, request)
    row = operation_rows(repo)[-1]
    if fault == "current-doc":
        if isinstance(repo, MemoryRepository):
            del repo._baseline_generations[(config().scope_id, view.previous.generation_id)]
        else:
            with independent(repo) as con:
                marker = "?" if isinstance(repo, SQLiteRepository) else "%s"
                con.execute(
                    "DELETE FROM baseline_generations WHERE generation_id=" + marker,
                    (view.previous.generation_id,),
                )
        # A normal changed digest wins before current corrupt scope decode.
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_IDEMPOTENCY_CONFLICT$"):
            invoke(repo, request.model_copy(update={"reason": "changed"}))
    elif fault == "count65":
        for revision in range(2, 66):
            new = list(row)
            new[1], new[2], new[4] = revision, f"corrupt-{revision}", str(uuid.uuid4())
            replace_operation(repo, tuple(new))
    else:
        new = list(row)
        new[5], new[7] = "x" * 4097, 4096
        if isinstance(repo, MemoryRepository):
            replace_operation(repo, tuple(new))
        else:
            with independent(repo) as con:
                if isinstance(repo, SQLiteRepository):
                    con.execute("PRAGMA ignore_check_constraints=ON")
                    con.execute("UPDATE baseline_operations SET receipt_json=?", (new[5],))
                else:
                    from psycopg import sql

                    names = con.execute(
                        "SELECT conname FROM pg_constraint "
                        "WHERE conrelid='baseline_operations'::regclass AND contype='c' "
                        "AND pg_get_constraintdef(oid) LIKE '%receipt_json%'"
                    ).fetchall()
                    assert len(names) == 1
                    con.execute(
                        sql.SQL("ALTER TABLE baseline_operations DROP CONSTRAINT {}").format(
                            sql.Identifier(names[0][0])
                        )
                    )
                    con.execute("UPDATE baseline_operations SET receipt_json=%s", (new[5],))
    before = raw_state(repo)
    decoded = []
    actual = bs._operation_envelope

    def decode(*args: Any, **kw: Any) -> Any:
        decoded.append(True)
        return actual(*args, **kw)

    with monkeypatch.context() as patch:
        patch.setattr(bs, "_operation_envelope", decode)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.page_baseline_control_events(config().scope_id)
    if fault == "count65" or not isinstance(repo, MemoryRepository):
        assert decoded == []
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        invoke(repo, request)
    assert raw_state(repo) == before


def test_fresh_controls_have_no_source_dependencies(adapter: Any, monkeypatch: Any) -> None:
    from c2hunter_controller import historical_generation as g
    from c2hunter_controller import historical_read as r

    repo = adapter
    view, _, _ = setup_references(repo)
    fired = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        fired.append(True)
        raise AssertionError("forbidden dependency")

    with monkeypatch.context() as patch:
        for name in ("_memory_acquire", "_sqlite_acquire", "_postgres_acquire"):
            patch.setattr(r, name, forbidden)
        patch.setattr(g, "produce_generation", forbidden)
        for name in ("get_job", "save_job", "get_candidates", "_put", "_audit"):
            if hasattr(repo, name):
                patch.setattr(repo, name, forbidden)
        for action in ("FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE"):
            req = control(
                view.control_revision,
                action,
                view.previous.generation_id if action == "ROLLBACK" else None,
            )
            view = invoke(repo, req).scope
            repo.page_baseline_control_events(config().scope_id)
        assert fired == []
        with pytest.raises(AssertionError, match="forbidden dependency"):
            repo.get_job("positive-wiring")
    assert fired == [True]
