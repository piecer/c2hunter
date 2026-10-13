"""Closed mixed-ledger boundary; seeded rows are defensive, not control execution."""

import hashlib

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_baseline as h
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_approval_contract import prepare
from tests.test_historical_source import START, config


def test_mixed_receipt_conflict_is_not_approval_corruption() -> None:
    repo = MemoryRepository()
    repo.create_baseline_scope(config(), "admin", START)
    request = prepare(repo)
    result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    key = (config().scope_id, request.idempotency_key)
    row = list(repo._baseline_operations[key])
    receipt = result.receipt.to_mapping()
    del receipt["source_job_id"], receipt["source_binding_sha256"]
    receipt.update(action="FREEZE", generation_id=None)
    raw = h.canonical_json(receipt)
    row[3], row[5], row[6], row[7] = (
        "0" * 64,
        raw,
        hashlib.sha256(raw.encode()).hexdigest(),
        len(raw.encode()),
    )
    repo._baseline_operations[key] = tuple(row)
    with pytest.raises(bs.BaselineStorageError) as caught:
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert caught.value.code == "BASELINE_IDEMPOTENCY_CONFLICT"


def test_repository_declares_complete_control_protocol() -> None:
    import inspect

    from c2hunter_controller.production import PostgresRepository
    from c2hunter_controller.repositories import Repository, SQLiteRepository

    for name in ("control_baseline_scope", "page_baseline_control_events"):
        expected = inspect.signature(getattr(Repository, name))
        for cls in (MemoryRepository, SQLiteRepository, PostgresRepository):
            assert inspect.signature(getattr(cls, name)) == expected


@pytest.mark.parametrize(
    "action,request_bytes,receipt_bytes",
    [
        ("FREEZE", 2961, 980),
        ("UNFREEZE", 2963, 982),
        ("ROLLBACK", 2997, 1016),
        ("REVOKE", 2961, 980),
        ("RETIRE", 2961, 980),
    ],
)
def test_actual_control_maxima_and_fingerprint(
    action: str, request_bytes: int, receipt_bytes: int
) -> None:
    import json

    from c2hunter_controller import historical_generation as g

    target = "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB" if action == "ROLLBACK" else None
    req = g.ControlRequest(
        expected_revision=2**63 - 1,
        idempotency_key="😀" * 200,
        action=action,
        reason="😀" * 512,
        generation_id=target,
    )
    receipt = g.ControlReceipt(
        operation_id="ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB",
        action=action,
        revision=2**63 - 1,
        actor="😀" * 200,
        occurred_at=START,
        generation_id=target,
    )

    def canonical(value: object) -> bytes:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode()

    assert len(canonical(req.to_mapping())) == request_bytes
    assert len(canonical(receipt.to_mapping())) == receipt_bytes
    expected = hashlib.sha256(
        canonical(
            dict(
                action=action,
                scope_id=config().scope_id,
                actor="operator",
                request=req.to_mapping(),
            )
        )
    ).hexdigest()
    assert bs.control_arguments(config().scope_id, req, "operator", START)[3] == expected
    assert req.generation_id == target
    assert g.ControlReceipt.model_validate_json(canonical(receipt.to_mapping())) == receipt


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_revision", True),
        ("expected_revision", 1.0),
        ("expected_revision", "1"),
        ("expected_revision", -1),
        ("expected_revision", 2**63),
        ("idempotency_key", "a" * 201),
        ("reason", "a" * 513),
        ("action", "freeze"),
        ("action", "APPROVE"),
        ("generation_id", "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB"),
        ("actor", "body actor"),
    ],
)
def test_request_closed_admission(field: str, value: object) -> None:
    from c2hunter_controller import historical_generation as g

    raw = dict(
        expected_revision=0, idempotency_key="k", action="FREEZE", reason="r", generation_id=None
    )
    raw[field] = value
    with pytest.raises(ValueError):
        g.ControlRequest.model_validate(raw)


def test_required_null_and_mixed_union_before_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    from c2hunter_controller import historical_generation as g

    raw = dict(
        expected_revision=0, idempotency_key="k", action="FREEZE", reason="r", generation_id=None
    )
    for field in raw:
        incomplete = dict(raw)
        del incomplete[field]
        with pytest.raises(ValueError):
            g.ControlRequest.model_validate(incomplete)
    with pytest.raises(ValueError):
        g.ControlRequest.model_validate(dict(raw, action="ROLLBACK"))
    receipt = dict(
        operation_id="ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB",
        action="FREEZE",
        revision=1,
        actor="a",
        occurred_at=START,
        generation_id=None,
    )
    valid = g.ControlReceipt.model_validate(receipt)
    raw_page = dict(
        items=(valid,), total=1, offset=0, limit=20, next_offset=None, earliest_retained_revision=1
    )
    assert g.ControlPage.model_validate(raw_page).items == (valid,)
    calls = []

    def forbidden(*args: object, **kwargs: object) -> object:
        calls.append(True)
        raise AssertionError("copy before admission")

    with monkeypatch.context() as patch:
        patch.setattr(g, "_unmodel", forbidden)
        for item in (
            dict(receipt, source_job_id="hybrid", source_binding_sha256="0" * 64),
            dict(receipt, action="UNKNOWN"),
            valid.model_copy(update={"actor": object()}),
        ):
            with pytest.raises(ValueError):
                g.ControlPage.model_validate(dict(raw_page, items=(item,)))
        for req in (dict(raw, reason="x" * 513), dict(raw, actor=object())):
            with pytest.raises(ValueError):
                g.ControlRequest.model_validate(req)
    assert calls == []
