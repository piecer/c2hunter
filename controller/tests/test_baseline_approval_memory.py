"""Memory prepares every value before replacing any supported-state reference."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any
from uuid import uuid4

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_approval_contract import prepare
from tests.test_baseline_approval_retention import publish
from tests.test_historical_source import START, config


@pytest.mark.parametrize(
    "boundary", ["producer", "serializer", "receipt", "result", "operation", "final-state"]
)
def test_memory_staging_faults(monkeypatch: Any, boundary: str) -> None:
    repo = MemoryRepository()
    repo.create_baseline_scope(config(), "admin", START)
    publish(repo, 0)
    request, second = publish(repo, 1)
    for revision in range(3, 65):
        req = g.ApprovalRequest.from_mapping(
            dict(
                request.to_mapping(),
                expected_revision=revision - 1,
                idempotency_key=f"seed-{revision}",
            )
        )
        rec = g.ApprovalReceipt.from_mapping(
            dict(second.receipt.to_mapping(), revision=revision, operation_id=str(uuid4()))
        )
        digest = bs.approval_arguments(config().scope_id, req, "reviewer", START)[3]
        repo._baseline_operations[(config().scope_id, req.idempotency_key)] = bs._operation_row(
            config().scope_id, req, digest, rec
        )
    repo._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
        dict(second.scope.to_mapping(), control_revision=64)
    )
    request = prepare(repo, 64)
    refs = (
        repo._baseline_scopes,
        repo._baseline_generations,
        repo._baseline_operations,
        repo.jobs,
        repo.candidates,
        repo.audit_events,
    )
    copies = tuple(value.copy() for value in refs)
    marker = TypeError("owned staging boundary")
    fired = []

    def fail(*args: Any, **kw: Any) -> Any:
        fired.append(True)
        raise marker

    with monkeypatch.context() as guard:
        if boundary == "final-state":
            actual = bs.memory_publish

            def final(*args: Any, **kw: Any) -> Any:
                actual(*args, **kw)
                return fail()

            guard.setattr(bs, "memory_publish", final)
        elif boundary == "serializer":
            import sys

            actual_json = g.generation_json

            def serialize(*args: Any, **kw: Any) -> Any:
                if sys._getframe(1).f_code.co_name == "_stage_publication":
                    return fail()
                return actual_json(*args, **kw)

            guard.setattr(g, "generation_json", serialize)
        else:
            module, name = {
                "producer": (g, "produce_generation"),
                "receipt": (g, "approval_receipt"),
                "result": (g, "PublicationResult"),
                "operation": (bs, "_operation_row"),
            }[boundary]
            guard.setattr(module, name, fail)
        with pytest.raises(TypeError) as caught:
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert caught.value is marker and fired == [True]
    assert all(
        a is b
        for a, b in zip(
            refs,
            (
                repo._baseline_scopes,
                repo._baseline_generations,
                repo._baseline_operations,
                repo.jobs,
                repo.candidates,
                repo.audit_events,
            ),
            strict=True,
        )
    )
    assert tuple(refs) == copies
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert (
            pool.submit(repo.publish_baseline_source, config().scope_id, request, "reviewer", START)
            .result(30)
            .created
        )
    assert len(repo._baseline_operations) == 64 and len(repo._baseline_generations) == 2
