"""Actual eight-operation consumers; source setup and raw oracles stay outside."""

from datetime import datetime, timedelta
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.publication_fixtures import publication_adapter
from tests.test_baseline_approval_transaction_repair import independent
from tests.test_historical_source import START, config, review, stored

adapter = publication_adapter
METHODS = (
    "create_baseline_scope",
    "get_baseline_scope",
    "page_baseline_scopes",
    "preview_baseline_source",
    "publish_baseline_source",
    "page_baseline_sources",
    "control_baseline_scope",
    "page_baseline_control_events",
)


class Consumer:
    """Expose only the accepted eight-method protocol, not fixture capabilities."""

    def __init__(self, repo: Any) -> None:
        for name in METHODS:
            setattr(self, name, getattr(repo, name))


def store_source(repo: Any, index: int) -> str:
    raw = stored()
    delta = timedelta(minutes=index * 2)
    raw.update(
        id=f"control-source-{index}",
        dataset_id=f"control-dataset-{index}",
        start_time=(START + delta).isoformat(),
        end_time=(START + delta + timedelta(seconds=60)).isoformat(),
    )
    for row in raw["flow_records"]:
        row["timestamp"] = (datetime.fromisoformat(row["timestamp"]) + delta).isoformat()
    repo.save_job(raw)
    return raw["id"]


def approval(repo: Any, job: str, revision: int) -> Any:
    preview = repo.preview_baseline_source(config().scope_id, job, revision, "APPROVAL")
    assert preview.admissible and preview.required_review == "EXPLICIT_NORMAL_AND_QUALITY_ASSERTION"
    return g.ApprovalRequest(
        expected_revision=revision,
        idempotency_key=f"approve-{job}",
        source_job_id=job,
        source_binding_sha256=preview.source_binding_sha256,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="Independent synthetic normality assertion",
    )


def control(revision: int, action: str, target: str | None = None, key: str | None = None) -> Any:
    return g.ControlRequest(
        expected_revision=revision,
        idempotency_key=key or f"{action}-{revision}",
        action=action,
        reason="Explicit synthetic control",
        generation_id=target,
    )


def invoke(repo: Any, request: Any) -> Any:
    return repo.control_baseline_scope(config().scope_id, request, "operator", START)


def raw_state(repo: Any) -> Any:
    if isinstance(repo, MemoryRepository):
        return (
            dict(repo._baseline_scopes),
            dict(repo._baseline_generations),
            dict(repo._baseline_operations),
        )
    with independent(repo) as con:
        return tuple(
            tuple(con.execute("SELECT * FROM " + table + " ORDER BY 1,2").fetchall())
            for table in ("baseline_scopes", "baseline_generations", "baseline_operations")
        )


def reopen(repo: Any) -> Any:
    peer = (
        SQLiteRepository(repo._path)
        if isinstance(repo, SQLiteRepository)
        else type(repo)(repo.database_url, None)
    )
    assert peer.connection is not repo.connection
    return peer


def test_actual_approval_control_replay_vertical(adapter: Any, monkeypatch: Any) -> None:
    repo = adapter
    jobs = [store_source(repo, index) for index in (0, 1, 10)]
    client = Consumer(repo)
    view, created = client.create_baseline_scope(config(), "admin", START)
    assert created and view.control_revision == 0
    assert client.page_baseline_scopes().items == (view,)
    requests = [approval(client, jobs[0], 0)]
    a = client.publish_baseline_source(config().scope_id, requests[0], "reviewer", START)
    requests.append(approval(client, jobs[1], 1))
    b = client.publish_baseline_source(config().scope_id, requests[1], "reviewer", START)
    page_a = client.page_baseline_sources(config().scope_id, a.receipt.generation_id)
    assert page_a.items[0].quality_review == review()
    assert b.scope.previous == a.scope.active
    if not isinstance(repo, MemoryRepository):
        peer = reopen(repo)
        try:
            assert peer.get_baseline_scope(config().scope_id) == b.scope
            assert peer.page_baseline_sources(config().scope_id, a.receipt.generation_id) == page_a
        finally:
            peer.close()
    receipts = [a.receipt, b.receipt]
    controls = []
    view = b.scope
    for action in ("FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE", "UNFREEZE"):
        req = control(
            view.control_revision, action, a.receipt.generation_id if action == "ROLLBACK" else None
        )
        result = invoke(client, req)
        assert result.receipt.generation_id == req.generation_id
        assert result.receipt.revision == view.control_revision + 1
        assert result.scope.accepted_event_end == b.scope.accepted_event_end
        if action == "ROLLBACK":
            assert result.scope.active == a.scope.active and result.scope.previous is None
            assert result.scope.frozen
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_GENERATION_RETIRED$"):
                client.page_baseline_sources(config().scope_id, b.receipt.generation_id)
        elif action in ("REVOKE", "RETIRE"):
            assert result.scope.active is result.scope.previous is None
            assert result.scope.state == ("REVOKED" if action == "REVOKE" else "RETIRED")
        controls.append((req, result.receipt))
        receipts.append(result.receipt)
        view = result.scope
        assert client.get_baseline_scope(config().scope_id) == view
        for original, receipt in zip(requests, (a.receipt, b.receipt), strict=True):
            replay = client.publish_baseline_source(
                config().scope_id, original, "reviewer", START + timedelta(days=1)
            )
            assert not replay.created and replay.receipt == receipt and replay.scope == view
        for original, receipt in controls:
            replay = invoke(client, original)
            assert replay.receipt == receipt and replay.scope == view
        page = client.page_baseline_control_events(config().scope_id)
        assert page.items == tuple(reversed(receipts))
        assert page.total == len(receipts) and page.earliest_retained_revision == 1
        assert (
            raw_state(repo)[1] == ()
            if not isinstance(repo, MemoryRepository)
            and action in ("REVOKE", "RETIRE", "UNFREEZE")
            and view.active is None
            else True
        )
    for job in jobs[:2]:
        repo.delete_job(job)
    import uuid

    from c2hunter_controller import historical_read as r

    fired = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        fired.append(True)
        raise AssertionError("forbidden retained dependency")

    before = raw_state(repo)
    with monkeypatch.context() as patch:
        for name in ("_memory_acquire", "_sqlite_acquire", "_postgres_acquire"):
            patch.setattr(r, name, forbidden)
        patch.setattr(g, "produce_generation", forbidden)
        patch.setattr(uuid, "uuid4", forbidden)
        for request, receipt in zip(requests, (a.receipt, b.receipt), strict=True):
            assert (
                client.publish_baseline_source(
                    config().scope_id, request, "reviewer", START
                ).receipt
                == receipt
            )
        for req, receipt in controls:
            assert invoke(client, req).receipt == receipt
        assert client.page_baseline_control_events(config().scope_id).items == tuple(
            reversed(receipts)
        )
        with pytest.raises(AssertionError, match="forbidden retained dependency"):
            client.preview_baseline_source(
                config().scope_id, jobs[2], view.control_revision, "APPROVAL"
            )
    assert fired == [True] and raw_state(repo) == before
    c_request = approval(client, jobs[2], view.control_revision)
    c = client.publish_baseline_source(config().scope_id, c_request, "reviewer", START)
    assert c.created and c.scope.previous is None and not c.scope.frozen
    assert c.scope.accepted_event_end > b.scope.accepted_event_end


def setup_references(repo: Any, count: int = 2) -> tuple[Any, list[Any], list[Any]]:
    view, _ = repo.create_baseline_scope(config(), "admin", START)
    requests, results = [], []
    for index in range(count):
        req = approval(repo, store_source(repo, index), view.control_revision)
        result = repo.publish_baseline_source(config().scope_id, req, "reviewer", START)
        requests.append(req)
        results.append(result)
        view = result.scope
    return view, requests, results


@pytest.mark.parametrize(
    "prior,count",
    [
        ("EMPTY", 0),
        ("HAS_REFERENCE", 1),
        ("HAS_REFERENCE", 2),
        ("REVOKED", 0),
        ("REVOKED", 1),
        ("RETIRED", 0),
        ("RETIRED", 1),
    ],
)
@pytest.mark.parametrize("frozen", [False, True])
@pytest.mark.parametrize("action", ["FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE"])
def test_public_action_algebra(
    adapter: Any, prior: str, count: int, frozen: bool, action: str
) -> None:
    repo = adapter
    view, _, _ = setup_references(repo, count)
    if prior in ("REVOKED", "RETIRED"):
        view = invoke(
            repo, control(view.control_revision, "REVOKE" if prior == "REVOKED" else "RETIRE")
        ).scope
    view = invoke(repo, control(view.control_revision, "FREEZE" if frozen else "UNFREEZE")).scope
    assert view.state == prior and view.frozen == frozen
    before = raw_state(repo)
    target = (
        view.previous.generation_id if view.previous else "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
    )
    req = control(view.control_revision, action, target if action == "ROLLBACK" else None)
    if action == "ROLLBACK" and view.previous is None:
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_ROLLBACK_UNAVAILABLE$"):
            invoke(repo, req)
        assert raw_state(repo) == before
        return
    result = invoke(repo, req)
    expected = view.to_mapping()
    expected.update(control_revision=view.control_revision + 1, frozen=action != "UNFREEZE")
    if action == "ROLLBACK":
        expected.update(active=expected["previous"], previous=None)
    elif action in ("REVOKE", "RETIRE"):
        expected.update(
            active=None, previous=None, state="REVOKED" if action == "REVOKE" else "RETIRED"
        )
    assert result.scope.to_mapping() == expected
    assert result.receipt.to_mapping() == dict(
        operation_id=result.receipt.operation_id,
        action=action,
        revision=view.control_revision + 1,
        actor="operator",
        occurred_at=START.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        generation_id=req.generation_id,
    )
    assert invoke(repo, req) == result
    after = raw_state(repo)
    assert after != before and len(after[2]) == len(before[2]) + 1
    if isinstance(repo, MemoryRepository):
        retained = {key[1] for key in after[1]}
    else:
        retained = {row[1] for row in after[1]}
    assert retained == {
        item.generation_id for item in (result.scope.active, result.scope.previous) if item
    }


@pytest.mark.parametrize("action", ["ROLLBACK", "REVOKE", "RETIRE"])
def test_erasure_does_not_decrease_watermark(adapter: Any, action: str) -> None:
    repo = adapter
    view, _, results = setup_references(repo)
    view = invoke(
        repo,
        control(
            view.control_revision,
            action,
            results[0].receipt.generation_id if action == "ROLLBACK" else None,
        ),
    ).scope
    view = invoke(repo, control(view.control_revision, "UNFREEZE")).scope
    before = raw_state(repo)
    # A distinct root with exactly B's event interval is not duplicate identity,
    # but still cannot cross the durable greatest-ever watermark.
    job = stored()
    delta = timedelta(minutes=2)
    job.update(
        id="overlap",
        dataset_id="overlap",
        start_time=(START + delta).isoformat(),
        end_time=(START + delta + timedelta(seconds=60)).isoformat(),
    )
    for row in job["flow_records"]:
        row["timestamp"] = (datetime.fromisoformat(row["timestamp"]) + delta).isoformat()
        row["total_bytes"] += 1
    repo.save_job(job)
    req = approval(repo, "overlap", view.control_revision)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_EVENT_ORDER$"):
        repo.publish_baseline_source(config().scope_id, req, "reviewer", START)
    assert raw_state(repo) == before
    req = approval(repo, store_source(repo, 10), view.control_revision)
    c = repo.publish_baseline_source(config().scope_id, req, "reviewer", START)
    assert c.scope.accepted_event_end > results[1].scope.accepted_event_end
    assert c.scope.previous == (results[0].scope.active if action == "ROLLBACK" else None)


@pytest.mark.parametrize("total", [0, 1])
def test_empty_and_singleton_control_page(adapter: Any, total: int) -> None:
    setup_references(adapter, 0)
    receipt = invoke(adapter, control(0, "FREEZE")).receipt if total else None
    for offset in (0, total, 64):
        for limit in (1, 20):
            page = adapter.page_baseline_control_events(config().scope_id, offset, limit)
            assert page.total == total and page.next_offset is None
            assert page.earliest_retained_revision == (1 if total else None)
            assert page.items == ((receipt,) if total and offset == 0 else ())


def test_mixed_retention_and_selected_page_budget(adapter: Any, monkeypatch: Any) -> None:
    repo = adapter
    view, requests, results = setup_references(repo, 1)
    first_control = control(view.control_revision, "REVOKE")
    receipts = [results[0].receipt]
    view = invoke(repo, first_control).scope
    receipts.append(repo.page_baseline_control_events(config().scope_id).items[0])
    while view.control_revision < 65:
        req = control(view.control_revision, "UNFREEZE" if view.frozen else "FREEZE")
        result = invoke(repo, req)
        view = result.scope
        receipts.append(result.receipt)
        if view.control_revision in (20, 21, 64, 65):
            expected = list(reversed(receipts[-64:]))
            for offset in (0, len(expected), 64):
                for limit in (1, 20):
                    decoded = []
                    actual = bs._operation_envelope

                    def envelope(
                        row: Any, identifier: str, seen: Any = decoded, decode: Any = actual
                    ) -> Any:
                        seen.append(row[1])
                        return decode(row, identifier)

                    with monkeypatch.context() as patch:
                        patch.setattr(bs, "_operation_envelope", envelope)
                        page = repo.page_baseline_control_events(config().scope_id, offset, limit)
                    selected = tuple(expected[offset : offset + limit])
                    assert page.items == selected and page.total == len(expected)
                    assert decoded == [item.revision for item in selected]
                    assert page.earliest_retained_revision == expected[-1].revision
                    assert page.next_offset == (
                        offset + len(selected) if offset + len(selected) < len(expected) else None
                    )
    assert len(raw_state(repo)[2]) == 64
    replay = invoke(repo, first_control)
    assert replay.receipt == receipts[1] and replay.scope == view
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_REVISION_CONFLICT$"):
        repo.publish_baseline_source(config().scope_id, requests[0], "reviewer", START)
    repo.delete_job(requests[0].source_job_id)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_SOURCE_NOT_FOUND$"):
        repo.publish_baseline_source(config().scope_id, requests[0], "reviewer", START)
    view = invoke(repo, control(view.control_revision, "RETIRE")).scope
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_REVISION_CONFLICT$"):
        invoke(repo, first_control)


@pytest.mark.parametrize(
    "old_action", ["APPROVE", "FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE"]
)
@pytest.mark.parametrize(
    "new_action", ["APPROVE", "FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE"]
)
def test_shared_cross_action_namespace(adapter: Any, old_action: str, new_action: str) -> None:
    repo = adapter
    view, approvals, results = setup_references(repo)
    if old_action == "APPROVE":
        key = approvals[1].idempotency_key
    else:
        old = control(
            view.control_revision,
            old_action,
            results[0].receipt.generation_id if old_action == "ROLLBACK" else None,
        )
        view = invoke(repo, old).scope
        key = old.idempotency_key
    before = raw_state(repo)
    if new_action == "APPROVE":
        changed = approvals[1].model_copy(
            update={"idempotency_key": key, "reason": "changed reason"}
        )
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_IDEMPOTENCY_CONFLICT$"):
            repo.publish_baseline_source(config().scope_id, changed, "other-actor", START)
    else:
        changed = control(
            view.control_revision,
            new_action,
            results[0].receipt.generation_id if new_action == "ROLLBACK" else None,
            key,
        )
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_IDEMPOTENCY_CONFLICT$"):
            invoke(repo, changed)
    assert raw_state(repo) == before
