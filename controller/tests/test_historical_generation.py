"""Synthetic approved-generation plumbing, not authentication or field accuracy."""

import importlib
import importlib.util
from datetime import timedelta
from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from tests.test_historical_source import RECEIPT, START, config, review


def generation_module() -> Any:
    name = "c2hunter_controller.historical_generation"
    assert importlib.util.find_spec(name) is not None, "approved-generation value producer missing"
    return importlib.import_module(name)


def receipt_data() -> dict[str, Any]:
    return {
        "source_receipt_id": RECEIPT,
        "source_job_id": "root",
        "root_job_id": "root",
        "dataset_id": "dataset",
        "root_identity": h.canonical_json(["root", "dataset"]),
        "ancestry_job_ids": ["root"],
        "root_content_sha256": None,
        "source_binding_sha256": "a" * 64,
        "observation_sha256": "b" * 64,
        "feature_observation_sha256": "c" * 64,
        "actual_sensor_id": "sensor",
        "sensor_key": "logical",
        "event_start": START.isoformat(),
        "event_end": (START + timedelta(seconds=60)).isoformat(),
        "origin": "SENSOR_CAPTURE",
        "origin_assurance": "STORED_LINEAGE_ONLY",
        "normality": "APPROVED_NORMAL",
        "approved_by": "fixture-admin",
        "approved_at": (START + timedelta(days=5)).isoformat(),
        "reason": "Synthetic earlier reference normality assertion only",
        "quality_review": review().to_mapping(),
        "producer_completeness": "UNKNOWN",
        "known_partial": False,
        "limitations": [
            "ADMIN_ASSERTED_IDENTITY",
            "HUMAN_ASSERTED_CLOCK_BOUND",
            "PRODUCER_COMPLETENESS_UNKNOWN",
        ],
    }


def test_receipt_closed_immutable_roundtrip() -> None:
    g = generation_module()
    raw = receipt_data()
    receipt = g.SourceReceipt.from_mapping(raw)
    assert receipt == g.SourceReceipt(**raw)
    assert receipt == g.SourceReceipt.model_validate_json(h.canonical_json(raw))
    raw["ancestry_job_ids"].append("unrelated")
    assert receipt.ancestry_job_ids == ("root",)
    with pytest.raises(ValueError):
        receipt.reason = "changed"
    for field, value in [("unknown", 0), ("known_partial", 0), ("normality", "BENIGN")]:
        with pytest.raises(ValueError):
            g.SourceReceipt.from_mapping(dict(receipt.to_mapping(), **{field: value}))


def empty_scope() -> Any:
    g = generation_module()
    cfg = config()
    return g.ScopeView(
        config=cfg,
        config_sha256=h.scope_config_sha256(cfg),
        control_revision=0,
        frozen=False,
        state="EMPTY",
        accepted_event_end=None,
        active=None,
        previous=None,
        created_by="fixture-admin",
        created_at=START,
    )


def source_job(
    index: int, *, aggregate: bool = False, hours: float | None = None
) -> dict[str, Any]:
    from tests.test_historical_source import stored

    raw = stored(aggregate=aggregate)
    shift = timedelta(hours=index * 12 if hours is None else hours)
    raw.update(
        id=f"root-{index}",
        dataset_id=f"dataset-{index}",
        start_time=(START + shift).isoformat(),
        end_time=(START + shift + timedelta(seconds=60)).isoformat(),
    )
    for row in raw["flow_records"]:
        row["timestamp"] = (h._utc(row["timestamp"]) + shift).isoformat()
        row["total_bytes"] += index  # independent observations, not just renamed roots
    return raw


def uid(index: int) -> str:
    return f"00000000-0000-0000-0000-{index:012x}"


def publish(snapshot: Any, scope: Any, current: Any = None, *, index: int = 1) -> Any:
    g = generation_module()
    request = g.ApprovalRequest(
        expected_revision=scope.control_revision,
        idempotency_key=f"fixture-{index}",
        source_job_id=snapshot.source.original.id,
        source_binding_sha256=snapshot.source_binding_sha256,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="Synthetic normal fixture",
    )
    return g.produce_generation(
        snapshot=snapshot,
        scope=scope,
        current_generation=current,
        accepted_event_end=scope.accepted_event_end,
        request=request,
        operation_id=uid(index),
        generation_id=uid(index + 100),
        actor="fixture-admin",
        now=START + timedelta(days=40),
    )


def advance(scope: Any, document: Any) -> Any:
    g = generation_module()
    return g.ScopeView.from_mapping(
        dict(
            scope.to_mapping(),
            control_revision=document.publication_revision,
            state="HAS_REFERENCE",
            previous=scope.active.to_mapping() if scope.active else None,
            active=g.generation_view(document).to_mapping(),
            accepted_event_end=max(s.event_end for s in document.sources).isoformat(),
        )
    )


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("aggregate", [False, True])
def test_actual_persisted_source_generation_comparison(
    backend: str, aggregate: bool, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_analysis import behavior_baseline as b

    from c2hunter_controller.historical_source import source_build_input
    from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
    from tests.test_historical_read import poison

    g = generation_module()
    assert callable(getattr(g, "produce_generation", None)), "deterministic publication missing"
    repo = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "source.sqlite")
    )
    for index in range(4):
        repo.save_job(source_job(index, aggregate=aggregate))
    for name in ("get_job", "list_jobs", "get_job_summary", "get_candidates"):
        monkeypatch.setattr(repo, name, poison)
    scope, current = empty_scope(), None
    for index in range(3):
        snap = repo.read_historical_source(
            f"root-{index}", purpose="APPROVAL", scope=scope.config, quality_review=review()
        )
        prior = current
        document = publish(snap, scope, current, index=index + 1)
        raw = g.generation_json(document)
        view = g.generation_view(document)
        current = g.decode_generation(
            raw, content_sha256=view.content_sha256, byte_size=view.byte_size, scope=scope.config
        )
        assert current == document
        assert publish(snap, scope, prior, index=index + 1) == current
        scope = advance(scope, current)
        if index == 0:
            single = current
    target = repo.read_historical_source(
        "root-3", purpose="COMPARISON", scope=scope.config, quality_review=review()
    ).source
    request = source_build_input(
        target, scope=scope.config, quality_review=review(), source_receipt_id=None
    )
    for doc, expected in [(single, "INSUFFICIENT"), (current, "READY")]:
        reference = g.generation_reference(doc, scope=scope.config)
        reference = b.baseline_reference_from_mapping(b.baseline_reference_to_mapping(reference))
        comparison = b.compare_behavior_windows(
            target=b.build_behavior_windows(request),
            reference=reference,
            scope=request.scope,
            target_observation=b.ObservationIdentity(
                target.root_identity, target.original.dataset_id, target.feature_observation_sha256
            ),
            target_event_start=target.event_start,
            target_event_end=target.event_end,
            target_vetoes=(),
        )
        assert {p.status for p in comparison.comparisons} == {expected}
    if backend == "sqlite":
        repo.connection.close()


def snapshot_for(raw: dict[str, Any], cfg: Any = None, quality: Any = None) -> Any:
    from c2hunter_controller.historical_read import HistoricalReadSnapshot
    from c2hunter_controller.historical_source import project_source

    source = project_source(
        raw, ancestors=(), scope=cfg or config(), quality_review=quality or review()
    )
    return HistoricalReadSnapshot(
        source=source,
        candidates=(),
        source_binding_sha256=h.source_binding_sha256(
            source.source_binding(), purpose="APPROVAL", candidates=()
        ),
    )


def producer_args() -> dict[str, Any]:
    g = generation_module()
    snap, scope = snapshot_for(source_job(0)), empty_scope()
    request = g.ApprovalRequest(
        expected_revision=0,
        idempotency_key="fixture",
        source_job_id=snap.source.original.id,
        source_binding_sha256=snap.source_binding_sha256,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="fixture normal assertion",
    )
    return dict(
        snapshot=snap,
        scope=scope,
        current_generation=None,
        accepted_event_end=None,
        request=request,
        operation_id=uid(1),
        generation_id=uid(101),
        actor="fixture-admin",
        now=START + timedelta(days=40),
    )


@pytest.mark.parametrize(
    "case,code",
    [
        ("revision", "BASELINE_REVISION_CONFLICT"),
        ("frozen", "BASELINE_FROZEN"),
        ("binding", "BASELINE_SOURCE_CHANGED"),
        ("snapshot_digest", "BASELINE_SOURCE_CHANGED"),
        ("comparison_binding", "BASELINE_SOURCE_CHANGED"),
        ("candidates", "BASELINE_SOURCE_CHANGED"),
        ("source_job", "BASELINE_SOURCE_CHANGED"),
        ("partial", "BASELINE_SOURCE_QUALITY"),
        ("clock", "BASELINE_SOURCE_QUALITY"),
        ("status", "BASELINE_SOURCE_STATE"),
        ("empty", "BASELINE_SOURCE_QUALITY"),
        ("watermark", "BASELINE_EVENT_ORDER"),
    ],
)
def test_admission_before_feature_publication(
    case: str, code: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_analysis import behavior_baseline as b

    g = generation_module()
    args = producer_args()
    raw = source_job(0)
    if case == "revision":
        args["request"] = g.ApprovalRequest.from_mapping(
            dict(args["request"].to_mapping(), expected_revision=1)
        )
    elif case == "frozen":
        args["scope"] = g.ScopeView.from_mapping(dict(args["scope"].to_mapping(), frozen=True))
    elif case in {"binding", "source_job"}:
        change = (
            {"source_binding_sha256": "0" * 64} if case == "binding" else {"source_job_id": "other"}
        )
        args["request"] = g.ApprovalRequest.from_mapping(
            dict(args["request"].to_mapping(), **change)
        )
    elif case in {"snapshot_digest", "comparison_binding", "candidates"}:
        snap = args["snapshot"]
        digest = (
            "0" * 64
            if case == "snapshot_digest"
            else h.source_binding_sha256(
                snap.source.source_binding(), purpose="COMPARISON", candidates=()
            )
        )
        changes = {"source_binding_sha256": digest}
        if case == "candidates":
            changes = {
                "candidates": (
                    h.project_candidate(
                        {"id": "rule", "candidate_ip": "203.0.113.9", "score": 1}, position=0
                    ),
                )
            }
        args["snapshot"] = snap.model_copy(update=changes)
    elif case == "watermark":
        args["accepted_event_end"] = START
        args["scope"] = g.ScopeView.from_mapping(
            dict(
                args["scope"].to_mapping(),
                state="REVOKED",
                accepted_event_end=START.isoformat(),
                control_revision=2,
            )
        )
        args["request"] = g.ApprovalRequest.from_mapping(
            dict(args["request"].to_mapping(), expected_revision=2)
        )
    else:
        if case == "partial":
            raw["capture_incomplete"] = True
        if case == "clock":
            raw["capture_quality"] = {"clock_skew_detected": True}
        if case == "status":
            raw["status"] = "PARTIALLY_COMPLETED"
        if case == "empty":
            raw["flow_records"] = []
        args["snapshot"] = snapshot_for(raw)
        args["request"] = g.ApprovalRequest.from_mapping(
            dict(
                args["request"].to_mapping(),
                source_binding_sha256=args["snapshot"].source_binding_sha256,
            )
        )
    calls = []
    actual = b.build_behavior_windows

    def observe(value: Any) -> Any:
        calls.append(value)
        return actual(value)

    monkeypatch.setattr(b, "build_behavior_windows", observe)
    with pytest.raises(ValueError, match=code):
        g.produce_generation(**args)
    if case != "empty":
        assert calls == []
