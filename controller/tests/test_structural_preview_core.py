"""Counts-only structural core; synthetic persisted bindings, not public preview."""

from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_read as r
from c2hunter_controller import historical_source as s
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_source import config, stored


def scope(kind: str = "EVALUATION") -> h.ScopeConfig:
    raw = config().to_mapping()
    raw.update(kind=kind, stored_sensor_id="sensor" if kind == "OPERATIONAL" else None)
    return h.ScopeConfig.from_mapping(raw)


def poison(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("reviewed authority/publication or generic acquisition visited")


def admitted_binding(metadata: list[dict[str, Any]], flows: list[Any]) -> h.SourceBindingProjection:
    # From structural-preview-closure/probe.py: original bounded acquisition,
    # no changed production state/review semantics and no fabricated review.
    original = h.project_original_job(dict(metadata[0], flow_records=flows))
    lineage = tuple(h.project_lineage_node(node) for node in metadata)
    root = next(node for node in lineage if node.parent_job_id is None)
    digest = (
        root.source.value.sha256.value
        if isinstance(root.source, h.Present) and isinstance(root.source.value.sha256, h.Present)
        else None
    )
    return h.SourceBindingProjection(
        original=original,
        lineage=lineage,
        root_job_id=root.id,
        root_identity="pcap:" + digest if digest else h.canonical_json([root.id, root.dataset_id]),
        root_content_sha256=digest,
        origin="PCAP_UPLOAD" if digest else "SENSOR_CAPTURE",
        origin_assurance="STORED_LINEAGE_ONLY",
        actual_sensor_id=original.sensor_ids[0],
        event_start=s._utc(original.start_time),
        event_end=s._utc(original.end_time),
        internal_networks=("10.0.0.0/24",),
        quality=h.aggregate_lineage_quality(lineage, selected_job_id=original.id),
    )


def persisted_binding(repo: Any, backend: str) -> h.SourceBindingProjection:
    with repo._lock:
        if backend == "sqlite":
            repo.connection.execute("BEGIN")
        try:
            if backend == "sqlite":
                metadata = r._chain("root", lambda key: r._sqlite_metadata(repo.connection, key))
                flows = r._sqlite_flows(repo.connection, "root")
            else:
                metadata = r._chain(
                    "root", lambda key: r._metadata(repo.jobs[key]) if key in repo.jobs else None
                )
                flows = r._admit_rows(repo.jobs["root"]["flow_records"])
            return admitted_binding(metadata, flows)
        finally:
            if backend == "sqlite":
                repo.connection.rollback()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_persisted_evaluation_without_review_has_conditional_counts(
    backend: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "input.db")
    try:
        repo.save_job(stored())
        cfg = scope()
        for name in ("get_job", "list_jobs", "get_job_summary", "get_candidates"):
            monkeypatch.setattr(repo, name, poison)
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_SCOPE_MISMATCH$"):
            repo.read_historical_source(
                "root", purpose="COMPARISON", scope=cfg, quality_review=None
            )
        binding = persisted_binding(repo, backend)
        before = h.source_binding_value(binding)
        factory = getattr(s, "structural_preview_input", None)
        assert callable(factory), "review-independent structural input factory is missing"
        calculate = getattr(s, "calculate_structural_preview", None)
        assert callable(calculate), "counts-only structural calculator is missing"
        for name in ("source_build_input", "source_from_binding"):
            monkeypatch.setattr(s, name, poison)
        for name in (
            "BaselineBuildInput",
            "BehaviorWindow",
            "BaselineBuildResult",
            "ProfileBuildRecord",
            "BaselineReference",
            "build_behavior_windows",
            "build_behavior_windows_with_retained_keys",
        ):
            monkeypatch.setattr(b, name, poison)
        monkeypatch.setattr(h.QualityReview, "__init__", poison)
        request = factory(binding, scope=cfg)
        result = calculate(request)
        assert {f.name for f in fields(request)} == {
            "scope",
            "source",
            "strict_flows",
            "trusted_peers",
        }
        assert {f.name for f in fields(result)} == {
            "profile_count",
            "eligible_profile_count",
            "excluded_profile_count",
            "reasons",
        }
        assert (
            result.profile_count,
            result.eligible_profile_count,
            result.excluded_profile_count,
        ) == (4, 4, 0)
        assert result.reasons == ()
        assert h.source_binding_value(binding) == before
        assert request.source.actual_sensor_id == "sensor"
        assert all(flow.sensor_id == "sensor" for flow in request.strict_flows)
    finally:
        repo.close()


def local_binding(raw: dict[str, Any] | None = None) -> h.SourceBindingProjection:
    raw = stored() if raw is None else raw
    return admitted_binding(
        [{key: value for key, value in raw.items() if key != "flow_records"}], raw["flow_records"]
    )


@pytest.mark.parametrize("field", ["strict_flows", "trusted_peers"])
def test_forged_derived_facts_rejected_before_calculation(
    field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = s.structural_preview_input(local_binding(), scope=scope())
    value = request.strict_flows[:-1] if field == "strict_flows" else ("203.0.113.9",)
    object.__setattr__(request, field, value)
    monkeypatch.setattr(b, "_prepare_structural_windows", poison)
    with pytest.raises(s.SourceInputError, match="^BASELINE_SOURCE_INVALID$"):
        s.calculate_structural_preview(request)


@pytest.mark.parametrize(
    "values",
    [
        (True, 1, 0, ()),
        (1, 0, 0, ()),
        (129, 129, 0, ()),
        (0, 0, 0, ("INVENTED",)),
        (0, 0, 0, ["INSUFFICIENT_STREAM_SAMPLES"]),
    ],
)
def test_counts_closed_strict_partition(values: tuple[Any, ...]) -> None:
    with pytest.raises(ValueError):
        s.StructuralPreviewCounts(*values)
