"""Structural facts and reviewed arithmetic parity; never stored-public preview."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_read as r
from c2hunter_controller import historical_source as s
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_source import START, review, stored
from tests.test_structural_preview_core import local_binding, persisted_binding, poison, scope


def genuine_review(kind: str) -> h.QualityReview:
    return h.QualityReview.model_validate(
        dict(review().to_mapping(), sensor_alias_asserted=kind == "EVALUATION")
    )


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("kind", ["OPERATIONAL", "EVALUATION"])
@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize(
    "fact",
    ["clean", "partial", "inherited_partial", "clock", "zero_clock", "upload", "same_sensor"],
)
def test_persisted_negative_quality_counts_and_unchanged_review_gate(
    backend: str,
    kind: str,
    purpose: str,
    fact: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw, cfg = stored(), scope(kind)
    if fact == "partial":
        raw["status"] = "PARTIALLY_COMPLETED"
    elif fact == "inherited_partial":
        earlier = stored()
        earlier["capture_incomplete"] = True
        raw["source_observation_quality"] = local_binding(earlier).quality.to_mapping()
    elif fact in ("clock", "zero_clock"):
        raw["operations"] = {
            "sensors": {"sensor": {"clock_offset_ms": -9001 if fact == "clock" else 0}}
        }
    elif fact == "upload":
        raw.update(
            source_type="PCAP_UPLOAD",
            mode="PCAP_UPLOAD",
            dataset_id="pcap:" + "a" * 64,
            source={"sha256": "a" * 64},
        )
    elif fact == "same_sensor":
        cfg = h.ScopeConfig.model_validate(dict(cfg.to_mapping(), sensor_key="sensor"))
    repo = MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "source.db")
    try:
        repo.save_job(raw)
        for name in ("get_job", "list_jobs", "get_job_summary", "get_candidates"):
            monkeypatch.setattr(repo, name, poison)
        before = (
            deepcopy((repo.jobs, repo.candidates, repo.audit_events))
            if backend == "memory"
            else "\n".join(repo.connection.iterdump())
        )
        binding = persisted_binding(repo, backend)
        identity_before = h.source_binding_value(binding)
        failure = (
            "BASELINE_SOURCE_STATE"
            if fact == "partial" and purpose == "APPROVAL"
            else "BASELINE_SCOPE_MISMATCH"
            if kind == "EVALUATION" or fact == "upload"
            else None
        )
        if failure:
            with pytest.raises(r.HistoricalReadError, match=f"^{failure}$"):
                repo.read_historical_source("root", purpose=purpose, scope=cfg, quality_review=None)
        if kind == "OPERATIONAL" and fact == "upload":
            with pytest.raises(s.SourceInputError, match="^BASELINE_SCOPE_MISMATCH$"):
                s.structural_preview_input(binding, scope=cfg)
        else:
            with monkeypatch.context() as blocked:
                for name in ("source_build_input", "source_from_binding"):
                    blocked.setattr(s, name, poison)
                blocked.setattr(h.QualityReview, "__init__", poison)
                for name in (
                    "BaselineBuildInput",
                    "BehaviorWindow",
                    "ProfileBuildRecord",
                    "BaselineBuildResult",
                    "BaselineReference",
                ):
                    blocked.setattr(b, name, poison)
                request = s.structural_preview_input(binding, scope=cfg)
                counts = s.calculate_structural_preview(request)
            assert (
                counts.profile_count,
                counts.eligible_profile_count,
                counts.excluded_profile_count,
            ) == (4, 4, 0)
            assert counts.reasons == ()
            if fact in ("partial", "inherited_partial"):
                assert request.source.quality.known_partial
            if fact == "clock":
                assert request.source.quality.clock_uncertain
            observation = s._hashes(
                request.source, request.strict_flows, request.trusted_peers, cfg.sensor_key
            )
            # Genuine assertions supplied later: compare arithmetic/hashes only,
            # never claim partial normal approval publication succeeds.
            reviewed = s.source_from_binding(
                binding, scope=cfg, quality_review=genuine_review(kind)
            )
            assert observation == (reviewed.observation_sha256, reviewed.feature_observation_sha256)
            assert h.source_binding_sha256(
                request.source, purpose=purpose, candidates=()
            ) == h.source_binding_sha256(reviewed.source_binding(), purpose=purpose, candidates=())
            assert h.source_binding_value(request.source) == identity_before
            assert all(row.sensor_id == binding.actual_sensor_id for row in request.strict_flows)
        after = (
            deepcopy((repo.jobs, repo.candidates, repo.audit_events))
            if backend == "memory"
            else "\n".join(repo.connection.iterdump())
        )
        assert after == before
    finally:
        repo.close()


SCENARIOS = [
    "packet",
    "aggregate",
    "mixed",
    "same_time",
    "unknown",
    "inbound",
    "both",
    "neither",
    "sparse",
    "empty",
    "trusted",
    "common53",
    "common123",
    "missing_port",
    "zero",
    "max_bytes",
    "max_packets",
    "bidirectional",
    "retry",
    "control",
    "udp",
    "payload",
    "ack",
    "mixed_exclusions",
]


def scenario_raw(case: str) -> dict[str, Any]:
    raw = stored(aggregate=case == "aggregate")
    rows = raw["flow_records"]
    for index, row in enumerate(rows):
        if case == "mixed" and index % 2:
            row.update(packet_count=2, duration_seconds=0.25)
        if case == "same_time":
            row["timestamp"] = START.isoformat()
        if case == "unknown":
            row["direction"] = "unknown"
        if case == "inbound":
            row["source_ip"], row["destination_ip"] = row["destination_ip"], row["source_ip"]
            row["source_port"], row["destination_port"] = (
                row["destination_port"],
                row["source_port"],
            )
            row["direction"] = "INBOUND"
        if case in ("both", "neither"):
            row.update(
                destination_ip="10.0.0.2", direction="UNKNOWN"
            ) if case == "both" else row.update(source_ip="198.51.100.1", direction="UNKNOWN")
        if case in ("common53", "common123", "missing_port"):
            row["destination_port"] = (
                None if case == "missing_port" else int(case.removeprefix("common"))
            )
        if case in ("zero", "bidirectional"):
            row.update(bidirectional=True, packet_count=2, total_bytes=0 if case == "zero" else 100)
        if case == "max_bytes":
            row["total_bytes"] = 2**53 if index % 2 else 0
        if case == "max_packets":
            row["packet_count"] = 2**53
        if case in ("retry", "control", "udp", "payload", "ack"):
            packets = 1000 if case == "control" else 1
            row.update(
                packet_count=packets,
                total_bytes=60 * packets,
                duration_seconds=1 if case == "control" else 0,
                tcp_flags={"syn": packets},
                tcp_flags_observed=True,
                tcp_syn_count=packets,
                tcp_syn_only_count=packets,
                tcp_syn_only_observations=[[0, 12345]],
            )
            if case == "udp":
                row["protocol"] = "UDP"
            if case == "payload":
                row.update(payload_length=20, payload_hash="payload")
            if case == "ack":
                row.update(
                    tcp_flags={"ack": 1},
                    tcp_syn_count=0,
                    tcp_syn_only_count=0,
                    tcp_ack_count=1,
                    tcp_ack_only_count=1,
                    tcp_syn_only_observations=[],
                )
        if case == "mixed_exclusions" and index < 8:
            row["destination_port"] = 53
    if case == "sparse":
        raw["flow_records"] = rows[:7]
    if case == "empty":
        raw["flow_records"] = []
    if case == "trusted":
        raw["allowlist"] = [
            {"type": "IP", "value": "203.0.113.9", "description": "saved", "enabled": True}
        ]
    return raw


@pytest.mark.parametrize("kind", ["OPERATIONAL", "EVALUATION"])
@pytest.mark.parametrize("case", SCENARIOS)
def test_real_numerical_counts_reasons_and_single_preparation(
    case: str, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding, cfg = local_binding(scenario_raw(case)), scope(kind)
    reviewed = s.source_from_binding(binding, scope=cfg, quality_review=genuine_review(kind))
    build = b.build_behavior_windows(
        s.source_build_input(
            reviewed, scope=cfg, quality_review=genuine_review(kind), source_receipt_id=None
        )
    )
    calls: dict[str, int] = {}
    for name in (
        "_prepare_structural_windows",
        "_calculate_structural_windows",
        "syn_retry_duplicate_flow_ids",
        "_dispersion",
    ):
        original = getattr(b, name)

        def observed(
            *args: Any, _name: str = name, _function: Any = original, **kwargs: Any
        ) -> Any:
            calls[_name] = calls.get(_name, 0) + 1
            return _function(*args, **kwargs)

        monkeypatch.setattr(b, name, observed)
    request = s.structural_preview_input(binding, scope=cfg)
    assert not calls
    result = s.calculate_structural_preview(request)
    assert (result.profile_count, result.eligible_profile_count, result.excluded_profile_count) == (
        build.raw_profile_count,
        build.eligible_profile_count,
        build.excluded_profile_count,
    )
    assert result.reasons == tuple(
        reason for reason in build.limitations if reason != "EVALUATION_SENSOR_ALIAS"
    )
    assert result.eligible_profile_count + result.excluded_profile_count == result.profile_count
    assert (
        calls["_prepare_structural_windows"]
        == calls["_calculate_structural_windows"]
        == calls["syn_retry_duplicate_flow_ids"]
        == 1
    )
    if case in (
        "packet",
        "aggregate",
        "mixed",
        "same_time",
        "zero",
        "max_bytes",
        "max_packets",
        "bidirectional",
    ):
        assert result.eligible_profile_count == 4
        assert calls["_dispersion"] > 0
    if case in ("both", "neither", "empty"):
        assert result.profile_count == 0 and result.reasons == ()
    if case in ("common53", "common123", "missing_port"):
        assert result.profile_count == 2 and result.eligible_profile_count == 0
    if case == "mixed_exclusions":
        assert (
            result.profile_count,
            result.eligible_profile_count,
            result.excluded_profile_count,
        ) == (4, 3, 1)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        result.profile_count = 0


@pytest.mark.parametrize("count", [128, 129])
def test_raw_group_admission_precedes_suppression_features(
    count: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = stored()
    raw["flow_records"] = [
        dict(raw["flow_records"][0], destination_port=1000 + i) for i in range(count)
    ]
    request = s.structural_preview_input(local_binding(raw), scope=scope())
    if count == 129:
        monkeypatch.setattr(b, "syn_retry_duplicate_flow_ids", poison)
        monkeypatch.setattr(b, "_dispersion", poison)
        with pytest.raises(s.SourceInputError, match="^BASELINE_PROFILE_LIMIT$"):
            s.calculate_structural_preview(request)
    else:
        result = s.calculate_structural_preview(request)
        assert (
            result.profile_count,
            result.eligible_profile_count,
            result.excluded_profile_count,
        ) == (128, 0, 128)


@pytest.mark.parametrize(
    "mutation", ["both_missing", "network", "sensor", "window", "bad_direction"]
)
def test_structural_scope_and_envelope_failures(mutation: str) -> None:
    raw, cfg = stored(), scope("OPERATIONAL")
    if mutation == "both_missing":
        raw["flow_records"][0]["destination_ip"] = "10.0.0.3"
    elif mutation == "network":
        cfg = h.ScopeConfig.model_validate(
            dict(cfg.to_mapping(), internal_networks=["10.0.0.0/16"])
        )
    elif mutation == "sensor":
        cfg = h.ScopeConfig.model_validate(dict(cfg.to_mapping(), stored_sensor_id="other"))
    elif mutation == "window":
        cfg = h.ScopeConfig.model_validate(dict(cfg.to_mapping(), window_seconds=61))
    else:
        raw["flow_records"][0]["direction"] = "INBOUND"
    expected = (
        "BASELINE_SOURCE_INVALID" if mutation == "bad_direction" else "BASELINE_SCOPE_MISMATCH"
    )
    with pytest.raises(s.SourceInputError, match=f"^{expected}$"):
        s.structural_preview_input(local_binding(raw), scope=cfg)
