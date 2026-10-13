"""Exact local admission limits, supported typed readmission and authority split."""

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_source as s
from tests.test_historical_generation import empty_scope, snapshot_for, source_job, uid
from tests.test_historical_source import START, review, stored
from tests.test_structural_preview_admission import changed_row, frozen
from tests.test_structural_preview_core import local_binding, poison, scope


@pytest.mark.parametrize(
    "case",
    [
        "rows8192",
        "sizes128",
        "flags16",
        "syn256",
        "aggregate_syn256",
        "hosts128",
        "trusted128",
        "allowlist128",
    ],
)
def test_exact_local_caps_are_not_prefix_success(case: str) -> None:
    raw, cfg = stored(), scope()
    if case == "rows8192":
        raw["flow_records"] *= 256
    elif case == "sizes128":
        raw["flow_records"][0]["packet_sizes"] = [1] * 128
    elif case == "flags16":
        raw["flow_records"][0]["tcp_flags"] = {str(i): 1 for i in range(16)}
    elif case in ("syn256", "aggregate_syn256"):
        raw["flow_records"][0]["tcp_syn_only_observations"] = [
            [0, i] for i in range(256 if case == "syn256" else 128)
        ]
        if case == "aggregate_syn256":
            raw["flow_records"][1]["tcp_syn_only_observations"] = [[0, i] for i in range(128)]
    elif case == "hosts128":
        cfg = h.ScopeConfig.model_validate(
            dict(
                cfg.to_mapping(),
                hosts=[{"ip": f"10.0.0.{i}", "epoch": "fixture"} for i in range(1, 129)],
            )
        )
    elif case == "trusted128":
        raw["flow_records"] = [
            dict(raw["flow_records"][0], destination_ip=f"203.0.113.{i}") for i in range(1, 129)
        ]
        raw["allowlist"] = [{"type": "CIDR", "value": "203.0.113.0/24", "description": "saved"}]
    else:
        raw["allowlist"] = [
            {"type": "IP", "value": "203.0.113.9", "description": str(i)} for i in range(128)
        ]
    request = s.structural_preview_input(local_binding(raw), scope=cfg)
    result = s.calculate_structural_preview(request)
    assert len(request.strict_flows) == len(raw["flow_records"])
    assert result.profile_count == (128 if case == "trusted128" else 4)
    assert result.eligible_profile_count == (0 if case in ("trusted128", "allowlist128") else 4)
    if case == "trusted128":
        assert len(request.trusted_peers) == 128


@pytest.mark.parametrize(
    "case",
    [
        "metadata_bytes",
        "row_bytes",
        "whole_bytes",
        "context",
        "quality_context",
        "lineage_unknown",
        "row_bool",
        "row_nonfinite",
        "changed_quality",
        "row_sensor",
        "root",
    ],
)
def test_forged_source_is_readmitted_before_normalization(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding, cfg = local_binding(), scope()
    code = "BASELINE_SOURCE_INVALID"
    if case in ("row_bytes", "whole_bytes"):
        binding = changed_row(binding, "domain", "x" * (65537 if case == "row_bytes" else 2000))
        if case == "whole_bytes":
            row = binding.original.flow_records[0]
            binding = binding.model_copy(
                update={
                    "original": binding.original.model_copy(update={"flow_records": (row,) * 5000})
                }
            )
        code = "BASELINE_SOURCE_LIMIT"
    elif case == "metadata_bytes":
        binding = binding.model_copy(
            update={
                "original": binding.original.model_copy(
                    update={
                        "allowlist": h.Present.model_construct(
                            present=True,
                            value=(
                                frozen(
                                    (
                                        ("type", "IP"),
                                        ("value", "203.0.113.9"),
                                        ("description", "x" * 262145),
                                    )
                                ),
                            ),
                        )
                    }
                )
            }
        )
        code = "BASELINE_SOURCE_LIMIT"
    elif case == "context":
        binding = binding.model_copy(
            update={
                "original": binding.original.model_copy(
                    update={
                        "allowlist": h.Present.model_construct(
                            present=True, value=(object(),) * 129
                        )
                    }
                )
            }
        )
        code = "BASELINE_SOURCE_LIMIT"
    elif case == "quality_context":
        binding = binding.model_copy(
            update={
                "quality": binding.quality.model_copy(update={"failed_sensors": (object(),) * 129})
            }
        )
        code = "BASELINE_SOURCE_LIMIT"
    elif case == "lineage_unknown":
        binding = binding.model_copy(
            update={"lineage": (binding.lineage[0].model_copy(update={"unknown": object()}),)}
        )
    elif case == "row_bool":
        binding = changed_row(binding, "packet_count", True)
    elif case == "row_nonfinite":
        binding = changed_row(binding, "duration_seconds", float("inf"))
    elif case == "changed_quality":
        binding = binding.model_copy(
            update={"quality": binding.quality.model_copy(update={"known_partial": True})}
        )
    elif case == "row_sensor":
        binding = changed_row(binding, "sensor_id", "foreign")
        code = "BASELINE_SCOPE_MISMATCH"
    else:
        binding = binding.model_copy(update={"root_identity": "invented"})
        code = "BASELINE_SOURCE_LINEAGE_INVALID"
    monkeypatch.setattr(s, "_flow_value", poison)
    with pytest.raises(s.SourceInputError, match=f"^{code}$"):
        s.structural_preview_input(binding, scope=cfg)


def test_structural_types_are_never_reviewed_source_or_producer_authority() -> None:
    value = s.structural_preview_input(local_binding(), scope=scope())
    counts = s.calculate_structural_preview(value)
    for wrong in (value, counts):
        with pytest.raises(s.SourceInputError, match="^BASELINE_SOURCE_INVALID$"):
            s.source_build_input(
                wrong, scope=value.scope, quality_review=None, source_receipt_id=None
            )
        snap = snapshot_for(source_job(0))
        cfg = empty_scope()
        approval = g.ApprovalRequest(
            expected_revision=cfg.control_revision,
            idempotency_key="fixture-1",
            source_job_id=snap.source.original.id,
            source_binding_sha256=snap.source_binding_sha256,
            normality="APPROVED_NORMAL",
            quality_review=review(),
            reason="negative type control",
        )
        with pytest.raises(ValueError):
            g.produce_generation(
                snapshot=snap.model_copy(update={"source": wrong}),
                scope=cfg,
                current_generation=None,
                accepted_event_end=None,
                request=approval,
                operation_id=uid(1),
                generation_id=uid(101),
                actor="fixture-admin",
                now=START + timedelta(days=40),
            )
        with pytest.raises(b.BaselineInputError):
            b.build_behavior_windows(wrong)
        with pytest.raises(b.BaselineInputError):
            b._reference(b.BaselineReference((wrong,)), value.scope)


def test_strict_aggregate_syn_overflow_before_first_pair_visit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = s.structural_preview_input(local_binding(), scope=scope())
    pair = (0, 12345)
    row = replace(request.strict_flows[0], tcp_syn_only_observations=(pair,) * 128)
    object.__setattr__(
        request, "strict_flows", (row, row, replace(row, tcp_syn_only_observations=(pair,)))
    )
    visits = []
    actual = s._strict_syn

    def observe(value: Any) -> None:
        visits.append(value)
        actual(value)

    monkeypatch.setattr(s, "_strict_syn", observe)
    with pytest.raises(s.SourceInputError, match="^BASELINE_SOURCE_LIMIT$"):
        s.calculate_structural_preview(request)
    assert visits == []
