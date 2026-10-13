"""Readmission is before member traversal/copy, not just before arithmetic."""

from dataclasses import replace
from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_source as s
from tests.test_structural_preview_core import local_binding, poison, scope


def frozen(entries: tuple[Any, ...]) -> h.FrozenObject:
    value = object.__new__(h.FrozenObject)
    object.__setattr__(value, "entries", entries)
    return value


def changed_row(
    binding: h.SourceBindingProjection, field: str, value: Any
) -> h.SourceBindingProjection:
    row = binding.original.flow_records[0]
    cell = frozen(tuple((k, v) for k, v in row.fields.entries if k != field) + ((field, value),))
    original = binding.original.model_copy(
        update={
            "flow_records": (
                row.model_copy(update={"fields": cell}),
                *binding.original.flow_records[1:],
            )
        }
    )
    return binding.model_copy(update={"original": original})


@pytest.mark.parametrize(
    "case", ["rows", "sizes", "flags", "syns", "aggregate_syns", "hosts", "networks", "lineage"]
)
def test_factory_caps_before_any_member_decoder(case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    binding, cfg = local_binding(), scope()
    bomb = object()
    if case == "rows":
        binding = binding.model_copy(
            update={
                "original": binding.original.model_copy(update={"flow_records": (bomb,) * 8193})
            }
        )
    elif case == "sizes":
        binding = changed_row(binding, "packet_sizes", (bomb,) * 129)
    elif case == "flags":
        binding = changed_row(
            binding, "tcp_flags", frozen(tuple((str(i), bomb) for i in range(17)))
        )
    elif case in ("syns", "aggregate_syns"):
        binding = changed_row(
            binding, "tcp_syn_only_observations", (bomb,) * (257 if case == "syns" else 128)
        )
        if case == "aggregate_syns":
            row = binding.original.flow_records[0]
            rows = (
                row,
                row,
                changed_row(
                    local_binding(), "tcp_syn_only_observations", (bomb,)
                ).original.flow_records[0],
            )
            binding = binding.model_copy(
                update={"original": binding.original.model_copy(update={"flow_records": rows})}
            )
    elif case == "hosts":
        cfg = cfg.model_copy(update={"hosts": (bomb,) * 129})
    elif case == "networks":
        cfg = cfg.model_copy(update={"internal_networks": (bomb,) * 129})
    else:
        binding = binding.model_copy(update={"lineage": (bomb,) * 17})
    monkeypatch.setattr(s, "_flows", poison)
    monkeypatch.setattr(h, "thaw_original_json", poison)
    code = "BASELINE_SOURCE_LINEAGE_INVALID" if case == "lineage" else "BASELINE_SOURCE_LIMIT"
    with pytest.raises(s.SourceInputError, match=f"^{code}$"):
        s.structural_preview_input(binding, scope=cfg)


@pytest.mark.parametrize("case", ["rows", "sizes", "flags", "syns", "aggregate_syns", "trusted"])
def test_calculator_caps_before_any_member_decoder(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = s.structural_preview_input(local_binding(), scope=scope())
    bomb = object()
    row = request.strict_flows[0]
    if case == "rows":
        object.__setattr__(request, "strict_flows", (bomb,) * 8193)
    elif case == "trusted":
        object.__setattr__(request, "trusted_peers", (bomb,) * 129)
    else:
        field = {
            "sizes": "packet_sizes",
            "flags": "tcp_flags",
            "syns": "tcp_syn_only_observations",
            "aggregate_syns": "tcp_syn_only_observations",
        }[case]
        value = (
            {str(i): bomb for i in range(17)}
            if case == "flags"
            else (bomb,) * (129 if case == "sizes" else 128 if case == "aggregate_syns" else 257)
        )
        row = replace(row, **{field: value})
        rows = (
            (row, row, replace(row, tcp_syn_only_observations=(bomb,)))
            if case == "aggregate_syns"
            else (row,)
        )
        object.__setattr__(request, "strict_flows", rows)
    monkeypatch.setattr(s, "_flows", poison)
    monkeypatch.setattr(h, "thaw_original_json", poison)
    with pytest.raises(s.SourceInputError, match="^BASELINE_SOURCE_LIMIT$"):
        s.calculate_structural_preview(request)


@pytest.mark.parametrize("case", ["binding", "original", "row", "raw_row", "scope", "host"])
def test_unknown_fields_reject_without_visiting_values(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding, cfg = local_binding(), scope()
    if case == "binding":
        binding = binding.model_copy(update={"unknown": object()})
    elif case == "original":
        binding = binding.model_copy(
            update={"original": binding.original.model_copy(update={"unknown": object()})}
        )
    elif case == "row":
        row = binding.original.flow_records[0].model_copy(update={"unknown": object()})
        binding = binding.model_copy(
            update={"original": binding.original.model_copy(update={"flow_records": (row,)})}
        )
    elif case == "raw_row":
        binding = changed_row(binding, "unknown", object())
    elif case == "scope":
        cfg = cfg.model_copy(update={"unknown": object()})
    else:
        cfg = cfg.model_copy(
            update={"hosts": (cfg.hosts[0].model_copy(update={"unknown": object()}),)}
        )
    monkeypatch.setattr(s, "_flows", poison)
    monkeypatch.setattr(h, "thaw_original_json", poison)
    with pytest.raises(s.SourceInputError, match="^BASELINE_SOURCE_INVALID$"):
        s.structural_preview_input(binding, scope=cfg)


@pytest.mark.parametrize(
    "case",
    [
        "mutable_flags",
        "bool_count",
        "mutable_sizes",
        "mutable_trust",
        "mutable_flows",
        "unused_mutable",
        "extra_flow",
        "mutable_scope",
    ],
)
@pytest.mark.parametrize("entry", ["constructor", "calculator"])
def test_exact_immutable_input_readmission(case: str, entry: str) -> None:
    binding = local_binding()
    if case == "mutable_flags":
        binding = changed_row(binding, "tcp_flags", h.FrozenObject(()))
    request = s.structural_preview_input(binding, scope=scope())
    values = {
        name: getattr(request, name)
        for name in ("scope", "source", "strict_flows", "trusted_peers")
    }
    row = request.strict_flows[0]
    if case == "mutable_flags":
        row = replace(row, tcp_flags={})
    elif case == "bool_count":
        row = replace(row, packet_count=True)
    elif case == "mutable_sizes":
        row = replace(row, packet_sizes=[])
    elif case == "unused_mutable":
        row = replace(row, payload_entropy=[])
    elif case == "extra_flow":
        row = replace(row)
        object.__setattr__(row, "unknown", object())
    elif case == "mutable_scope":
        values["scope"] = request.scope.model_copy(update={"hosts": list(request.scope.hosts)})
    values["strict_flows"] = (row, *request.strict_flows[1:])
    if case == "mutable_flows":
        values["strict_flows"] = list(values["strict_flows"])
    if case == "mutable_trust":
        values["trusted_peers"] = []
    with pytest.raises(ValueError):
        if entry == "constructor":
            s.StructuralPreviewInput(**values)
        else:
            for key, value in values.items():
                object.__setattr__(request, key, value)
            s.calculate_structural_preview(request)
