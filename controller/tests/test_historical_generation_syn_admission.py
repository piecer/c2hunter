"""Aggregate source admission must precede SYN member preflight and copying."""

import dataclasses
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from c2hunter_controller import historical_generation as g
from tests.test_historical_generation import producer_args, snapshot_for


@contextmanager
def visits_to(values: list[Any], *, forbid_admission: bool = False) -> Iterator[dict[str, int]]:
    ids = {id(value) for value in values}
    calls: dict[str, int] = dict.fromkeys(("_snapshot_raw", "_snapshot_preflight", "_unmodel"), 0)
    codes = {getattr(g, name).__code__: name for name in calls}
    if forbid_admission:
        calls["strict_collection_caps"] = 0
        codes[g.SourceProjection.strict_collection_caps.__func__.__code__] = (
            "strict_collection_caps"
        )

    def observe(frame: Any, event: str, arg: Any) -> None:
        if event == "call" and frame.f_code in codes:
            name = codes[frame.f_code]
            if name == "strict_collection_caps" or id(frame.f_locals.get("value")) in ids:
                calls[name] += 1

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        yield calls
    finally:
        sys.setprofile(previous)


def aggregate_args(
    representation: str, *, mapping: bool, sentinel: bool, count: int
) -> tuple[dict[str, Any], list[Any]]:
    args = producer_args()
    snapshot = args["snapshot"]
    strict = list(snapshot.source.strict_flows)
    original = list(snapshot.source.original.flow_records)
    members = []
    for i, size in enumerate((85, 86, count - 171)):
        pairs = tuple((n, 1000 * (i + 1) + n) for n in range(size))
        values = (18000,) * size if sentinel else pairs
        if representation in ("strict", "both"):
            row = dataclasses.replace(strict[i], tcp_syn_only_observations=values)
            strict[i] = dict(vars(row)) if mapping else row
            members.extend(values)
        if representation in ("original", "both"):
            fields = g.h.thaw_original_json(original[i].fields)
            fields["tcp_syn_only_observations"] = [list(pair) for pair in pairs]
            row = g.h.OriginalFlowProjection(
                fields=g.h.freeze_original_json(fields),
                sensitive_keys_present=original[i].sensitive_keys_present,
            )
            if mapping:
                if sentinel:
                    fields["tcp_syn_only_observations"] = list(values)
                original[i] = dict(vars(row), fields=fields)
                members.extend(fields["tcp_syn_only_observations"])
            else:
                if sentinel:
                    entries = tuple(
                        (key, values if key == "tcp_syn_only_observations" else item)
                        for key, item in row.fields.entries
                    )
                    row = row.model_copy(update={"fields": g.h.FrozenObject(entries)})
                original[i] = row
                members.extend(dict(row.fields.entries)["tcp_syn_only_observations"])
    original_job = snapshot.source.original.model_copy(update={"flow_records": tuple(original)})
    source = snapshot.source.model_copy(
        update={
            "strict_flows": tuple(strict),
            "original": dict(vars(original_job)) if mapping else original_job,
        }
    )
    args["snapshot"] = snapshot.model_copy(
        update={"source": dict(vars(source)) if mapping else source}
    )
    return args, members


@pytest.mark.parametrize("representation", ["strict", "original", "both"])
@pytest.mark.parametrize("mapping", [False, True])
@pytest.mark.parametrize("sentinel", [False, True])
def test_aggregate_overflow_before_any_member_visit(
    representation: str, mapping: bool, sentinel: bool
) -> None:
    args, members = aggregate_args(representation, mapping=mapping, sentinel=sentinel, count=257)
    with visits_to(members) as calls, pytest.raises(ValueError) as error:
        g.produce_generation(**args)
    assert getattr(error.value, "code", None) == "BASELINE_SOURCE_LIMIT"
    assert calls == dict.fromkeys(calls, 0)


@pytest.mark.parametrize("mapping", [False, True])
def test_exact_aggregate_cap_actual_source_publishes(mapping: bool) -> None:
    args, _ = aggregate_args("both", mapping=False, sentinel=False, count=256)
    snapshot = snapshot_for(
        g.h.thaw_original_job(args["snapshot"].source.original), args["scope"].config
    )
    members = [
        pair
        for row in snapshot.source.strict_flows
        for pair in (row.tcp_syn_only_observations or ())
    ]
    members += [
        pair
        for row in snapshot.source.original.flow_records
        for pair in dict(row.fields.entries).get("tcp_syn_only_observations", ())
    ]
    if mapping:
        original = dict(vars(snapshot.source.original))
        original["flow_records"] = tuple(
            dict(vars(row), fields=g.h.thaw_original_json(row.fields))
            for row in snapshot.source.original.flow_records
        )
        source = dict(
            vars(snapshot.source),
            original=original,
            strict_flows=tuple(dict(vars(row)) for row in snapshot.source.strict_flows),
        )
        args["snapshot"] = snapshot.model_copy(update={"source": source})
    else:
        args["snapshot"] = snapshot
    args["request"] = args["request"].model_copy(
        update={"source_binding_sha256": snapshot.source_binding_sha256}
    )
    with visits_to(members) as calls:
        result = g.produce_generation(**args)
    assert result.sources[0].source_binding_sha256 == snapshot.source_binding_sha256
    assert calls["_snapshot_raw"] > 0


@pytest.mark.parametrize("count", [256, 257])
@pytest.mark.parametrize(
    "malformed",
    [
        "rows-overflow",
        "rows-kind",
        "original-name",
        "row-name",
        "map-width",
        "frozen-width",
        "entries-kind",
        "entry-shape",
        "duplicate-name",
        "unknown-name",
    ],
)
def test_counter_prerequisites_reject_before_scanning_members(malformed: str, count: int) -> None:
    args, members = aggregate_args("both", mapping=False, sentinel=False, count=count)
    snapshot = args["snapshot"]
    original = dict(vars(snapshot.source.original))
    rows = list(original["flow_records"])
    row = dict(vars(rows[0]))
    poison = object()
    cell = g.h.FrozenObject(())
    if malformed == "rows-overflow":
        original["flow_records"] = (poison,) * 8193
    elif malformed == "rows-kind":
        original["flow_records"] = {"poison": poison}
    elif malformed == "original-name":
        original["unknown"] = poison
    else:
        if malformed == "row-name":
            row["unknown"] = poison
        elif malformed == "map-width":
            row["fields"] = {str(i): poison for i in range(len(g.h.FLOW_FIELDS) + 1)}
        else:
            entries: Any = {
                "frozen-width": (("sensor_id", poison),) * (len(g.h.FLOW_FIELDS) + 1),
                "entries-kind": [("sensor_id", poison)],
                "entry-shape": (("sensor_id", poison, poison),),
                "duplicate-name": (("sensor_id", poison), ("sensor_id", poison)),
                "unknown-name": (("unknown", poison),),
            }[malformed]
            # Deliberately malformed container, not a supported positive fixture.
            object.__setattr__(cell, "entries", entries)
            row["fields"] = cell
        rows[0] = row
        original["flow_records"] = tuple(rows)
    args["snapshot"] = snapshot.model_copy(
        update={"source": snapshot.source.model_copy(update={"original": original})}
    )
    with visits_to([*members, poison], forbid_admission=True) as calls, pytest.raises(ValueError):
        g.produce_generation(**args)
    assert calls == dict.fromkeys(calls, 0)


@pytest.mark.parametrize("mapping", [False, True])
@pytest.mark.parametrize("field", ["strict_flows", "trusted_peers"])
def test_earlier_collection_overflow_never_visits_its_member(mapping: bool, field: str) -> None:
    args, _ = aggregate_args("both", mapping=mapping, sentinel=False, count=256)
    snapshot = args["snapshot"]
    source = dict(snapshot.source) if mapping else dict(vars(snapshot.source))
    member = object()
    source[field] = (member,) * (8193 if field == "strict_flows" else 129)
    args["snapshot"] = snapshot.model_copy(update={"source": source})
    with visits_to([member]) as calls, pytest.raises(ValueError):
        g.produce_generation(**args)
    assert calls == dict.fromkeys(calls, 0)
