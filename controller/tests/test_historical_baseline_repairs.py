"""Persistent H5 repair witnesses; public constructors and mapping paths only."""

import json
from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h

T0 = "2026-01-01T00:00:00Z"
T1 = "2026-01-01T00:01:00Z"


def job(**changes: Any) -> dict[str, Any]:
    return dict(
        dict(
            id="root",
            dataset_id="dataset-1",
            parent_job_id=None,
            source_type="SENSOR_CAPTURE",
            mode="LIVE_CAPTURE",
            status="COMPLETED",
            start_time=T0,
            end_time=T1,
            sensor_ids=["sensor-1"],
            internal_networks=["10.0.0.0/8"],
            analysis={"module": "c2"},
            flow_records=[],
        ),
        **changes,
    )


def source(raw: dict[str, Any], nodes: tuple[h.LineageNode, ...]) -> h.SourceBindingProjection:
    root = next(n for n in nodes if n.parent_job_id is None)
    uploaded = root.dataset_id.startswith("pcap:")
    return h.SourceBindingProjection(
        original=h.project_original_job(raw),
        lineage=nodes,
        root_job_id=root.id,
        root_identity=root.dataset_id if uploaded else '["root","dataset-1"]',
        root_content_sha256=root.dataset_id[5:] if uploaded else None,
        origin="PCAP_UPLOAD" if uploaded else "SENSOR_CAPTURE",
        origin_assurance="STORED_LINEAGE_ONLY",
        actual_sensor_id="sensor-1",
        event_start=raw["start_time"],
        event_end=raw["end_time"],
        internal_networks=("10.0.0.0/8",),
        quality=h.aggregate_lineage_quality(nodes, selected_job_id=raw["id"]),
    )


@pytest.mark.parametrize(
    "left,right",
    [
        ({"sensors": {"sensor-1": {"clock_offset_ms": 9000}}}, {}),
        ({}, {"sensors": {"sensor-1": {"clock_offset_ms": 9000}}}),
        (
            {"sensors": {"sensor-1": {"clock_offset_ms": 9000}}},
            {"sensors": {"sensor-1": {"clock_offset_ms": 0}}},
        ),
        ({"sensors": {"sensor-1": {"clock_offset_ms": 0}}}, {}),
        ({"failed_sensors": ["sensor-1"]}, {}),
        ({}, {"failed_sensors": ["sensor-1"]}),
        ({"failed_sensors": []}, {}),
        ({"failed_sensors": ["sensor-1"]}, {"failed_sensors": []}),
    ],
)
def test_selected_operations_match_lineage_presence_and_values(
    left: dict[str, Any],
    right: dict[str, Any],
) -> None:
    raw = job(operations=left)
    nodes = (h.project_lineage_node(job(operations=right)),)
    with pytest.raises(ValueError, match="BASELINE_SOURCE_LINEAGE_INVALID"):
        source(raw, nodes)


def test_selected_operations_set_semantics_and_known_negatives() -> None:
    raw = job(
        operations={
            "failed_sensors": ["b", "a", "a"],
            "sensors": {"b": {"clock_offset_ms": 9000}, "a": {"clock_offset_ms": -9000}},
        }
    )
    node = h.project_lineage_node(raw)
    # Independently admitted quality need not preserve set ordering/multiplicity.
    mapping = node.to_mapping()
    mapping["quality"]["failed_sensors"]["value"] = ["b", "a", "a"]
    mapping["quality"]["sensor_offsets"].reverse()
    projection = source(raw, (h.LineageNode.from_mapping(mapping),))
    assert projection.quality.known_partial and projection.quality.clock_uncertain
    assert projection.quality.failed_sensors == ("a", "b")
    assert h.SourceBindingProjection.from_mapping(projection.to_mapping()) == projection


@pytest.mark.parametrize("operations", [None, {}, {"sensors": {"sensor-1": {"status": "OK"}}}])
def test_missing_operations_measurement_never_becomes_zero(operations: Any) -> None:
    raw = job() if operations is None else job(operations=operations)
    projection = source(raw, (h.project_lineage_node(raw),))
    assert projection.quality.sensor_offset_bounds == ()
    assert h.stored_clock_offset_ms(projection.quality) is None
    assert not projection.quality.known_partial and not projection.quality.clock_uncertain


@pytest.mark.parametrize("conflict", [1, 2, None])
@pytest.mark.parametrize("missing_descendant", [False, True])
def test_retained_upload_digests_match_root(
    conflict: int | None,
    missing_descendant: bool,
) -> None:
    digest = "a" * 64
    root = job(
        dataset_id="pcap:" + digest,
        source_type="PCAP_UPLOAD",
        mode="PCAP_UPLOAD",
        source={"sha256": digest},
    )
    raws = [
        root,
        dict(root, id="child", parent_job_id="root"),
        dict(root, id="grandchild", parent_job_id="child"),
    ]
    if missing_descendant:
        raws[1 if conflict != 1 else 2].pop("source")
    if conflict is not None:
        raws[conflict]["source"] = {"sha256": "b" * 64}
    nodes = tuple(h.project_lineage_node(raw) for raw in raws)
    if conflict is not None:
        with pytest.raises(ValueError, match="BASELINE_SOURCE_LINEAGE_INVALID"):
            source(raws[-1], nodes)
    else:
        projection = source(raws[-1], nodes)
        assert projection.root_content_sha256 == digest
        assert h.SourceBindingProjection.from_mapping(projection.to_mapping()) == projection


def test_upload_root_digest_remains_required() -> None:
    root = job(dataset_id="pcap:" + "a" * 64, source_type="PCAP_UPLOAD", mode="PCAP_UPLOAD")
    with pytest.raises(ValueError, match="BASELINE_SOURCE_LINEAGE_INVALID"):
        source(root, (h.project_lineage_node(root),))


@pytest.mark.parametrize("route", ["constructor", "mapping"])
@pytest.mark.parametrize("kind", ["offset", "minimum", "maximum"])
@pytest.mark.parametrize(
    "value", [-(2**63) - 1, 2**63, 10**400, True], ids=["below", "above", "huge", "bool"]
)
def test_finite_integer_rejection_is_controlled(route: str, kind: str, value: Any) -> None:
    model: Any = h.SensorOffset if kind == "offset" else h.SensorOffsetBounds
    data = (
        {"sensor_id": "s", "clock_offset_ms": value}
        if kind == "offset"
        else {
            "sensor_id": "s",
            "minimum_ms": value if kind == "minimum" else -1e308,
            "maximum_ms": value if kind == "maximum" else 1e308,
        }
    )
    with pytest.raises(ValueError, match="BASELINE_SOURCE_INVALID"):
        model(**data) if route == "constructor" else model.from_mapping(data)


@pytest.mark.parametrize("value", [-(2**63), 2**63 - 1, 0, 0.0, 0.5, -1e308, 1e308])
def test_finite_endpoints_roundtrip_without_type_coercion(value: int | float) -> None:
    offset = h.SensorOffset(sensor_id="s", clock_offset_ms=value)
    bounds = h.SensorOffsetBounds(sensor_id="s", minimum_ms=value, maximum_ms=value)
    assert type(offset.clock_offset_ms) is type(value)
    assert type(bounds.minimum_ms) is type(value) is type(bounds.maximum_ms)
    assert h.SensorOffset.from_mapping(offset.to_mapping()) == offset
    assert h.SensorOffsetBounds.from_mapping(bounds.to_mapping()) == bounds


def flow(size: int = 300) -> dict[str, Any]:
    row = dict(
        sensor_id="sensor-1",
        timestamp=T0,
        source_ip="10.0.0.1",
        destination_ip="203.0.113.1",
        protocol="tcp",
        direction="OUTBOUND",
        packet_count=1,
        total_bytes=9,
        duration_seconds=0,
        domain="",
    )
    row["domain"] = "x" * (size - len(h.canonical_json(row).encode()))
    assert len(h.canonical_json(row).encode()) == size
    return row


def job_wire(raw: dict[str, Any], *, frozen: bool = False) -> dict[str, Any]:
    # Build DTO input without asking the rejecting helper to admit the input first.
    wire = {k: v for k, v in raw.items() if k not in {"operations", "allowlist", "flow_records"}}
    for name in ("operations", "allowlist"):
        wire[name] = {"present": True, "value": raw[name]} if name in raw else {"present": False}
    wire["flow_records"] = [
        h.project_original_flow(row) if frozen else {"fields": row, "sensitive_keys_present": []}
        for row in raw["flow_records"]
    ]
    return wire


def admit_job(raw: dict[str, Any], route: str) -> h.OriginalJobProjection:
    if route == "helper":
        return h.project_original_job(raw)
    wire = job_wire(raw, frozen=route == "frozen")
    if route == "mapping":
        return h.OriginalJobProjection.from_mapping(wire)
    return h.OriginalJobProjection(**wire)


@pytest.mark.parametrize("route", ["helper", "constructor", "mapping", "frozen"])
@pytest.mark.parametrize("extra", [0, 1])
def test_job_metadata_budget_at_original_root(route: str, extra: int) -> None:
    raw = job(operations={"sensors": {"sensor-1": {"loss_reason": ""}}})
    metadata = {k: v for k, v in raw.items() if k != "flow_records"}
    raw["operations"]["sensors"]["sensor-1"]["loss_reason"] = "x" * (
        256 * 1024 - len(h.canonical_json(metadata).encode()) + extra
    )
    assert len(h.canonical_json(metadata).encode()) == 256 * 1024 + extra
    if extra:
        with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
            admit_job(raw, route)
    else:
        obj = admit_job(raw, route)
        assert h.OriginalJobProjection.from_mapping(obj.to_mapping()) == obj
        assert h.OriginalJobProjection(**obj.to_mapping()) == obj
        assert h.thaw_original_job(obj) == raw


@pytest.mark.parametrize("route", ["helper", "constructor", "mapping", "frozen"])
@pytest.mark.parametrize("extra", [0, 1])
def test_job_flow_budget_excludes_dto_wrappers(route: str, extra: int) -> None:
    # Corrected reviewer fixture: 129 rows, EVERY row <=64KiB.
    rows = [flow(65500)] * 128 + [flow(8 * 1024 * 1024 - 128 * 65500 - 130 + extra)]
    assert len(rows) == 129
    assert all(len(h.canonical_json(r).encode()) <= 65536 for r in rows)
    assert len(h.canonical_json(rows).encode()) == 8 * 1024 * 1024 + extra
    raw = job(flow_records=rows)
    if extra:
        with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
            admit_job(raw, route)
    else:
        obj = admit_job(raw, route)
        assert len(obj.flow_records) == 129
        assert h.OriginalJobProjection.from_mapping(obj.to_mapping()) == obj
        assert h.OriginalJobProjection(**obj.to_mapping()) == obj
        # The containing source DTO must not charge those wrappers either.
        node = h.project_lineage_node(job())
        mapped_source = source(job(), (node,)).to_mapping()
        mapped_source["original"] = obj.to_mapping()
        bound = h.SourceBindingProjection.from_mapping(mapped_source)
        assert h.SourceBindingProjection.from_mapping(bound.to_mapping()) == bound


@pytest.mark.parametrize("route", ["helper", "constructor", "mapping"])
@pytest.mark.parametrize("extra", [0, 1])
def test_candidate_depth_is_metered_at_original_cell_root(route: str, extra: int) -> None:
    value: Any = 0
    for _ in range(12 + extra):
        value = [value]
    raw = {
        "id": "c",
        "candidate_ip": "203.0.113.1",
        "score": 1,
        "evidence": [{"metrics": {"nested": value}}],
    }

    def create() -> h.CandidateProjection:
        if route == "helper":
            return h.project_candidate(raw, position=0)
        if route == "mapping":
            return h.CandidateProjection.from_mapping({"fields": raw, "position": 0})
        arguments: dict[str, Any] = {"fields": raw, "position": 0}
        return h.CandidateProjection(**arguments)

    if extra:
        with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
            create()
    else:
        obj = create()
        assert h.CandidateProjection.from_mapping(obj.to_mapping()) == obj
        assert h.CandidateProjection(**obj.to_mapping()) == obj
        assert h.thaw_original_json(h.decode_original_json(h.canonical_json(raw))) == raw


def test_job_aggregate_admission_precedes_copy_and_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_dumps = json.dumps

    def only_scalar(value: Any, *args: Any, **kwargs: Any) -> str:
        assert not isinstance(value, dict | list | tuple), "whole-input serialization"
        return original_dumps(value, *args, **kwargs)

    def no_freeze(value: object) -> Any:
        pytest.fail("oversized aggregate reached immutable copy")

    raw = job(flow_records=[flow(60000)] * 140)
    wire = job_wire(raw)
    monkeypatch.setattr(json, "dumps", only_scalar)
    monkeypatch.setattr(h, "_freeze", no_freeze)
    for data in (
        wire,
        dict(
            job_wire(job()),
            operations={
                "present": True,
                "value": {"sensors": {"sensor-1": {"loss_reason": "x" * (256 * 1024)}}},
            },
        ),
    ):
        for create in (
            h.OriginalJobProjection.from_mapping,
            h.OriginalJobProjection.model_validate,
        ):
            with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
                create(data)


@pytest.mark.parametrize("route", ["helper", "constructor", "mapping"])
@pytest.mark.parametrize("extra", [0, 1])
def test_flow_row_limit_is_not_widened(route: str, extra: int) -> None:
    raw = flow(65536 + extra)
    data: dict[str, Any] = {"fields": raw, "sensitive_keys_present": []}

    def create() -> h.OriginalFlowProjection:
        if route == "helper":
            return h.project_original_flow(raw)
        if route == "mapping":
            return h.OriginalFlowProjection.from_mapping(data)
        return h.OriginalFlowProjection(**data)

    if extra:
        with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
            create()
    else:
        obj = create()
        assert h.OriginalFlowProjection.from_mapping(obj.to_mapping()) == obj


@pytest.mark.parametrize("extra", [0, 1])
def test_root_metadata_byte_limit_is_not_widened(extra: int) -> None:
    raw = job(unused="")
    raw.pop("flow_records")
    raw["unused"] = "x" * (256 * 1024 - len(h.canonical_json(raw).encode()) + extra)
    assert len(h.canonical_json(raw).encode()) == 256 * 1024 + extra
    if extra:
        with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
            h.project_lineage_node(raw)
    else:
        obj = h.project_lineage_node(raw)
        assert h.LineageNode.from_mapping(obj.to_mapping()) == obj


@pytest.mark.parametrize("name", ["allowlist", "operations"])
@pytest.mark.parametrize("route", ["helper", "constructor", "mapping"])
def test_job_observed_absent_empty_and_null_stay_distinct(name: str, route: str) -> None:
    absent = admit_job(job(), route)
    assert isinstance(getattr(absent, name), h.Absent)
    raw = job(**{name: [] if name == "allowlist" else {}})
    present = admit_job(raw, route)
    assert isinstance(getattr(present, name), h.Present)
    assert h.thaw_original_job(present) == raw
    with pytest.raises(ValueError):
        admit_job(job(**{name: None}), route)
    mapped = present.to_mapping()
    mapped[name]["extra"] = None
    for create in (h.OriginalJobProjection.from_mapping, h.OriginalJobProjection.model_validate):
        with pytest.raises(ValueError):
            create(mapped)


@pytest.mark.parametrize("count", [128, 129])
def test_context_caps_survive_wrapper_separation(count: int) -> None:
    raw = job(
        operations={
            "failed_sensors": ["same"] * count,
            "sensors": {f"s{i}": {"clock_offset_ms": 0} for i in range(count)},
        }
    )
    for route in ("helper", "constructor", "mapping"):
        if count == 128:
            projected = admit_job(raw, route)
            assert h.thaw_original_job(projected) == raw
        else:
            with pytest.raises(ValueError):
                admit_job(raw, route)


@pytest.mark.parametrize("bad", [True, 1, "bad\u0000", "\ud800", float("inf")])
def test_wrapper_scalar_validation_remains_closed(bad: Any) -> None:
    raw = h.project_source_quality({}).to_mapping()
    raw["error_code"] = {"present": True, "value": bad}
    for create in (h.SourceQualityFacts.from_mapping, h.SourceQualityFacts.model_validate):
        with pytest.raises(ValueError):
            create(raw)
    raw = h.project_source_quality({}).to_mapping()
    raw["unrecognized"] = bad
    with pytest.raises(ValueError):
        h.SourceQualityFacts.from_mapping(raw)


@pytest.mark.parametrize("extra", [0, 1])
def test_original_flow_array_node_budget_is_aggregate(extra: int) -> None:
    def nodes(value: Any) -> int:
        if isinstance(value, dict):
            return 1 + sum(1 + nodes(v) for v in value.values())
        if isinstance(value, list):
            return 1 + sum(nodes(v) for v in value)
        return 1

    row = flow()
    row["tcp_flags"] = {f"f{i}": 1 for i in range(128)}
    rows = [row] * ((262144 - 1) // nodes(row))
    remaining = 262144 - 1 - sum(nodes(r) for r in rows)
    # Add one valid small row and fill its packet_sizes array to the exact count.
    last = flow()
    last["packet_sizes"] = []
    if remaining < nodes(last):
        rows.pop()
        remaining += nodes(row)
    # A second bounded flags map supplies pairs of nodes when >128 are needed.
    spare = remaining - nodes(last)
    if spare > 128:
        last["tcp_flags"] = {f"g{i}": 1 for i in range((spare - 128 + 1) // 2)}
    last["packet_sizes"] = [1] * (remaining - nodes(last) + extra)
    assert len(last["packet_sizes"]) <= 128
    rows.append(last)
    assert nodes(rows) == 262144 + extra
    raw = job(flow_records=rows)
    for route in ("helper", "constructor", "mapping"):
        if extra:
            with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
                admit_job(raw, route)
        else:
            obj = admit_job(raw, route)
            assert h.OriginalJobProjection.from_mapping(obj.to_mapping()) == obj
