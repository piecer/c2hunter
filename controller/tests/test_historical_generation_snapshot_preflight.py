"""Snapshot readmission uses the real producer and unchanged recursive copier."""

import sys
from typing import Any

import pytest

from c2hunter_controller import historical_generation as g
from tests.test_historical_generation import producer_args


def rejected_without_copy(args: dict[str, Any], target: object) -> None:
    visits = []
    code = g._unmodel.__code__

    def observe(frame: Any, event: str, arg: Any) -> None:
        if event == "call" and frame.f_code is code and frame.f_locals["value"] is target:
            visits.append(1)

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError):
            g.produce_generation(**args)
    finally:
        sys.setprofile(previous)
    assert not visits, "snapshot was recursively copied before structural admission"


@pytest.mark.parametrize("field,limit", [("strict_flows", 8192), ("trusted_peers", 128)])
@pytest.mark.parametrize("real", [True, False])
def test_snapshot_collection_cap_before_copy(field: str, limit: int, real: bool) -> None:
    args = producer_args()
    snapshot = args["snapshot"]
    member = (
        (snapshot.source.strict_flows[0] if field == "strict_flows" else "203.0.113.7")
        if real
        else 18000
    )
    source = snapshot.source.model_copy(update={field: (member,) * (limit + 1)})
    args["snapshot"] = snapshot.model_copy(update={"source": source})
    rejected_without_copy(args, member)


def updated(value: Any, path: tuple[Any, ...], replacement: Any) -> Any:
    if not path:
        return replacement
    key, *rest = path
    if isinstance(value, g.h.FrozenObject):
        value = g.h.thaw_original_json(value)
    if isinstance(value, g.h.FrozenDTO):
        return value.model_copy(
            update={key: updated(getattr(value, key, None), tuple(rest), replacement)}
        )
    if isinstance(value, tuple | list):
        items = list(value)
        items[key] = updated(items[key], tuple(rest), replacement)
        return tuple(items) if isinstance(value, tuple) else items
    result = dict(value)
    result[key] = updated(result.get(key), tuple(rest), replacement)
    return result


CAP_PATHS = [
    (("candidates",), 2048),
    (("source", "lineage"), 16),
    (("source", "internal_networks"), 128),
    (("source", "original", "flow_records"), 8192),
    (("source", "original", "sensor_ids"), 128),
    (("source", "original", "internal_networks"), 128),
    (("source", "quality", "stop_reasons"), 128),
    (("source", "quality", "failed_sensors"), 128),
    (("source", "quality", "sensor_offset_bounds"), 128),
    (("source", "lineage", 0, "quality", "sensor_offsets"), 128),
    (("source", "original", "flow_records", 0, "fields", "packet_sizes"), 128),
    (("source", "original", "flow_records", 0, "fields", "tcp_syn_only_observations"), 256),
]


@pytest.mark.parametrize("path,limit", CAP_PATHS, ids=lambda value: str(value))
def test_snapshot_sibling_caps_precede_copy(path: tuple[Any, ...], limit: int) -> None:
    args = producer_args()
    args["snapshot"] = updated(args["snapshot"], path, (18000,) * (limit + 1))
    rejected_without_copy(args, args["snapshot"])


UNKNOWN_PATHS = [
    (),
    ("source",),
    ("source", "original"),
    ("source", "lineage", 0),
    ("source", "lineage", 0, "quality"),
    ("source", "lineage", 0, "source"),
    ("source", "quality"),
    ("source", "original", "flow_records", 0),
    ("source", "original", "flow_records", 0, "fields"),
    ("source", "original", "analysis"),
]


@pytest.mark.parametrize("path", UNKNOWN_PATHS, ids=str)
def test_snapshot_closed_names_precede_poison(path: tuple[Any, ...]) -> None:
    args = producer_args()
    args["snapshot"] = updated(args["snapshot"], (*path, "unknown"), object())
    rejected_without_copy(args, args["snapshot"])


def test_valid_snapshot_keeps_original_binding() -> None:
    args = producer_args()
    snapshot = args["snapshot"]
    checked = g._checked(g.HistoricalReadSnapshot, snapshot)
    assert checked == snapshot
    assert (
        g.produce_generation(**args).sources[0].source_binding_sha256
        == snapshot.source_binding_sha256
    )


@pytest.mark.parametrize("role", ["flow", "candidate", "allowlist", "sensor", "evidence", "factor"])
def test_known_raw_scalar_does_not_visit_mapping_values(role: str) -> None:
    key = {
        "flow": "sensor_id",
        "candidate": "candidate_ip",
        "allowlist": "type",
        "sensor": "status",
        "evidence": "description",
        "factor": "explanation",
    }[role]
    poison = object()
    calls = []
    code = g._snapshot_raw.__code__

    def observe(frame: Any, event: str, arg: Any) -> None:
        if event == "call" and frame.f_code is code and frame.f_locals["value"] is poison:
            calls.append(1)

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError):
            g._snapshot_raw({key: {"poison": poison}}, role)
    finally:
        sys.setprofile(previous)
    assert not calls


def candidate_snapshot() -> Any:
    args = producer_args()
    candidate = g.h.project_candidate(
        {
            "id": "candidate",
            "candidate_ip": "203.0.113.9",
            "score": 1,
            "evidence": [{"metrics": {"opaque": [["name", 1]], "object": {"name": 1}}}],
            "prefilter_factors": [{}],
        },
        position=0,
    )
    return args["snapshot"].model_copy(update={"candidates": (candidate,)})


@pytest.mark.parametrize(
    "path,limit",
    [
        (("candidates", 0, "fields", "ports"), 128),
        (("candidates", 0, "fields", "hosts"), 128),
        (("candidates", 0, "fields", "protocols"), 128),
        (("candidates", 0, "fields", "internal_hosts"), 128),
        (("candidates", 0, "fields", "prefilter_factors"), 128),
        (("candidates", 0, "fields", "evidence"), 262144),
    ],
)
def test_candidate_raw_caps_before_snapshot_copy(path: tuple[Any, ...], limit: int) -> None:
    args = producer_args()
    args["snapshot"] = updated(candidate_snapshot(), path, [18000] * (limit + 1))
    rejected_without_copy(args, args["snapshot"])


@pytest.mark.parametrize(
    "path",
    [
        ("candidates", 0),
        ("candidates", 0, "fields"),
        ("candidates", 0, "fields", "evidence", 0),
        ("candidates", 0, "fields", "prefilter_factors", 0),
    ],
)
def test_candidate_unknown_before_snapshot_copy(path: tuple[Any, ...]) -> None:
    args = producer_args()
    args["snapshot"] = updated(candidate_snapshot(), (*path, "unknown"), object())
    rejected_without_copy(args, args["snapshot"])


def test_comparison_candidate_kind_and_order_survive_readmission() -> None:
    snapshot = candidate_snapshot()
    a = snapshot.candidates[0]
    b = g.h.project_candidate(
        {"id": "second", "candidate_ip": "203.0.113.10", "score": 1.0}, position=1
    )
    snapshot = snapshot.model_copy(update={"candidates": (b, a)})
    checked = g._checked(g.HistoricalReadSnapshot, snapshot)
    assert checked == snapshot
    assert checked.candidates[0].position == 1
    assert g.h.source_binding_sha256(
        checked.source.source_binding(), purpose="COMPARISON", candidates=checked.candidates
    ) == g.h.source_binding_sha256(
        snapshot.source.source_binding(), purpose="COMPARISON", candidates=snapshot.candidates
    )
    args = producer_args()
    args["snapshot"] = checked
    with pytest.raises(ValueError, match="BASELINE_SOURCE_CHANGED"):
        g.produce_generation(**args)


@pytest.mark.parametrize(
    "value",
    [
        {"present": True, "value": {"warnings": [18000] * 129}},
        {"present": True, "value": {"failed_sensors": [18000] * 129}},
        {"present": True, "value": {"sensors": {str(n): {} for n in range(129)}}},
        {"present": True, "value": {"unknown": object()}},
        {"present": True, "value": {"sensors": {"sensor": {"unknown": object()}}}},
        {"present": True, "unknown": object(), "value": {}},
    ],
)
def test_operations_observed_closure_precedes_copy(value: Any) -> None:
    args = producer_args()
    args["snapshot"] = updated(args["snapshot"], ("source", "original", "operations"), value)
    rejected_without_copy(args, args["snapshot"])


@pytest.mark.parametrize(
    "value",
    [
        {"present": True, "value": [18000] * 129},
        {"present": True, "value": [{"unknown": object()}]},
    ],
)
def test_allowlist_observed_closure_precedes_copy(value: Any) -> None:
    args = producer_args()
    args["snapshot"] = updated(args["snapshot"], ("source", "original", "allowlist"), value)
    rejected_without_copy(args, args["snapshot"])


@pytest.mark.parametrize("field", ["capture_completions", "failed_sensors"])
def test_lineage_observed_array_before_copy(field: str) -> None:
    args = producer_args()
    args["snapshot"] = updated(
        args["snapshot"],
        ("source", "lineage", 0, "quality", field),
        {"present": True, "value": (18000,) * 129},
    )
    rejected_without_copy(args, args["snapshot"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("packet_sizes", (18000,) * 129),
        ("tcp_flags", {str(n): 1 for n in range(17)}),
        ("tcp_syn_only_observations", ((0, 1),) * 257),
    ],
)
@pytest.mark.parametrize("typed", [True, False])
def test_flow_collection_before_copy(field: str, value: Any, typed: bool) -> None:
    from dataclasses import replace

    args = producer_args()
    row = args["snapshot"].source.strict_flows[0]
    row = replace(row, **{field: value}) if typed else dict(vars(row), **{field: value})
    args["snapshot"] = updated(args["snapshot"], ("source", "strict_flows", 0), row)
    rejected_without_copy(args, args["snapshot"])


def test_exact_2048_candidates_readmit_but_cannot_approve() -> None:
    args = producer_args()
    candidates = tuple(
        g.h.project_candidate(
            {"id": f"c-{n}", "candidate_ip": "203.0.113.9", "score": 1}, position=n
        )
        for n in range(2048)
    )
    args["snapshot"] = args["snapshot"].model_copy(update={"candidates": candidates})
    checked = g._checked(g.HistoricalReadSnapshot, args["snapshot"])
    assert checked.candidates == candidates
    with pytest.raises(ValueError, match="BASELINE_SOURCE_CHANGED"):
        g.produce_generation(**args)


def test_exact_128_trusted_peers_remain_source_valid() -> None:
    from tests.test_historical_generation import empty_scope, snapshot_for, source_job

    raw = source_job(0)
    raw["flow_records"] = [
        dict(raw["flow_records"][0], destination_ip=f"203.0.113.{n}") for n in range(1, 129)
    ]
    raw["allowlist"] = [{"type": "CIDR", "value": "203.0.113.0/24", "description": "test peers"}]
    snapshot = snapshot_for(raw, empty_scope().config)
    assert len(snapshot.source.trusted_peers) == 128
    checked = g._checked(g.HistoricalReadSnapshot, snapshot)
    assert checked == snapshot
    args = producer_args()
    args["snapshot"] = checked
    args["request"] = args["request"].model_copy(
        update={"source_binding_sha256": checked.source_binding_sha256}
    )
    with pytest.raises(ValueError, match="BASELINE_SOURCE_QUALITY"):
        g.produce_generation(**args)


def test_source_measurements_and_long_opaque_tuples_are_not_reason_codes() -> None:
    from tests.test_historical_generation import empty_scope, snapshot_for, source_job

    raw = source_job(0)
    names = [
        "".join(c.upper() if bits & (1 << i) else c for i, c in enumerate("payload"))
        for bits in range(40)
    ]
    for row in raw["flow_records"]:
        row.update({name: "omitted-sensitive-content" for name in names})
        row.update(
            payload_entropy=7.25,
            payload_printable_ratio=0.75,
            domain="example.invalid",
            packet_sizes=list(range(128)),
        )
    snapshot = snapshot_for(raw, empty_scope().config)
    checked = g._checked(g.HistoricalReadSnapshot, snapshot)
    assert checked == snapshot
    assert len(checked.source.original.flow_records[0].sensitive_keys_present) == 40
    assert checked.source.strict_flows[0].payload_entropy == 7.25
    assert checked.source.strict_flows[0].packet_sizes == tuple(range(128))
    candidate = g.h.project_candidate(
        {
            "id": "opaque",
            "candidate_ip": "203.0.113.9",
            "score": 1,
            "evidence": [{"metrics": {"array": list(range(64)), "pairs": [["k", 1]]}}],
        },
        position=0,
    )
    snapshot = snapshot.model_copy(update={"candidates": (candidate,)})
    assert g._checked(g.HistoricalReadSnapshot, snapshot) == snapshot


def test_snapshot_preflight_neither_thaws_nor_copies() -> None:
    snapshot = candidate_snapshot()
    calls = []
    codes = (g._unmodel.__code__, g.h.thaw_original_json.__code__, g.h._freeze.__code__)

    def observe(frame: Any, event: str, arg: Any) -> None:
        if event == "call" and frame.f_code in codes:
            calls.append(frame.f_code.co_name)

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        g._snapshot_preflight(snapshot, g.HistoricalReadSnapshot)
    finally:
        sys.setprofile(previous)
    assert not calls


@pytest.mark.parametrize("field,limit", [("candidates", 2048), ("lineage", 16)])
def test_real_sibling_members_reject_before_copy(field: str, limit: int) -> None:
    args = producer_args()
    if field == "candidates":
        member = candidate_snapshot().candidates[0]
        path = (field,)
    else:
        member = args["snapshot"].source.lineage[0]
        path = ("source", field)
    args["snapshot"] = updated(args["snapshot"], path, (member,) * (limit + 1))
    rejected_without_copy(args, args["snapshot"])


def test_detector_weight_unknown_name_precedes_poison() -> None:
    args = producer_args()
    poison = object()
    args["snapshot"] = updated(
        args["snapshot"],
        ("source", "original", "analysis", "detector_weights"),
        {"unknown": poison},
    )
    visits = []
    codes = (g._snapshot_preflight.__code__, g._snapshot_raw.__code__, g._unmodel.__code__)

    def observe(frame: Any, event: str, arg: Any) -> None:
        if event == "call" and frame.f_code in codes and frame.f_locals["value"] is poison:
            visits.append(1)

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError):
            g.produce_generation(**args)
    finally:
        sys.setprofile(previous)
    assert not visits


@pytest.mark.parametrize(
    "field",
    ["sensor_id", "payload_entropy", "average_packet_size", "packet_count", "bidirectional"],
)
@pytest.mark.parametrize("typed", [True, False])
def test_flow_scalar_shape_before_snapshot_copy(field: str, typed: bool) -> None:
    from dataclasses import replace

    args = producer_args()
    row = args["snapshot"].source.strict_flows[0]
    change = {field: {"poison": [18000] * 4096}}
    row = replace(row, **change) if typed else dict(vars(row), **change)
    args["snapshot"] = updated(args["snapshot"], ("source", "strict_flows", 0), row)
    rejected_without_copy(args, args["snapshot"])
