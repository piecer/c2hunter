"""Finite independent cross-boundary corpus; no imported candidate test fixtures."""

import json
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import permutations
from uuid import UUID

import pytest

from c2hunter_analysis import behavior_baseline as b
from c2hunter_analysis.domain import Flow

T0 = datetime(2025, 6, 1, tzinfo=UTC)
S = b.BaselineScopeIdentity(
    "1" * 64,
    "OPERATIONAL",
    "logical",
    "actual",
    ("192.168.0.0/16",),
    60,
    (b.HostEpoch("192.168.1.10", "lease-A"),),
    "behavior-window-v1",
)
OBS = b.ObservationIdentity("current", "dataset-current", "e" * 64)


def req(
    start=T0,
    *,
    receipt=None,
    size_change=False,
    direction_change=False,
    aggregate=False,
    peer="203.0.113.9",
    port=443,
):
    rows = tuple(
        Flow(
            "actual",
            start + timedelta(seconds=i * 2),
            "192.168.1.10",
            peer,
            50000 + i,
            port,
            "TCP",
            "OUTBOUND",
            packet_count=2 if aggregate else 1,
            total_bytes=100 if size_change else (20 if i < 4 else 180),
            duration_seconds=1 if aggregate else 0,
        )
        for i in range(8)
    )
    if not direction_change:
        rows += (
            Flow(
                "actual",
                start + timedelta(seconds=20),
                peer,
                "192.168.1.10",
                port,
                50000,
                "TCP",
                "INBOUND",
                total_bytes=800,
            ),
        )
    return b.BaselineBuildInput(
        S, "actual", False, start, start + timedelta(seconds=60), rows, (), receipt
    )


def history(*, aggregate=False):
    return b.BaselineReference(
        tuple(
            b.ReferenceWindow(
                b.build_behavior_windows(
                    req(
                        T0 + timedelta(hours=i * 12),
                        receipt=str(UUID(int=i + 11)),
                        aggregate=aggregate,
                    )
                )
                .profiles[0]
                .window,
                b.ObservationIdentity(f"root-{i}", f"dataset-{i}", f"{i + 100:064x}"),
            )
            for i in range(3)
        )
    )


def compare(request=None, reference=None, *, vetoes=(), observation=OBS, target=None):
    request = request or req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    return b.compare_behavior_windows(
        target=target or b.build_behavior_windows(request),
        reference=reference,
        scope=request.scope,
        target_observation=observation,
        target_event_start=request.event_start,
        target_event_end=request.event_end,
        target_vetoes=vetoes,
    )


def canonical(x):
    return json.dumps(
        x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


@pytest.mark.parametrize("aggregate", [False, True])
def test_independent_positive_score_math_and_immutable_roundtrip(aggregate):
    r = compare(
        req(T0 + timedelta(days=2), size_change=True, direction_change=True, aggregate=aggregate),
        history(aggregate=aggregate),
    )
    c = r.comparisons[0]
    assert (
        c.status == "READY" and c.size_dispersion.robust_z == 16 and c.outbound_share.robust_z == 10
    )
    assert c.historical_anomaly_score == 46 and len(r.candidates) == 1
    assert tuple(f.points for f in r.candidates[0].candidate.factors) == (26, 20)
    encoded = b.baseline_comparison_to_mapping(r)
    restored = b.baseline_comparison_from_mapping(json.loads(canonical(encoded)))
    assert restored == r
    encoded["candidates"][0]["candidate"]["factors"][0]["metrics"]["robust_z"] = 0
    assert restored.candidates[0].candidate.factors[0].metrics["robust_z"] == 16
    with pytest.raises(TypeError):
        restored.candidates[0].candidate.factors[0].metrics["robust_z"] = 0


@pytest.mark.parametrize("size,direction", [(False, False), (True, False), (False, True)])
def test_independent_matching_and_one_family_are_nonpositive(size, direction):
    r = compare(
        req(T0 + timedelta(days=2), size_change=size, direction_change=direction), history()
    )
    assert r.comparisons[0].status == "READY"
    assert not r.candidates and r.comparisons[0].historical_anomaly_score == 0
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(r)) == r


@pytest.mark.parametrize(
    "veto", ["TARGET_REVIEW_REQUIRED", "TARGET_PARTIAL_CAPTURE", "SOURCE_CLOCK_UNCERTAIN"]
)
@pytest.mark.parametrize("with_reference", [False, True])
def test_each_global_quality_veto_dominates_current_and_history(veto, with_reference):
    r = compare(reference=history() if with_reference else None, vetoes=(veto,))
    c = r.comparisons[0]
    assert c.status == "INCOMPATIBLE" and c.historical_anomaly_score == 0 and not r.candidates
    for n in b.FEATURES:
        f = getattr(c, n)
        assert f.current is not None and f.status == "INCOMPATIBLE"
        assert (
            f.reference_median,
            f.reference_scale,
            f.robust_z,
            f.eligible_window_ids,
            f.drifting,
        ) == (None, None, None, (), False)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("packet_count", True),
        ("packet_count", 10**1000),
        ("total_bytes", None),
        ("total_bytes", False),
        ("duration_seconds", float("inf")),
        ("duration_seconds", float("nan")),
        ("duration_seconds", True),
        ("duration_seconds", 0.0000005),
        ("timestamp", T0.replace(tzinfo=None)),
        ("tcp_syn_only_observations", ((True, 1),)),
        ("tcp_syn_only_observations", ((0, False),)),
        ("tcp_flags", {"syn": True}),
    ],
)
def test_strict_source_tail_rejects_valid_prefix(field, bad):
    r = req()
    with pytest.raises(b.BaselineInputError):
        b.build_behavior_windows(replace(r, flows=r.flows + (replace(r.flows[0], **{field: bad}),)))


@pytest.mark.parametrize("budget", ["flows", "syn", "trusted", "hosts", "networks"])
def test_raw_budget_rejection_before_normalization_and_copy(monkeypatch, budget):
    r = req()
    if budget == "flows":
        r = replace(r, flows=r.flows[:1] * 8193)
    if budget == "syn":
        r = replace(
            r, flows=tuple(replace(f, tcp_syn_only_observations=((0, 2),) * 33) for f in r.flows)
        )
    if budget == "trusted":
        r = replace(r, trusted_peers=("203.0.113.9",) * 129)
    if budget == "hosts":
        r = replace(r, scope=replace(S, hosts=S.hosts * 129))
    if budget == "networks":
        r = replace(r, scope=replace(S, internal_networks=S.internal_networks * 129))

    def forbidden(*a, **k):
        pytest.fail("normalization/copy before raw cardinality admission")

    monkeypatch.setattr(b, "ip_address", forbidden)
    monkeypatch.setattr(b, "ip_network", forbidden)
    monkeypatch.setattr(b, "replace", forbidden)
    with pytest.raises(b.BaselineInputError) as e:
        b.build_behavior_windows(r)
    assert e.value.code == "BASELINE_SOURCE_LIMIT"


def test_profile_limit_precedes_suppression_and_feature_work(monkeypatch):
    r = req()
    r = replace(
        r,
        flows=tuple(replace(r.flows[0], destination_port=p) for p in range(129)),
        trusted_peers=("203.0.113.9",),
    )

    def forbidden(*a, **k):
        pytest.fail("feature/suppression invoked before raw profile admission")

    monkeypatch.setattr(b, "syn_retry_duplicate_flow_ids", forbidden)
    monkeypatch.setattr(b, "outbound_control_flood_flow_ids", forbidden)
    monkeypatch.setattr(b, "_dispersion", forbidden)
    with pytest.raises(b.BaselineInputError) as e:
        b.build_behavior_windows(r)
    assert e.value.code == "BASELINE_PROFILE_LIMIT"


@pytest.mark.parametrize(
    "bad_identity", ["root_identity", "dataset_id", "feature_observation_sha256"]
)
def test_single_target_identity_collision_removes_only_that_receipt(bad_identity):
    h = history()
    first = h.windows[0]
    h = replace(
        h,
        windows=(
            replace(
                first,
                observation=replace(
                    first.observation, **{bad_identity: getattr(OBS, bad_identity)}
                ),
            ),
            *h.windows[1:],
        ),
    )
    r = compare(reference=h)
    c = r.comparisons[0]
    assert c.status == "INSUFFICIENT" and not r.candidates
    for name in b.FEATURES:
        f = getattr(c, name)
        assert f.eligible_window_ids == tuple(w.window.source_receipt_id for w in h.windows[1:])
        assert f.excluded_future_count == 0


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_equal_cutoff_and_microsecond_future_filter(delta):
    target = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    h = history()
    first = h.windows[0]
    end = target.event_start + timedelta(microseconds=delta)
    h = replace(
        h,
        windows=(
            *h.windows,
            replace(
                first,
                window=replace(
                    first.window,
                    source_receipt_id=str(UUID(int=99)),
                    event_start=end - timedelta(seconds=60),
                    event_end=end,
                ),
                observation=b.ObservationIdentity("extra", "extra", "d" * 64),
            ),
        ),
    )
    r = compare(target, h)
    for name in b.FEATURES:
        f = getattr(r.comparisons[0], name)
        assert f.excluded_future_count == (0 if delta < 0 else 1)
        assert len(f.eligible_window_ids) == (4 if delta < 0 else 3)
    assert r.comparisons[0].historical_anomaly_score == 46


@pytest.mark.parametrize("extra_microsecond", [0, 1])
def test_freshness_exact_seven_days(extra_microsecond):
    h = history()
    t = h.windows[-1].window.event_end + timedelta(days=7, microseconds=extra_microsecond)
    r = compare(req(t, size_change=True, direction_change=True), h)
    assert r.comparisons[0].status == ("READY" if extra_microsecond == 0 else "STALE")
    assert bool(r.candidates) == (extra_microsecond == 0)


def test_future_feature_local_support_and_permutation_bytes():
    h = history()
    t = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    first = h.windows[0]
    future = replace(
        first,
        window=replace(
            first.window,
            source_receipt_id=str(UUID(int=99)),
            event_start=t.event_start,
            event_end=t.event_end,
            recurrence=None,
            limitations=("PACKET_TIMING_UNAVAILABLE",),
        ),
        observation=b.ObservationIdentity("extra", "extra", "d" * 64),
    )
    h = replace(h, windows=(*h.windows, future))
    expected = canonical(b.baseline_comparison_to_mapping(compare(t, h)))
    for refs in permutations(h.windows):
        rr = compare(replace(t, flows=tuple(reversed(t.flows))), replace(h, windows=refs))
        assert canonical(b.baseline_comparison_to_mapping(rr)) == expected
        assert rr.comparisons[0].recurrence.excluded_future_count == 0
        assert rr.comparisons[0].outbound_share.excluded_future_count == 1


@pytest.mark.parametrize("port", [53, 123, None])
def test_excluded_services_do_not_hide_other_streams(port):
    r = req()
    extra = tuple(replace(f, destination_port=port) for f in r.flows[:8])
    r = replace(r, flows=r.flows + extra)
    built = b.build_behavior_windows(r)
    assert built.raw_profile_count == 2 and built.eligible_profile_count == 1
    compared = compare(r, None, target=built)
    assert compared.unprofiled_count == 1 and len(compared.comparisons) == 1


def test_mixed_representation_and_inbound_aggregate_differ():
    r = req()
    mixed = replace(r, flows=(replace(r.flows[0], packet_count=2), *r.flows[1:]))
    w = b.build_behavior_windows(mixed).profiles[0].window
    assert w.key.observation_kind == "AGGREGATE" and w.recurrence is None
    assert "MIXED_REPRESENTATION" in w.limitations
    inbound = replace(
        r, flows=(*r.flows[:8], replace(r.flows[-1], packet_count=100, duration_seconds=20))
    )
    w = b.build_behavior_windows(inbound).profiles[0].window
    assert w.key.observation_kind == "PACKET" and w.recurrence == 0


def test_stream_winner_lexical_not_numeric_and_score_precedence():
    t = req(T0 + timedelta(days=2), size_change=True, direction_change=True, port=80)
    t = replace(t, flows=t.flows + tuple(replace(f, destination_port=100) for f in t.flows))
    h = history()
    h = replace(
        h,
        windows=tuple(
            replace(x, window=replace(x.window, key=replace(x.window.key, service_port=p)))
            for p in (80, 100)
            for x in h.windows
        ),
    )
    expected = b.baseline_comparison_to_mapping(compare(t, h))
    assert expected["candidates"][0]["comparison_key"]["service_port"] == 100
    for seed in range(8):
        flows = list(t.flows)
        refs = list(h.windows)
        random.Random(seed).shuffle(flows)
        random.Random(seed + 1).shuffle(refs)
        assert canonical(
            b.baseline_comparison_to_mapping(
                compare(replace(t, flows=tuple(flows)), replace(h, windows=tuple(refs)))
            )
        ) == canonical(expected)
    h = replace(
        h,
        windows=tuple(
            replace(x, window=replace(x.window, size_dispersion=0.5))
            if x.window.key.service_port == 100
            else x
            for x in h.windows
        ),
    )
    assert compare(t, h).candidates[0].comparison_key.service_port == 80


def test_suppression_mixed_same_stream_preserves_ack_payload_udp_inbound():
    r = req()
    seed = replace(
        r.flows[0],
        source_port=50000,
        tcp_flags_observed=True,
        tcp_flags={"syn": 1000},
        tcp_syn_count=1000,
        tcp_syn_only_count=1000,
        packet_count=1000,
        total_bytes=60000,
        duration_seconds=1,
    )
    ack = replace(
        seed,
        timestamp=T0 + timedelta(seconds=2),
        packet_count=2,
        total_bytes=120,
        tcp_flags={"syn": 1, "ack": 1},
        tcp_syn_count=1,
        tcp_syn_only_count=1,
        tcp_ack_count=1,
    )
    payload = replace(
        seed,
        timestamp=T0 + timedelta(seconds=3),
        packet_count=1,
        total_bytes=90,
        tcp_flags={"syn": 1},
        tcp_syn_count=1,
        tcp_syn_only_count=1,
        payload_length=30,
    )
    udp = tuple(replace(f, protocol="UDP") for f in r.flows)
    r = replace(r, flows=(*r.flows, seed, ack, payload, *udp))
    expected = b.build_behavior_windows(r)
    tcp = next(p.window for p in expected.profiles if p.stream.protocol == "TCP")
    u = next(p.window for p in expected.profiles if p.stream.protocol == "UDP")
    assert tcp.outbound_record_count == 10 and tcp.outbound_share == 1010 / 1810
    assert u.outbound_record_count == 8 and u.outbound_share == 0.5
    assert "SUPPRESSED_CONTROL_OR_RETRY_ROWS" in tcp.limitations
    for seednum in range(8):
        rows = list(r.flows)
        random.Random(seednum).shuffle(rows)
        assert b.build_behavior_windows(replace(r, flows=tuple(rows))) == expected


@pytest.mark.parametrize("boundary", ["build", "reference", "comparison"])
@pytest.mark.parametrize("bad", [True, float("nan"), float("inf"), 10**1000, None])
def test_numeric_mapping_cross_boundary_rejects_closed_scalars(boundary, bad):
    if boundary == "build":
        value = b.baseline_build_to_mapping(b.build_behavior_windows(req()))
        value["profiles"][0]["window"]["outbound_record_count"] = bad
        decode = b.baseline_build_from_mapping
    elif boundary == "reference":
        value = b.baseline_reference_to_mapping(history())
        value["windows"][0]["window"]["outbound_record_count"] = bad
        decode = b.baseline_reference_from_mapping
    else:
        value = b.baseline_comparison_to_mapping(compare(reference=history()))
        value["comparisons"][0]["features"]["size_dispersion"]["robust_z"] = bad
        decode = b.baseline_comparison_from_mapping
    with pytest.raises(b.BaselineInputError):
        decode(value)


@pytest.mark.parametrize(
    "mutation",
    ["factors_missing", "factor_points", "factor_count", "wrong_winner", "unprofiled_overflow"],
)
def test_comparison_factor_and_provenance_lies_rejected(mutation):
    value = b.baseline_comparison_to_mapping(compare(reference=history()))
    if mutation == "factors_missing":
        value["candidates"][0]["candidate"]["factors"].pop()
    if mutation == "factor_points":
        value["candidates"][0]["candidate"]["factors"][0]["points"] = 25
    if mutation == "factor_count":
        value["candidates"][0]["candidate"]["factors"][0]["metrics"]["reference_windows"] = 4
    if mutation == "wrong_winner":
        value["candidates"][0]["comparison_key"]["service_port"] = 80
    if mutation == "unprofiled_overflow":
        value["unprofiled_count"] = 128
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_from_mapping(value)


@pytest.mark.parametrize(
    "reason",
    [
        "TARGET_REVIEW_REQUIRED",
        "TARGET_PARTIAL_CAPTURE",
        "SOURCE_CLOCK_UNCERTAIN",
        "INSUFFICIENT_STREAM_SAMPLES",
    ],
)
def test_strict_comparison_inverse_rejects_positive_with_whole_profile_veto(reason):
    value = b.baseline_comparison_to_mapping(compare(reference=history()))
    # Ordinary decoded JSON only; all limitation projections agree after mutation.
    value["limitations"] = sorted(set(value["limitations"]) | {reason})
    value["comparisons"][0]["limitations"] = sorted(
        set(value["comparisons"][0]["limitations"]) | {reason}
    )
    value["candidates"][0]["candidate"]["limitations"] = value["comparisons"][0][
        "limitations"
    ].copy()
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_from_mapping(value)


@pytest.mark.parametrize(
    "reason", ["TRUSTED_PEERS_EXCLUDED", "COMMON_SERVICES_EXCLUDED", "SERVICE_PORT_UNAVAILABLE"]
)
def test_strict_build_inverse_rejects_eligible_excluded_stream(reason):
    value = b.baseline_build_to_mapping(b.build_behavior_windows(req()))
    value["limitations"] = [reason]
    value["profiles"][0]["reasons"] = [reason]
    value["profiles"][0]["window"]["limitations"] = [reason]
    with pytest.raises(b.BaselineInputError):
        b.baseline_build_from_mapping(value)


@pytest.mark.parametrize(
    "reason", ["TRUSTED_PEERS_EXCLUDED", "COMMON_SERVICES_EXCLUDED", "SERVICE_PORT_UNAVAILABLE"]
)
def test_source_publication_rejects_explicitly_excluded_window(reason):
    w = history().windows[0].window
    with pytest.raises(b.BaselineInputError):
        b.behavior_window_to_mapping(replace(w, limitations=(reason,)))


@pytest.mark.parametrize("protocol", ["S" * 256, "ß" * 128, "ß" * 256])
def test_admitted_raw_protocol_always_roundtrips(protocol):
    r = req()
    r = replace(r, flows=tuple(replace(f, protocol=protocol) for f in r.flows))
    try:
        built = b.build_behavior_windows(r)
    except b.BaselineInputError:
        return  # a bounded invalid protocol may be rejected at admission
    assert b.baseline_build_from_mapping(b.baseline_build_to_mapping(built)) == built
