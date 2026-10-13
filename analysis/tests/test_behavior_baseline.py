import json
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from c2hunter_analysis import behavior_baseline as b
from c2hunter_analysis.domain import Flow

START = datetime(2026, 1, 1, tzinfo=UTC)
SCOPE = b.BaselineScopeIdentity(
    "a" * 64,
    "OPERATIONAL",
    "sensor",
    "sensor",
    ("10.0.0.0/8",),
    60,
    (b.HostEpoch("10.0.0.1", "epoch"),),
    "behavior-window-v1",
)
TARGET_OBSERVATION = b.ObservationIdentity("target-root", "target-data", "f" * 64)


def request(start=START, *, receipt=None, varied=True, inbound=True, aggregate=False):
    rows = tuple(
        Flow(
            "sensor",
            start + timedelta(seconds=i),
            "10.0.0.1",
            "8.8.8.8",
            40000,
            443,
            "TCP",
            "OUTBOUND",
            packet_count=2 if aggregate else 1,
            total_bytes=(10 if i < 4 else 90) if varied else 50,
            duration_seconds=0.1 if aggregate else 0,
        )
        for i in range(8)
    )
    if inbound:
        rows += (
            Flow(
                "sensor",
                start,
                "8.8.8.8",
                "10.0.0.1",
                443,
                40000,
                "TCP",
                "INBOUND",
                total_bytes=400,
            ),
        )
    return b.BaselineBuildInput(
        SCOPE, "sensor", False, start, start + timedelta(seconds=60), rows, (), receipt
    )


def history(**kwargs):
    windows = []
    for i, hours in enumerate((0, 12, 24)):
        result = b.build_behavior_windows(
            request(START + timedelta(hours=hours), receipt=str(UUID(int=i + 1)), **kwargs)
        )
        assert result.eligible_profile_count == 1
        window = result.profiles[0].window
        assert window is not None
        windows.append(
            b.ReferenceWindow(window, b.ObservationIdentity(f"root-{i}", f"data-{i}", str(i) * 64))
        )
    return b.BaselineReference(tuple(windows))


def compare(req, reference, **kwargs):
    vetoes = kwargs.pop("target_vetoes", ())
    observation = kwargs.pop("target_observation", TARGET_OBSERVATION)
    return b.compare_behavior_windows(
        target=b.build_behavior_windows(req),
        reference=reference,
        scope=req.scope,
        target_observation=observation,
        target_event_start=req.event_start,
        target_event_end=req.event_end,
        target_vetoes=vetoes,
        **kwargs,
    )


@pytest.mark.parametrize("varied,inbound", [(True, True), (False, True), (True, False)])
def test_matching_and_one_family_change_are_not_candidates(varied, inbound):
    result = compare(request(START + timedelta(days=2), varied=varied, inbound=inbound), history())
    assert result.candidates == ()
    assert result.comparisons[0].status == "READY"
    assert result.comparisons[0].historical_anomaly_score == 0


@pytest.mark.parametrize("kind", ["aggregate", "mixed", "tied", "bidirectional", "seven", "zero"])
def test_feature_eligibility_keeps_single_classified_window(kind):
    req = request(aggregate=kind == "aggregate")
    if kind == "mixed":
        req = replace(req, flows=(replace(req.flows[0], packet_count=2), *req.flows[1:]))
    if kind == "tied":
        req = replace(req, flows=tuple(replace(f, timestamp=START) for f in req.flows))
    if kind == "bidirectional":
        req = replace(req, flows=(replace(req.flows[0], bidirectional=True), *req.flows[1:]))
    if kind == "seven":
        req = replace(req, flows=req.flows[1:])
    if kind == "zero":
        req = replace(req, flows=tuple(replace(f, total_bytes=0) for f in req.flows))
    built = b.build_behavior_windows(req)
    assert built.raw_profile_count == 1
    w = built.profiles[0].window
    assert w is not None
    if kind in {"aggregate", "mixed"}:
        assert w.key.observation_kind == "AGGREGATE"
    else:
        assert w.key.observation_kind == "PACKET"
    if kind in {"aggregate", "mixed", "tied", "seven"}:
        assert w.recurrence is None
    if kind in {"bidirectional", "zero", "seven"}:
        assert w.outbound_share is None
    if kind == "seven":
        assert w.size_dispersion is None
        assert not built.profiles[0].eligible_for_reference
        assert "INSUFFICIENT_STREAM_SAMPLES" in w.limitations
    if kind == "mixed":
        assert "MIXED_REPRESENTATION" in w.limitations


@pytest.mark.parametrize(
    "case,status",
    [
        ("aggregate", "READY"),
        ("seven", "INCOMPATIBLE"),
        ("veto_missing", "INCOMPATIBLE"),
        ("no_reference", "MISSING"),
        ("representation", "MISSING"),
        ("two", "INSUFFICIENT"),
        ("short_span", "INSUFFICIENT"),
        ("exact_span", "READY"),
        ("stale_two", "STALE"),
        ("exact_fresh", "READY"),
        ("stale", "STALE"),
        ("future", "MISSING"),
        ("equal", "MISSING"),
        ("overlap", "MISSING"),
        ("self_root", "MISSING"),
        ("self_dataset", "MISSING"),
        ("self_digest", "MISSING"),
    ],
)
def test_comparison_precedence_and_causal_boundaries(case, status):
    ref = history(aggregate=case == "aggregate")
    req = request(
        START + timedelta(days=2),
        varied=False,
        inbound=False,
        aggregate=case in {"aggregate", "representation"},
    )
    kwargs = {}
    if case == "seven":
        req = replace(req, flows=req.flows[:7])
    if case in {"veto_missing", "no_reference"}:
        ref = None
    if case == "veto_missing":
        kwargs["target_vetoes"] = ("TARGET_REVIEW_REQUIRED",)
    if case in {"two", "stale_two"}:
        ref = replace(ref, windows=ref.windows[:2])
    if case in {"short_span", "exact_span"}:
        last = ref.windows[-1]
        end = START + timedelta(days=1) - timedelta(microseconds=case == "short_span")
        ref = replace(
            ref,
            windows=(
                *ref.windows[:2],
                replace(
                    last,
                    window=replace(
                        last.window, event_start=end - timedelta(seconds=60), event_end=end
                    ),
                ),
            ),
        )
    if case in {"exact_fresh", "stale", "stale_two"}:
        start = ref.windows[-1].window.event_end + timedelta(days=7)
        start += timedelta(microseconds=case != "exact_fresh")
        req = request(start, varied=False, inbound=False)
    if case in {"future", "equal", "overlap"}:
        shift = {
            "future": timedelta(seconds=60),
            "equal": timedelta(0),
            "overlap": timedelta(seconds=-30),
        }[case]
        ref = replace(
            ref,
            windows=tuple(
                replace(
                    r,
                    window=replace(
                        r.window,
                        event_start=req.event_start + shift,
                        event_end=req.event_start + shift + timedelta(seconds=60),
                    ),
                )
                for r in ref.windows
            ),
        )
        if case == "equal":
            ref = replace(
                ref,
                windows=tuple(
                    replace(
                        r,
                        window=replace(
                            r.window,
                            event_start=req.event_start - timedelta(seconds=60),
                            event_end=req.event_start,
                        ),
                    )
                    for r in ref.windows
                ),
            )
    if case.startswith("self_"):
        field = {
            "self_root": "root_identity",
            "self_dataset": "dataset_id",
            "self_digest": "feature_observation_sha256",
        }[case]
        ref = replace(
            ref,
            windows=tuple(
                replace(
                    r,
                    observation=replace(
                        r.observation, **{field: getattr(TARGET_OBSERVATION, field)}
                    ),
                )
                for r in ref.windows
            ),
        )
    result = compare(req, ref, **kwargs)
    row = result.comparisons[0]
    assert row.status == status
    if case == "aggregate":
        assert row.recurrence.status == "INCOMPATIBLE"
        assert row.size_dispersion.status == row.outbound_share.status == "READY"
        assert len(result.candidates) == 1
    elif status != "READY":
        assert not result.candidates
        assert row.historical_anomaly_score == 0
        for name in b.FEATURES:
            f = getattr(row, name)
            assert f.status == status
            assert (f.reference_median, f.reference_scale, f.robust_z) == (None, None, None)
            assert not f.drifting
            if case in {"future", "equal", "overlap"}:
                assert f.excluded_future_count == 3
            if status in {"INSUFFICIENT", "STALE"}:
                assert f.eligible_window_ids


@pytest.mark.parametrize(
    "excluded", ["trusted", "common", "missing_port", "inbound", "both", "neither"]
)
def test_excluded_streams_and_rows_remain_counted(excluded):
    req = request()
    extra = tuple(
        replace(
            f,
            destination_port=8443 if f.direction == "OUTBOUND" else f.destination_port,
            source_port=8443 if f.direction == "INBOUND" else f.source_port,
        )
        for f in req.flows
    )
    if excluded == "trusted":
        req = replace(req, trusted_peers=("8.8.8.8",))
    if excluded == "common":
        extra = tuple(
            replace(
                f,
                destination_port=53 if f.direction == "OUTBOUND" else f.destination_port,
                source_port=53 if f.direction == "INBOUND" else f.source_port,
            )
            for f in extra
        )
    if excluded == "missing_port":
        extra = tuple(
            replace(
                f,
                destination_port=None if f.direction == "OUTBOUND" else f.destination_port,
                source_port=None if f.direction == "INBOUND" else f.source_port,
            )
            for f in extra
        )
    if excluded == "inbound":
        extra = extra[-1:]
    if excluded in {"both", "neither"}:
        extra = (
            replace(extra[0], destination_ip="10.0.0.2")
            if excluded == "both"
            else replace(extra[0], source_ip="9.9.9.9"),
        )
    req = replace(req, flows=req.flows + extra)
    result = b.build_behavior_windows(req)
    if excluded in {"both", "neither"}:
        assert result.raw_profile_count == result.eligible_profile_count == 1
        assert result.excluded_row_count == 1
    else:
        assert result.raw_profile_count == 2
        assert result.excluded_profile_count == (2 if excluded == "trusted" else 1)
        assert sum(p.window is None for p in result.profiles) == result.excluded_profile_count
        compared = compare(req, None)
        assert compared.unprofiled_count == result.excluded_profile_count
        assert len(compared.comparisons) == result.eligible_profile_count


def test_raw_stream_129_rejected_even_when_all_trusted():
    req = request()
    req = replace(
        req,
        flows=tuple(replace(req.flows[0], destination_port=i) for i in range(129)),
        trusted_peers=("8.8.8.8",),
    )
    with pytest.raises(b.BaselineInputError) as caught:
        b.build_behavior_windows(req)
    assert caught.value.code == "BASELINE_PROFILE_LIMIT"
    result = b.build_behavior_windows(replace(req, flows=req.flows[:128]))
    assert result.raw_profile_count == result.excluded_profile_count == 128


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("packet_count", True, "BASELINE_SOURCE_INVALID"),
        ("packet_count", 0, "BASELINE_SOURCE_INVALID"),
        ("total_bytes", 2**53 + 1, "BASELINE_SOURCE_INVALID"),
        ("duration_seconds", float("nan"), "BASELINE_SOURCE_INVALID"),
        ("duration_seconds", 0.0000001, "BASELINE_SOURCE_INVALID"),
        ("duration_seconds", 61, "BASELINE_SOURCE_INVALID"),
        ("timestamp", START.replace(tzinfo=None), "BASELINE_SOURCE_INVALID"),
        ("timestamp", START - timedelta(microseconds=1), "BASELINE_SOURCE_INVALID"),
        ("source_port", True, "BASELINE_SOURCE_INVALID"),
        ("destination_port", 65536, "BASELINE_SOURCE_INVALID"),
        ("protocol", "", "BASELINE_SOURCE_INVALID"),
        ("protocol", "T\x00CP", "BASELINE_SOURCE_INVALID"),
        ("direction", "INBOUND", "BASELINE_SOURCE_INVALID"),
        ("direction", "bogus", "BASELINE_SOURCE_INVALID"),
        ("sensor_id", "foreign", "BASELINE_SCOPE_MISMATCH"),
        ("source_ip", "10.0.0.2", "BASELINE_SCOPE_MISMATCH"),
        ("destination_ip", "bad", "BASELINE_SOURCE_INVALID"),
        ("bidirectional", 1, "BASELINE_SOURCE_INVALID"),
        ("tcp_flags_observed", 1, "BASELINE_SOURCE_INVALID"),
        ("tcp_syn_only_observations_truncated", 1, "BASELINE_SOURCE_INVALID"),
        ("tcp_syn_count", True, "BASELINE_SOURCE_INVALID"),
        ("tcp_flags", {"SYN": float("inf")}, "BASELINE_SOURCE_INVALID"),
        ("tcp_flags", {"x" * 257: 1}, "BASELINE_SOURCE_INVALID"),
        ("tcp_flags", {str(i): 1 for i in range(17)}, "BASELINE_SOURCE_LIMIT"),
        ("tcp_syn_only_observations", ((-1, 1),), "BASELINE_SOURCE_INVALID"),
        ("tcp_syn_only_observations", ((0, 2**32),), "BASELINE_SOURCE_INVALID"),
        ("tcp_syn_only_observations", ((60_000_001, 1),), "BASELINE_SOURCE_INVALID"),
        ("payload_length", -1, "BASELINE_SOURCE_INVALID"),
        ("payload_hash", 1, "BASELINE_SOURCE_INVALID"),
    ],
)
def test_consumed_row_fields_reject_entire_request(field, value, code):
    req = request()
    req = replace(req, flows=(*req.flows, replace(req.flows[0], **{field: value})))
    with pytest.raises(b.BaselineInputError) as caught:
        b.build_behavior_windows(req)
    assert caught.value.code == code
    assert str(value) not in str(caught.value) if len(str(value)) > 5 else True


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("actual_sensor_id", "other", "BASELINE_SCOPE_MISMATCH"),
        ("sensor_alias_asserted", True, "BASELINE_SCOPE_MISMATCH"),
        ("sensor_alias_asserted", 1, "BASELINE_SOURCE_INVALID"),
        ("source_receipt_id", "bad", "BASELINE_SOURCE_INVALID"),
        ("event_end", START + timedelta(seconds=61), "BASELINE_SCOPE_MISMATCH"),
        ("trusted_peers", ("8.8.8.8",) * 129, "BASELINE_SOURCE_LIMIT"),
        ("trusted_peers", ("8.8.8.8",) * 2, "BASELINE_SOURCE_INVALID"),
        ("trusted_peers", ("8.8.8.0/24",), "BASELINE_SOURCE_INVALID"),
    ],
)
def test_build_request_identity_is_strict(field, value, code):
    with pytest.raises(b.BaselineInputError) as caught:
        b.build_behavior_windows(replace(request(), **{field: value}))
    assert caught.value.code == code


@pytest.mark.parametrize("budget", ["flows", "syn", "hosts", "networks"])
def test_raw_bounds_checked_before_feature_work(budget):
    req = request()
    if budget == "flows":
        req = replace(req, flows=(req.flows[0],) * 8193)
    elif budget == "syn":
        req = replace(
            req, flows=(replace(req.flows[0], tcp_syn_only_observations=((0, 1),) * 257),)
        )
    elif budget == "hosts":
        req = replace(req, scope=replace(SCOPE, hosts=SCOPE.hosts * 129))
    else:
        req = replace(req, scope=replace(SCOPE, internal_networks=SCOPE.internal_networks * 129))
    with pytest.raises(b.BaselineInputError) as caught:
        b.build_behavior_windows(req)
    assert caught.value.code == "BASELINE_SOURCE_LIMIT"


def test_unknown_direction_is_derived_and_evaluation_alias_is_explicit():
    req = request()
    req = replace(req, flows=tuple(replace(f, direction="UNKNOWN") for f in req.flows))
    built = b.build_behavior_windows(req)
    assert "DERIVED_FROM_CIDR" in built.limitations
    scope = replace(SCOPE, kind="EVALUATION", stored_sensor_id=None)
    aliased = replace(
        req,
        scope=scope,
        actual_sensor_id="pcap:sensor",
        sensor_alias_asserted=True,
        flows=tuple(replace(f, sensor_id="pcap:sensor") for f in req.flows),
    )
    assert b.build_behavior_windows(aliased).eligible_profile_count == 1
    with pytest.raises(b.BaselineInputError) as caught:
        b.build_behavior_windows(replace(aliased, sensor_alias_asserted=False))
    assert caught.value.code == "BASELINE_SCOPE_MISMATCH"


@pytest.mark.parametrize("case", ["flood", "mixed_ack", "payload", "retry"])
def test_suppression_preserves_noncontrol_rows_and_permutation(case):
    req = request()
    udp = tuple(replace(f, protocol="UDP") for f in req.flows)
    seed = replace(
        req.flows[0],
        destination_port=80,
        total_bytes=60000,
        packet_count=1000,
        duration_seconds=1,
        tcp_flags={"syn": 1000},
        tcp_flags_observed=True,
        tcp_syn_count=1000,
        tcp_syn_only_count=1000,
    )
    extra = (seed,)
    if case == "mixed_ack":
        extra += (
            replace(
                seed,
                destination_port=81,
                packet_count=100,
                tcp_flags={"syn": 90, "ack": 10},
                tcp_syn_count=90,
                tcp_syn_only_count=90,
                tcp_ack_count=10,
            ),
        )
    if case == "payload":
        extra += (
            replace(
                seed,
                destination_port=81,
                packet_count=100,
                tcp_flags={"syn": 100},
                tcp_syn_count=100,
                tcp_syn_only_count=100,
                payload_length=1,
            ),
        )
    if case == "retry":
        extra = tuple(
            replace(
                seed,
                timestamp=START + timedelta(seconds=t),
                duration_seconds=0,
                packet_count=1,
                total_bytes=60,
                tcp_flags={"syn": 1},
                tcp_syn_count=1,
                tcp_syn_only_count=1,
                tcp_syn_only_observations=((0, 12345),),
            )
            for t in (0, 2, 6, 12)
        )
    req = replace(req, flows=udp + extra)
    result = b.build_behavior_windows(req)
    assert "SUPPRESSED_CONTROL_OR_RETRY_ROWS" in result.limitations
    assert result == b.build_behavior_windows(replace(req, flows=tuple(reversed(req.flows))))
    udp_record = next(p for p in result.profiles if p.stream.protocol == "UDP")
    assert udp_record.window.outbound_record_count == 8
    assert udp_record.window.outbound_share == 0.5
    control = next(p for p in result.profiles if p.stream.service_port == 80)
    if case == "retry":
        assert control.window.outbound_record_count == 1
    else:
        assert control.window is None
    if case in {"mixed_ack", "payload"}:
        retained = next(p for p in result.profiles if p.stream.service_port == 81)
        assert retained.window.outbound_record_count == 1


@pytest.mark.parametrize(
    "case",
    [
        "null_receipt",
        "duplicate",
        "receipt_envelope",
        "receipt_observation",
        "nan",
        "bool_count",
        "seven",
        "empty_features",
        "wrong_scope",
        "wrong_epoch",
        "wrong_duration",
        "target_receipt",
        "target_counts",
        "target_envelope",
        "target_eligibility",
        "target_key",
        "target_veto",
        "bad_observation",
        "too_many_receipts",
        "too_many_windows",
    ],
)
def test_comparison_rejects_corrupt_dtos_not_missing_history(case):
    ref = history()
    req = request(START + timedelta(days=2))
    target = b.build_behavior_windows(req)
    kwargs = dict(
        target=target,
        reference=ref,
        scope=SCOPE,
        target_observation=TARGET_OBSERVATION,
        target_event_start=req.event_start,
        target_event_end=req.event_end,
        target_vetoes=(),
    )
    first = ref.windows[0]
    if case in {"null_receipt", "nan", "bool_count", "seven", "empty_features", "wrong_duration"}:
        changes = {
            "null_receipt": {"source_receipt_id": None},
            "nan": {"recurrence": float("nan")},
            "bool_count": {"outbound_record_count": True},
            "seven": {"outbound_record_count": 7},
            "empty_features": {"recurrence": None, "size_dispersion": None, "outbound_share": None},
            "wrong_duration": {"event_end": START + timedelta(seconds=61)},
        }[case]
        ref = replace(
            ref, windows=(replace(first, window=replace(first.window, **changes)), *ref.windows[1:])
        )
    if case == "duplicate":
        ref = replace(ref, windows=(*ref.windows, first))
    if case in {"receipt_envelope", "receipt_observation"}:
        changed = replace(
            first, window=replace(first.window, key=replace(first.window.key, service_port=8443))
        )
        if case == "receipt_envelope":
            changed = replace(
                changed,
                window=replace(
                    changed.window,
                    event_start=START + timedelta(seconds=1),
                    event_end=START + timedelta(seconds=61),
                ),
            )
        else:
            changed = replace(changed, observation=TARGET_OBSERVATION)
        ref = replace(ref, windows=(*ref.windows, changed))
    if case in {"wrong_scope", "wrong_epoch"}:
        change = (
            {"scope_config_sha256": "b" * 64} if case == "wrong_scope" else {"host_epoch": "other"}
        )
        ref = replace(
            ref,
            windows=(
                replace(
                    first, window=replace(first.window, key=replace(first.window.key, **change))
                ),
                *ref.windows[1:],
            ),
        )
    if case == "target_receipt":
        target = b.build_behavior_windows(replace(req, source_receipt_id=str(UUID(int=99))))
    if case == "target_counts":
        target = replace(target, raw_profile_count=2)
    if case == "target_eligibility":
        target = replace(
            target, profiles=(replace(target.profiles[0], eligible_for_reference=False),)
        )
    if case == "target_key":
        target = replace(target, profiles=(replace(target.profiles[0], key=None),))
    if case == "target_envelope":
        kwargs["target_event_start"] += timedelta(seconds=1)
        kwargs["target_event_end"] += timedelta(seconds=1)
    if case == "target_veto":
        kwargs["target_vetoes"] = ("NO_ACTIVE_REFERENCE",)
    if case == "bad_observation":
        kwargs["target_observation"] = replace(TARGET_OBSERVATION, feature_observation_sha256="bad")
    if case == "too_many_receipts":
        ref = replace(
            ref,
            windows=tuple(
                replace(first, window=replace(first.window, source_receipt_id=str(UUID(int=i + 1))))
                for i in range(17)
            ),
        )
    if case == "too_many_windows":
        ref = replace(ref, windows=(first,) * 2049)
    kwargs.update(target=target, reference=ref)
    with pytest.raises(b.BaselineInputError):
        b.compare_behavior_windows(**kwargs)


def test_all_streams_retained_but_only_highest_lexical_tie_per_peer_candidate():
    req = request(START + timedelta(days=2), varied=False, inbound=False)
    req = replace(
        req, flows=req.flows + tuple(replace(f, destination_port=8443) for f in req.flows)
    )
    ref = history()
    ref = replace(
        ref,
        windows=ref.windows
        + tuple(
            replace(r, window=replace(r.window, key=replace(r.window.key, service_port=8443)))
            for r in ref.windows
        ),
    )
    result = compare(req, ref)
    assert len(result.comparisons) == 2
    assert len(result.candidates) == 1
    assert result.candidates[0].comparison_key.service_port == 443
    assert result == compare(
        replace(req, flows=tuple(reversed(req.flows))),
        replace(ref, windows=tuple(reversed(ref.windows))),
    )


def test_nonfinite_robust_math_abstains_without_nonfinite_statistics():
    ref = history()
    ref = replace(
        ref,
        windows=tuple(
            replace(r, window=replace(r.window, recurrence=1e308, size_dispersion=1e308))
            for r in ref.windows
        ),
    )
    result = compare(request(START + timedelta(days=2), varied=False, inbound=False), ref)
    row = result.comparisons[0]
    assert row.status == "INSUFFICIENT"
    assert row.recurrence.status == row.size_dispersion.status == "INCOMPATIBLE"
    assert row.recurrence.robust_z is row.size_dispersion.robust_z is None
    assert "NONFINITE_FEATURE_UNAVAILABLE" in row.limitations
    assert not result.candidates


def canonical(mapping):
    return json.dumps(
        mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def test_canonical_closed_roundtrip_build_compare_and_source_publication():
    req = request(START + timedelta(days=2), varied=False, inbound=False, aggregate=True)
    built = b.build_behavior_windows(req)
    mapping = b.baseline_build_to_mapping(built)
    assert set(mapping) == {f.name for f in fields(b.BaselineBuildResult)}
    assert mapping["profiles"][0]["window"]["source_receipt_id"] is None
    assert mapping["profiles"][0]["window"]["event_start"] == "2026-01-03T00:00:00.000000Z"
    assert b.baseline_build_from_mapping(json.loads(canonical(mapping))) == built
    ref = history(aggregate=True)
    result = compare(req, ref)
    projected = b.baseline_comparison_to_mapping(result)
    assert set(projected["comparisons"][0]["features"]) == set(b.FEATURES)
    assert "recurrence" not in projected["comparisons"][0]
    assert projected["comparisons"][0]["features"]["recurrence"]["current"] is None
    assert b.baseline_comparison_from_mapping(json.loads(canonical(projected))) == result
    assert b.baseline_reference_from_mapping(b.baseline_reference_to_mapping(ref)) == ref
    for refwindow in ref.windows:
        assert (
            b.behavior_window_from_mapping(b.behavior_window_to_mapping(refwindow.window))
            == refwindow.window
        )
    with pytest.raises(b.BaselineInputError):
        b.behavior_window_to_mapping(built.profiles[0].window)
    assert canonical(projected) == canonical(
        b.baseline_comparison_to_mapping(
            compare(
                replace(req, flows=tuple(reversed(req.flows))),
                replace(ref, windows=tuple(reversed(ref.windows))),
            )
        )
    )


def dto_mapping(kind):
    if kind == "build":
        result = b.build_behavior_windows(request())
        return b.baseline_build_to_mapping(result), b.baseline_build_from_mapping
    if kind == "reference":
        return b.baseline_reference_to_mapping(history()), b.baseline_reference_from_mapping
    result = compare(request(START + timedelta(days=2), varied=False, inbound=False), history())
    return b.baseline_comparison_to_mapping(result), b.baseline_comparison_from_mapping


def nodes(value, path=()):
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from nodes(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from nodes(child, (*path, index))


def at(value, path):
    for step in path:
        value = value[step]
    return value


@pytest.mark.parametrize("kind", ["build", "comparison", "reference"])
@pytest.mark.parametrize("mutation", ["extra", "missing", "wrong_shape"])
def test_inverse_rejects_every_nested_object_shape(kind, mutation):
    mapping, decoder = dto_mapping(kind)
    for path, node in nodes(mapping):
        if path and path[-1] == "metrics":
            continue
        changed = json.loads(canonical(mapping))
        target = at(changed, path)
        if mutation == "extra":
            target["unexpected"] = None
        elif mutation == "missing":
            target.pop(next(iter(node)))
        elif path:
            parent = at(changed, path[:-1])
            parent[path[-1]] = []
        else:
            changed = []
        with pytest.raises(b.BaselineInputError):
            decoder(changed)


@pytest.mark.parametrize(
    "case",
    [
        "bool_count",
        "float_count",
        "null_count",
        "tuple_array",
        "naive_time",
        "offset_time",
        "short_time",
        "unknown_reason",
        "duplicate_reason",
        "unknown_status",
        "ready_null",
        "false_drift",
        "score",
        "candidate_ip",
        "source_ids",
        "metrics_nested",
        "metrics_bool",
        "factor_name",
        "unknown_kind",
        "oversized_array",
    ],
)
def test_inverse_rejects_malformed_scalars_and_cross_field_lies(case):
    mapping, decoder = dto_mapping(
        "comparison"
        if case
        in {
            "unknown_status",
            "ready_null",
            "false_drift",
            "score",
            "candidate_ip",
            "source_ids",
            "metrics_nested",
            "metrics_bool",
            "factor_name",
        }
        else "build"
    )
    if case in {"bool_count", "float_count", "null_count"}:
        mapping["raw_profile_count"] = {"bool_count": True, "float_count": 1.0, "null_count": None}[
            case
        ]
    elif case == "tuple_array":
        mapping["profiles"] = tuple(mapping["profiles"])
    elif case in {"naive_time", "offset_time", "short_time"}:
        mapping["profiles"][0]["window"]["event_start"] = {
            "naive_time": "2026-01-01T00:00:00.000000",
            "offset_time": "2026-01-01T09:00:00.000000+09:00",
            "short_time": "2026-01-01T00:00:00Z",
        }[case]
    elif case in {"unknown_reason", "duplicate_reason"}:
        mapping["limitations"] = ["bad"] if case == "unknown_reason" else ["DERIVED_FROM_CIDR"] * 2
    elif case == "unknown_kind":
        mapping["profiles"][0]["key"]["observation_kind"] = "OTHER"
    elif case == "oversized_array":
        mapping["profiles"] *= 129
    elif case == "unknown_status":
        mapping["comparisons"][0]["status"] = "NORMAL"
    elif case == "ready_null":
        mapping["comparisons"][0]["features"]["size_dispersion"]["reference_scale"] = None
    elif case == "false_drift":
        mapping["comparisons"][0]["features"]["size_dispersion"]["drifting"] = False
    elif case == "score":
        mapping["comparisons"][0]["historical_anomaly_score"] = float("nan")
    elif case == "candidate_ip":
        mapping["candidates"][0]["candidate"]["candidate_ip"] = "9.9.9.9"
    elif case == "source_ids":
        mapping["comparisons"][0]["source_window_ids"] = []
    elif case in {"metrics_nested", "metrics_bool"}:
        mapping["candidates"][0]["candidate"]["factors"][0]["metrics"]["robust_z"] = (
            {} if case == "metrics_nested" else True
        )
    elif case == "factor_name":
        mapping["candidates"][0]["candidate"]["factors"][0]["name"] = "RELATIVE_RECURRENCE"
    with pytest.raises(b.BaselineInputError):
        decoder(mapping)


def test_projection_ownership_and_immutable_candidate_metrics():
    req = request(START + timedelta(days=2), varied=False, inbound=False)
    result = compare(req, history())
    assert {"RETROSPECTIVE_NOT_AS_WAS", "HISTORY_MATCH_IS_NOT_BENIGN"} <= set(result.limitations)
    with pytest.raises(TypeError):
        result.candidates[0].candidate.factors[0].metrics["robust_z"] = 0
    encoded = b.baseline_comparison_to_mapping(result)
    decoded = b.baseline_comparison_from_mapping(encoded)
    encoded["candidates"][0]["candidate"]["factors"][0]["metrics"]["robust_z"] = 999
    assert decoded == result
    with pytest.raises(TypeError):
        decoded.candidates[0].candidate.factors[0].metrics["robust_z"] = 0
    reference = history()
    assert canonical(b.baseline_reference_to_mapping(reference)) == canonical(
        b.baseline_reference_to_mapping(
            replace(reference, windows=tuple(reversed(reference.windows)))
        )
    )


def test_boolean_port_cannot_alias_integer_key_in_direct_build_projection():
    req = request()
    req = replace(
        req,
        flows=tuple(
            replace(
                f,
                destination_port=1 if f.direction == "OUTBOUND" else f.destination_port,
                source_port=1 if f.direction == "INBOUND" else f.source_port,
            )
            for f in req.flows
        ),
    )
    built = b.build_behavior_windows(req)
    row = built.profiles[0]
    corrupt = replace(built, profiles=(replace(row, key=replace(row.key, service_port=True)),))
    with pytest.raises(b.BaselineInputError):
        b.baseline_build_to_mapping(corrupt)


@pytest.mark.parametrize("epoch", ["", None, "x" * 65, "bad\n"])
def test_missing_or_malformed_epoch_is_scope_mismatch(epoch):
    scope = replace(SCOPE, hosts=(b.HostEpoch("10.0.0.1", epoch),))
    with pytest.raises(b.BaselineInputError) as caught:
        b.build_behavior_windows(replace(request(), scope=scope))
    assert caught.value.code == "BASELINE_SCOPE_MISMATCH"


def test_syn_budget_precedes_any_ip_normalization(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("raw SYN budget must precede IP normalization")

    req = request()
    req = replace(req, flows=(replace(req.flows[0], tcp_syn_only_observations=((0, 1),) * 257),))
    monkeypatch.setattr(b, "ip_address", forbidden)
    monkeypatch.setattr(b, "ip_network", forbidden)
    with pytest.raises(b.BaselineInputError) as caught:
        b.build_behavior_windows(req)
    assert caught.value.code == "BASELINE_SOURCE_LIMIT"


def test_direct_projections_sort_canonical_keys_not_supplied_tuple_order():
    req = request()
    req = replace(
        req,
        flows=req.flows
        + tuple(replace(f, destination_port=8443) for f in req.flows if f.direction == "OUTBOUND"),
    )
    built = b.build_behavior_windows(req)
    assert canonical(b.baseline_build_to_mapping(built)) == canonical(
        b.baseline_build_to_mapping(replace(built, profiles=tuple(reversed(built.profiles))))
    )
    result = compare(req, None)
    assert canonical(b.baseline_comparison_to_mapping(result)) == canonical(
        b.baseline_comparison_to_mapping(
            replace(result, comparisons=tuple(reversed(result.comparisons)))
        )
    )


@pytest.mark.parametrize(
    "family,reason",
    [
        ("recurrence", "PACKET_TIMING_UNAVAILABLE"),
        ("outbound_share", "DIRECTION_BALANCE_UNAVAILABLE"),
    ],
)
def test_unobserved_feature_cannot_be_invented_by_deserializer(family, reason):
    req = request()
    req = replace(
        req, flows=tuple(replace(f, timestamp=START, bidirectional=True) for f in req.flows)
    )
    mapping = b.baseline_build_to_mapping(b.build_behavior_windows(req))
    assert reason in mapping["profiles"][0]["window"]["limitations"]
    mapping["profiles"][0]["window"][family] = 0.0
    with pytest.raises(b.BaselineInputError):
        b.baseline_build_from_mapping(mapping)


def test_huge_integer_feature_rejected_with_typed_safe_error():
    mapping, decoder = dto_mapping("comparison")
    mapping["comparisons"][0]["features"]["recurrence"]["current"] = 10**1000
    with pytest.raises(b.BaselineInputError):
        decoder(mapping)


def test_empty_host_assertions_are_scope_mismatch():
    with pytest.raises(b.BaselineInputError) as caught:
        b.build_behavior_windows(replace(request(), scope=replace(SCOPE, hosts=())))
    assert caught.value.code == "BASELINE_SCOPE_MISMATCH"


@pytest.mark.parametrize("boundary", ["flows", "syn", "context"])
def test_exact_input_limits_are_admitted(boundary):
    req = request()
    if boundary == "flows":
        req = replace(req, flows=req.flows[:8] * 1024)
    elif boundary == "syn":
        req = replace(
            req,
            flows=(
                replace(req.flows[0], tcp_syn_only_observations=((0, 1),) * 256),
                *req.flows[1:],
            ),
        )
    else:
        scope = replace(
            SCOPE,
            hosts=tuple(b.HostEpoch(f"10.0.0.{i}", f"epoch-{i}") for i in range(128)),
            internal_networks=tuple(f"10.{i}.0.0/16" for i in range(128)),
        )
        req = replace(req, scope=scope, trusted_peers=tuple(f"8.0.0.{i}" for i in range(128)))
    result = b.build_behavior_windows(req)
    assert result.eligible_profile_count == 1
    assert result.profiles[0].window.outbound_record_count == (8192 if boundary == "flows" else 8)


def test_reference_exact_16_receipts_128_profiles_2048_windows_and_profile_overflow():
    seed = history().windows[0]
    refs = []
    for port in range(1000, 1128):
        for i in range(16):
            start = START + timedelta(days=i)
            refs.append(
                replace(
                    seed,
                    window=replace(
                        seed.window,
                        key=replace(seed.window.key, service_port=port),
                        source_receipt_id=str(UUID(int=i + 1)),
                        event_start=start,
                        event_end=start + timedelta(seconds=60),
                    ),
                    observation=b.ObservationIdentity(f"root-{i}", f"data-{i}", f"{i:064x}"),
                )
            )
    reference = b.BaselineReference(tuple(refs))
    assert (
        b.baseline_reference_from_mapping(b.baseline_reference_to_mapping(reference)) == reference
    )
    empty = replace(request(START + timedelta(days=17)), flows=())
    assert compare(empty, reference).comparisons == ()
    extra = replace(
        seed, window=replace(seed.window, key=replace(seed.window.key, service_port=1128))
    )
    with pytest.raises(b.BaselineInputError) as caught:
        b.baseline_reference_to_mapping(b.BaselineReference(tuple(refs[::16]) + (extra,)))
    assert caught.value.code == "BASELINE_PROFILE_LIMIT"


def test_feature_math_bytes_scaling_and_offset_equivalence():
    from datetime import timezone

    req = request()
    times = (0, 1, 2, 4, 6, 9, 12, 16)
    req = replace(
        req,
        flows=tuple(
            replace(f, timestamp=START + timedelta(seconds=t))
            for f, t in zip(req.flows[:8], times, strict=True)
        )
        + req.flows[8:],
    )
    window = b.build_behavior_windows(req).profiles[0].window
    assert (window.recurrence, window.size_dispersion, window.outbound_share) == (0.5, 0.8, 0.5)
    scaled = replace(
        req, flows=tuple(replace(f, total_bytes=f.total_bytes * 13) for f in req.flows)
    )
    assert b.build_behavior_windows(scaled) == b.build_behavior_windows(req)
    zone = timezone(timedelta(hours=9))
    offset = replace(
        req,
        event_start=req.event_start.astimezone(zone),
        event_end=req.event_end.astimezone(zone),
        flows=tuple(replace(f, timestamp=f.timestamp.astimezone(zone)) for f in req.flows),
    )
    assert canonical(b.baseline_build_to_mapping(b.build_behavior_windows(offset))) == canonical(
        b.baseline_build_to_mapping(b.build_behavior_windows(req))
    )


def test_missing_feature_is_not_counted_as_future_support():
    ref = history()
    req = request(START + timedelta(days=2))
    future = replace(
        ref.windows[0],
        window=replace(
            ref.windows[0].window,
            source_receipt_id=str(UUID(int=99)),
            event_start=req.event_start,
            event_end=req.event_end,
            recurrence=None,
            limitations=("PACKET_TIMING_UNAVAILABLE",),
        ),
    )
    result = compare(req, replace(ref, windows=(*ref.windows, future)))
    row = result.comparisons[0]
    assert row.status == "READY"
    assert row.recurrence.excluded_future_count == 0
    assert (
        row.size_dispersion.excluded_future_count == row.outbound_share.excluded_future_count == 1
    )


@pytest.mark.parametrize(
    "remaining,status", [("size_dispersion", "INSUFFICIENT"), ("none", "INCOMPATIBLE")]
)
def test_feature_local_null_does_not_veto_available_family(remaining, status):
    req = request(START + timedelta(days=2), aggregate=True)
    req = replace(req, flows=tuple(replace(f, bidirectional=True) for f in req.flows))
    built = b.build_behavior_windows(req)
    if remaining == "none":
        row = built.profiles[0]
        reasons = tuple(sorted((*row.reasons, "NONFINITE_FEATURE_UNAVAILABLE")))
        w = replace(row.window, size_dispersion=None, limitations=reasons)
        built = replace(
            built,
            profiles=(replace(row, window=w, eligible_for_reference=False, reasons=reasons),),
            eligible_profile_count=0,
            excluded_profile_count=1,
            limitations=reasons,
        )
    result = b.compare_behavior_windows(
        target=built,
        reference=history(aggregate=True),
        scope=SCOPE,
        target_observation=TARGET_OBSERVATION,
        target_event_start=req.event_start,
        target_event_end=req.event_end,
        target_vetoes=(),
    )
    assert result.comparisons[0].status == status
    assert not result.candidates


def test_single_family_descriptive_drift_roundtrips_but_nonzero_score_is_rejected():
    result = compare(request(START + timedelta(days=2), varied=False), history())
    assert result.comparisons[0].size_dispersion.drifting
    assert result.comparisons[0].historical_anomaly_score == 0
    assert result.candidates == ()
    projected = b.baseline_comparison_to_mapping(result)
    assert b.baseline_comparison_from_mapping(projected) == result
    projected["comparisons"][0]["historical_anomaly_score"] = 1.0
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_from_mapping(projected)


def test_comparison_unobserved_direction_stays_null_on_roundtrip():
    req = request(START + timedelta(days=2))
    req = replace(req, flows=tuple(replace(f, bidirectional=True) for f in req.flows))
    mapping = b.baseline_comparison_to_mapping(compare(req, history()))
    mapping["comparisons"][0]["features"]["outbound_share"]["current"] = 0.0
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_from_mapping(mapping)


def test_null_build_window_requires_exclusion_reason():
    req = replace(request(), trusted_peers=("8.8.8.8",))
    mapping = b.baseline_build_to_mapping(b.build_behavior_windows(req))
    mapping["profiles"][0]["reasons"] = []
    with pytest.raises(b.BaselineInputError):
        b.baseline_build_from_mapping(mapping)


def test_tied_retry_rows_preserve_canonical_bytes_across_permutations():
    import random

    req = request()
    seed = replace(
        req.flows[0],
        destination_port=80,
        source_port=55000,
        total_bytes=60,
        tcp_flags={"syn": 1},
        tcp_flags_observed=True,
        tcp_syn_count=1,
        tcp_syn_only_count=1,
        tcp_syn_only_observations=((0, 77),),
    )
    retry = tuple(replace(seed, timestamp=START + timedelta(seconds=t)) for t in (0, 2, 6, 12))
    req = replace(req, flows=(*req.flows, *retry, replace(seed, total_bytes=70)))
    expected = canonical(b.baseline_build_to_mapping(b.build_behavior_windows(req)))
    for seed_value in range(10):
        rows = list(req.flows)
        random.Random(seed_value).shuffle(rows)
        observed = b.build_behavior_windows(replace(req, flows=tuple(rows)))
        assert "SUPPRESSED_CONTROL_OR_RETRY_ROWS" in observed.limitations
        assert canonical(b.baseline_build_to_mapping(observed)) == expected


def test_single_peer_own_three_approved_windows_yields_two_family_candidate():
    reference = history()
    target = request(START + timedelta(days=2), varied=False, inbound=False)
    built = b.build_behavior_windows(target)
    assert built.profiles[0].window.source_receipt_id is None
    assert all(w.window.source_receipt_id is not None for w in reference.windows)
    result = compare(target, reference)
    assert len(result.candidates) == 1
    comparison = result.comparisons[0]
    assert comparison.status == "READY"
    assert comparison.recurrence.drifting is False
    assert comparison.size_dispersion.drifting is True
    assert comparison.outbound_share.drifting is True
    assert len(comparison.source_window_ids) == 3
    assert result.candidates[0].comparison_key == comparison.key
    assert {factor.name for factor in result.candidates[0].candidate.factors} == {
        "HISTORICAL_RECORD_SIZE_DISPERSION_CHANGE",
        "HISTORICAL_DIRECTION_BALANCE_CHANGE",
    }
