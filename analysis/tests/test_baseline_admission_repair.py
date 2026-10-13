"""Direct DTO/publication siblings of the retained F1–F4 reviewer regressions."""

from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest
from test_baseline_adversarial import T0, compare, history, req

from c2hunter_analysis import behavior_baseline as b

EXCLUSIONS = (
    "TRUSTED_PEERS_EXCLUDED",
    "COMMON_SERVICES_EXCLUDED",
    "SERVICE_PORT_UNAVAILABLE",
)


@pytest.mark.parametrize("fault", (*EXCLUSIONS, 53, 123))
@pytest.mark.parametrize("boundary", ("build", "target", "window", "reference", "support"))
def test_f1_direct_window_admission(fault, boundary):
    request = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    target = b.build_behavior_windows(request)
    ref = history()
    w = target.profiles[0].window if boundary in ("build", "target") else ref.windows[0].window
    if isinstance(fault, str):
        w = replace(w, limitations=(fault,))
    else:
        w = replace(w, key=replace(w.key, service_port=fault))
    if boundary in ("build", "target"):
        record = replace(
            target.profiles[0],
            stream=replace(target.profiles[0].stream, service_port=w.key.service_port),
            key=w.key,
            window=w,
            reasons=w.limitations,
        )
        target = replace(target, profiles=(record,), limitations=w.limitations)
    else:
        ref = replace(ref, windows=(replace(ref.windows[0], window=w), *ref.windows[1:]))
    with pytest.raises(b.BaselineInputError):
        if boundary == "build":
            b.baseline_build_to_mapping(target)
        elif boundary == "target":
            compare(request, history(), target=target)
        elif boundary == "window":
            b.behavior_window_to_mapping(w)
        elif boundary == "reference":
            b.baseline_reference_to_mapping(ref)
        else:
            compare(request, ref)


@pytest.mark.parametrize("fault", (*EXCLUSIONS, 53, 123))
def test_f1_comparison_publication_cannot_restore_excluded_profile(fault):
    result = compare(reference=history())
    row = result.comparisons[0]
    item = result.candidates[0]
    if isinstance(fault, str):
        reasons = tuple(sorted((*row.limitations, fault)))
        row = replace(row, limitations=reasons)
        item = replace(item, candidate=replace(item.candidate, limitations=reasons))
    else:
        row = replace(row, key=replace(row.key, service_port=fault))
        item = replace(
            item, comparison_key=row.key, candidate=replace(item.candidate, ports=(fault,))
        )
    result = replace(result, comparisons=(row,), candidates=(item,), limitations=row.limitations)
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_to_mapping(result)


@pytest.mark.parametrize("excluded", ("trusted", 53, 123, None))
def test_f1_other_peer_exclusion_does_not_veto_positive(excluded):
    request = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    other = req(
        request.event_start, peer="203.0.113.10", port=443 if excluded == "trusted" else excluded
    )
    request = replace(
        request,
        flows=(*request.flows, *other.flows),
        trusted_peers=("203.0.113.10",) if excluded == "trusted" else (),
    )
    target = b.build_behavior_windows(request)
    assert target.eligible_profile_count == 1
    assert b.baseline_build_from_mapping(b.baseline_build_to_mapping(target)) == target
    result = compare(request, history(), target=target)
    assert result.comparisons[0].status == "READY"
    assert result.comparisons[0].historical_anomaly_score == 46
    assert len(result.candidates) == 1 and result.unprofiled_count == 1
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result


@pytest.mark.parametrize("boundary", ("build", "target", "window", "reference"))
def test_f2_sample_reason_cannot_claim_sufficient_window(boundary):
    request = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    target = b.build_behavior_windows(request)
    ref = history()
    reasons = ("INSUFFICIENT_STREAM_SAMPLES",)
    if boundary in ("build", "target"):
        record = target.profiles[0]
        record = replace(
            record, window=replace(record.window, limitations=reasons), reasons=reasons
        )
        target = replace(target, profiles=(record,), limitations=reasons)
    else:
        window = replace(ref.windows[0].window, limitations=reasons)
        ref = replace(ref, windows=(replace(ref.windows[0], window=window), *ref.windows[1:]))
    with pytest.raises(b.BaselineInputError):
        if boundary == "build":
            b.baseline_build_to_mapping(target)
        elif boundary == "target":
            compare(request, ref, target=target)
        elif boundary == "window":
            b.behavior_window_to_mapping(window)
        else:
            b.baseline_reference_to_mapping(ref)


VETOES = ("TARGET_REVIEW_REQUIRED", "TARGET_PARTIAL_CAPTURE", "SOURCE_CLOCK_UNCERTAIN")


@pytest.mark.parametrize("reason", (*VETOES, "INSUFFICIENT_STREAM_SAMPLES"))
@pytest.mark.parametrize("placement", ("summary", "profile"))
def test_f2_direct_comparison_rejects_positive_veto(reason, placement):
    result = compare(reference=history())
    reasons = tuple(sorted((*result.limitations, reason)))
    result = replace(result, limitations=reasons)
    if placement == "profile":
        row = replace(result.comparisons[0], limitations=reasons)
        item = result.candidates[0]
        item = replace(item, candidate=replace(item.candidate, limitations=reasons))
        result = replace(result, comparisons=(row,), candidates=(item,))
    if placement == "summary" and reason == "INSUFFICIENT_STREAM_SAMPLES":
        # Aggregate sample warnings can describe an unprofiled/other stream.
        assert (
            b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result
        )
    else:
        with pytest.raises(b.BaselineInputError):
            b.baseline_comparison_to_mapping(result)


@pytest.mark.parametrize("reason", VETOES)
def test_f2_target_summary_veto_applies_to_all_direct_comparisons(reason):
    request = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    extra = req(request.event_start, peer="203.0.113.10")
    request = replace(request, flows=(*request.flows, *extra.flows))
    target = b.build_behavior_windows(request)
    target = replace(target, limitations=tuple(sorted((*target.limitations, reason))))
    result = compare(request, history(), target=target)
    assert not result.candidates
    for row in result.comparisons:
        source = next(p.window for p in target.profiles if p.key == row.key)
        assert row.status == "INCOMPATIBLE" and row.historical_anomaly_score == 0
        assert not row.source_window_ids
        for name in b.FEATURES:
            feature = getattr(row, name)
            assert feature.current == getattr(source, name)
            assert feature.status == "INCOMPATIBLE"
            assert (feature.reference_median, feature.reference_scale, feature.robust_z) == (
                None,
                None,
                None,
            )
            assert not feature.eligible_window_ids and not feature.drifting
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result


def test_f2_sparse_peer_does_not_veto_positive_peer():
    request = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    extra = req(request.event_start, peer="203.0.113.10")
    request = replace(request, flows=(*request.flows, *extra.flows[:7]))
    result = compare(request, history())
    assert "INSUFFICIENT_STREAM_SAMPLES" in result.limitations
    assert {r.key.peer_ip: r.status for r in result.comparisons} == {
        "203.0.113.9": "READY",
        "203.0.113.10": "INCOMPATIBLE",
    }
    assert len(result.candidates) == 1
    assert result.candidates[0].candidate.anomaly_score == 46
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result


@pytest.mark.parametrize(
    "field,value",
    (
        ("scope_config_sha256", "2" * 64),
        ("sensor_key", "other"),
        ("feature_version", "other-version"),
        ("host_epoch", "other-epoch"),
    ),
)
def test_f3_direct_comparison_collection_identity(field, value):
    result = compare(req(T0 + timedelta(days=2)), history())
    first = result.comparisons[0]
    key = replace(first.key, peer_ip="203.0.113.10", **{field: value})
    result = replace(result, comparisons=(first, replace(first, key=key)))
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_to_mapping(result)


@pytest.mark.parametrize("count", (16, 17, 18))
def test_f3_receipt_union_across_rows_and_feature_local_support(count):
    result = compare(req(T0 + timedelta(days=2)), history())
    first = result.comparisons[0]
    rows = []
    for index in range(2):
        ids = [str(UUID(int=(index * 9 + j) % count + 100)) for j in range(9)]
        features = {
            name: replace(
                getattr(first, name), eligible_window_ids=tuple(sorted(ids[n * 3 : n * 3 + 3]))
            )
            for n, name in enumerate(b.FEATURES)
        }
        rows.append(
            replace(
                first,
                key=replace(first.key, peer_ip=f"203.0.113.{index + 1}"),
                source_window_ids=tuple(sorted(set(ids))),
                **features,
            )
        )
    result = replace(result, comparisons=tuple(rows))
    if count > 16:
        with pytest.raises(b.BaselineInputError):
            b.baseline_comparison_to_mapping(result)
    else:
        assert (
            b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result
        )


def test_f3_reference_publication_cannot_mix_epochs_for_one_host():
    ref = history()
    first = ref.windows[0]
    other = replace(
        first,
        window=replace(
            first.window,
            key=replace(first.window.key, peer_ip="203.0.113.10", host_epoch="other-epoch"),
        ),
    )
    ref = replace(ref, windows=(*ref.windows, other))
    with pytest.raises(b.BaselineInputError):
        b.baseline_reference_to_mapping(ref)


def test_f3_build_publication_cannot_mix_epochs_for_one_host():
    target = b.build_behavior_windows(req())
    first = target.profiles[0]
    key = replace(first.key, peer_ip="203.0.113.10", host_epoch="other-epoch")
    other = replace(
        first,
        key=key,
        stream=replace(first.stream, peer_ip=key.peer_ip, host_epoch=key.host_epoch),
        window=replace(first.window, key=key),
    )
    target = replace(target, profiles=(first, other), raw_profile_count=2, eligible_profile_count=2)
    with pytest.raises(b.BaselineInputError):
        b.baseline_build_to_mapping(target)


def test_f3_real_multi_host_mixed_support_remains_admitted():
    request = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    scope = replace(
        request.scope, hosts=(*request.scope.hosts, b.HostEpoch("192.168.1.11", "lease-B"))
    )
    other = req(request.event_start, peer="203.0.113.10", size_change=True, direction_change=True)
    request = replace(
        request,
        scope=scope,
        flows=(*request.flows, *(replace(f, source_ip="192.168.1.11") for f in other.flows)),
    )
    ref = history()
    second = tuple(
        replace(
            r,
            window=replace(
                r.window,
                key=replace(
                    r.window.key,
                    internal_host_ip="192.168.1.11",
                    host_epoch="lease-B",
                    peer_ip="203.0.113.10",
                ),
            ),
        )
        for r in ref.windows
    )
    first = ref.windows[0]
    ref = replace(
        ref,
        windows=(
            replace(
                first,
                window=replace(
                    first.window, recurrence=None, limitations=("PACKET_TIMING_UNAVAILABLE",)
                ),
            ),
            *ref.windows[1:],
            *second,
        ),
    )
    ref = b.baseline_reference_from_mapping(b.baseline_reference_to_mapping(ref))
    target = b.build_behavior_windows(request)
    assert b.baseline_build_from_mapping(b.baseline_build_to_mapping(target)) == target
    result = compare(request, ref, target=target)
    assert len(result.candidates) == 2
    assert {r.key.host_epoch for r in result.comparisons} == {"lease-A", "lease-B"}
    assert {len(r.recurrence.eligible_window_ids) for r in result.comparisons} == {2, 3}
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result


@pytest.mark.parametrize("length", (129, 256))
def test_f4_normalized_protocol_overflow_rejected_at_builder(length):
    request = req()
    request = replace(
        request, flows=(*request.flows[:-1], replace(request.flows[-1], protocol="ß" * length))
    )
    with pytest.raises(b.BaselineInputError) as error:
        b.build_behavior_windows(request)
    assert error.value.code == "BASELINE_SOURCE_INVALID"
    assert str(error.value) == "Invalid baseline input."


@pytest.mark.parametrize("protocol", ("S" * 256, "ß" * 128, "é" * 256))
def test_f4_normalized_boundary_preserves_identity_and_publication(protocol):
    receipt = str(UUID(int=123))
    request = req(receipt=receipt)
    scope = replace(
        request.scope,
        sensor_key="logical-ß",
        stored_sensor_id="actual-ß",
        hosts=(b.HostEpoch("192.168.1.10", "epoch-ß"),),
    )
    request = replace(
        request,
        scope=scope,
        actual_sensor_id="actual-ß",
        flows=tuple(replace(f, protocol=protocol, sensor_id="actual-ß") for f in request.flows),
    )
    built = b.build_behavior_windows(request)
    assert b.baseline_build_from_mapping(b.baseline_build_to_mapping(built)) == built
    window = built.profiles[0].window
    assert window.key.protocol == protocol.upper()
    assert window.key.sensor_key == "logical-ß" and window.key.host_epoch == "epoch-ß"
    assert window.source_receipt_id == receipt
    assert request.actual_sensor_id == "actual-ß" and request.flows[0].protocol == protocol
    assert b.behavior_window_from_mapping(b.behavior_window_to_mapping(window)) == window
