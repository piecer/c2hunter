"""Additional finite provenance and isolation cases, independent of product fixtures."""

from dataclasses import replace
from datetime import timedelta, timezone
from uuid import UUID

import pytest
from test_baseline_adversarial import OBS, T0, canonical, compare, history, req

from c2hunter_analysis import behavior_baseline as b


@pytest.mark.parametrize(
    "reason", ["TARGET_REVIEW_REQUIRED", "TARGET_PARTIAL_CAPTURE", "SOURCE_CLOCK_UNCERTAIN"]
)
def test_run_wide_veto_in_summary_cannot_coexist_with_ready_row(reason):
    value = b.baseline_comparison_to_mapping(compare(reference=history()))
    value["limitations"] = sorted(set(value["limitations"]) | {reason})
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_from_mapping(value)


@pytest.mark.parametrize("port", [53, 123])
def test_reference_decoder_rejects_common_service_even_without_reason(port):
    value = b.baseline_reference_to_mapping(history())
    for item in value["windows"]:
        item["window"]["key"]["service_port"] = port
    with pytest.raises(b.BaselineInputError):
        b.baseline_reference_from_mapping(value)


def test_excluded_target_cannot_become_a_positive_through_build_decoder():
    request = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    value = b.baseline_build_to_mapping(b.build_behavior_windows(request))
    value["limitations"] = ["TRUSTED_PEERS_EXCLUDED"]
    row = value["profiles"][0]
    row["reasons"] = row["window"]["limitations"] = ["TRUSTED_PEERS_EXCLUDED"]
    with pytest.raises(b.BaselineInputError):
        target = b.baseline_build_from_mapping(value)
        result = compare(request, history(), target=target)
        print("EXCLUDED_TARGET_COMPARISON", b.baseline_comparison_to_mapping(result))


def test_reference_with_excluded_sources_cannot_supply_positive_support():
    value = b.baseline_reference_to_mapping(history())
    for item in value["windows"]:
        item["window"]["limitations"] = ["TRUSTED_PEERS_EXCLUDED"]
    with pytest.raises(b.BaselineInputError):
        reference = b.baseline_reference_from_mapping(value)
        result = compare(reference=reference)
        print("EXCLUDED_SOURCE_SCORE", result.comparisons[0].historical_anomaly_score)


@pytest.mark.parametrize(
    "key_field,new_value",
    [
        ("scope_config_sha256", "2" * 64),
        ("sensor_key", "other-sensor"),
        ("host_epoch", "other-epoch"),
    ],
)
def test_comparison_collection_cannot_mix_scope_identity(key_field, new_value):
    # Combine two well-shaped producer rows with distinct peers, then change one identity.
    r = compare(reference=history())
    value = b.baseline_comparison_to_mapping(r)
    import copy

    second = copy.deepcopy(value["comparisons"][0])
    cand = copy.deepcopy(value["candidates"][0])
    second["key"]["peer_ip"] = "203.0.113.10"
    cand["comparison_key"]["peer_ip"] = "203.0.113.10"
    cand["candidate"]["candidate_ip"] = "203.0.113.10"
    second["key"][key_field] = new_value
    cand["comparison_key"][key_field] = new_value
    value["comparisons"].append(second)
    value["candidates"].append(cand)
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_from_mapping(value)


def test_reference_global_receipt_bound_survives_comparison_projection():
    import copy

    value = b.baseline_comparison_to_mapping(compare(reference=history()))
    rows = []
    candidates = []
    for i in range(6):
        row = copy.deepcopy(value["comparisons"][0])
        cand = copy.deepcopy(value["candidates"][0])
        ip = f"203.0.113.{i + 1}"
        row["key"]["peer_ip"] = ip
        cand["comparison_key"]["peer_ip"] = ip
        cand["candidate"]["candidate_ip"] = ip
        ids = [str(UUID(int=i * 3 + j + 100)) for j in range(3)]
        row["source_window_ids"] = ids
        for feature in row["features"].values():
            feature["eligible_window_ids"] = ids.copy()
        rows.append(row)
        candidates.append(cand)
    value["comparisons"] = rows
    value["candidates"] = candidates
    with pytest.raises(b.BaselineInputError):
        b.baseline_comparison_from_mapping(value)


def test_peer_trust_is_local_not_global_and_receipts_do_not_bleed():
    r = req()
    extra = req(peer="203.0.113.10")
    r = replace(r, flows=(*r.flows, *extra.flows), trusted_peers=("203.0.113.9",))
    result = b.build_behavior_windows(r)
    assert (
        result.raw_profile_count == 2
        and result.excluded_profile_count == 1
        and result.eligible_profile_count == 1
    )
    assert next(x for x in result.profiles if x.stream.peer_ip == "203.0.113.9").window is None
    good = next(x for x in result.profiles if x.stream.peer_ip == "203.0.113.10")
    assert good.eligible_for_reference and "TRUSTED_PEERS_EXCLUDED" not in good.reasons
    comparison = compare(r, None, target=result)
    assert len(comparison.comparisons) == 1 and comparison.unprofiled_count == 1
    assert (
        b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(comparison))
        == comparison
    )


@pytest.mark.parametrize("kind", ["observation", "envelope"])
def test_single_receipt_must_bind_one_observation_and_envelope_across_peers(kind):
    h = history()
    first = h.windows[0]
    w = replace(first.window, key=replace(first.window.key, peer_ip="203.0.113.10"))
    more = replace(first, window=w)
    if kind == "observation":
        more = replace(more, observation=OBS)
    else:
        more = replace(
            more,
            window=replace(
                w,
                event_start=w.event_start + timedelta(microseconds=1),
                event_end=w.event_end + timedelta(microseconds=1),
            ),
        )
    with pytest.raises(b.BaselineInputError):
        compare(reference=replace(h, windows=(*h.windows, more)))


def test_offset_equivalent_dt_inputs_and_integer_durations_roundtrip():
    request = req(aggregate=True)
    zone = timezone(timedelta(hours=-5))
    shifted = replace(
        request,
        event_start=request.event_start.astimezone(zone),
        event_end=request.event_end.astimezone(zone),
        flows=tuple(replace(f, timestamp=f.timestamp.astimezone(zone)) for f in request.flows),
    )
    expected = b.baseline_build_to_mapping(b.build_behavior_windows(request))
    assert canonical(b.baseline_build_to_mapping(b.build_behavior_windows(shifted))) == canonical(
        expected
    )


@pytest.mark.parametrize("mutate", ["sensor", "host", "duration"])
def test_empty_or_unprofiled_target_still_has_scope_envelope_validation(mutate):
    request = replace(req(), flows=())
    if mutate == "duration":
        request = replace(request, event_end=request.event_end + timedelta(seconds=1))
    elif mutate == "sensor":
        request = replace(request, actual_sensor_id="other")
    else:
        request = replace(req(), flows=(replace(req().flows[-1], destination_ip="192.168.1.11"),))
    with pytest.raises(b.BaselineInputError) as e:
        b.build_behavior_windows(request)
    assert e.value.code == "BASELINE_SCOPE_MISMATCH"
