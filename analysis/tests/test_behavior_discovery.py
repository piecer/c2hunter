from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from itertools import accumulate
from pathlib import Path

import pytest

from c2hunter_analysis import domain
from c2hunter_analysis.detectors import (
    PeriodicBeaconDetector,
    SingleHostCompositeBeaconDetector,
    run_detectors,
)
from c2hunter_analysis.domain import AnalysisContext, Flow

START = datetime(2026, 8, 9, tzinfo=UTC)
OUTLIER = "203.0.113.250"


def context(flows: list[Flow], **kwargs: object) -> AnalysisContext:
    return AnalysisContext(
        dataset_id="job-local-discovery",
        start=START,
        end=START + timedelta(hours=3),
        flows=flows,
        **kwargs,
    )


def stream(peer: str, *, unusual: bool = False, port: int = 443) -> list[Flow]:
    intervals = [300, 900, 450, 1050, 600, 1200, 750] if unusual else [1, 2, 8, 32, 128, 512, 2048]
    sizes = [120, 121, 119, 120, 122, 119, 121, 120] if unusual else [64, 128, 256, 512] * 2
    return [
        Flow(
            sensor_id="s1",
            timestamp=START + timedelta(seconds=second),
            source_ip="10.0.0.1",
            destination_ip=peer,
            source_port=50000,
            destination_port=port,
            protocol="TCP",
            direction="OUTBOUND",
            total_bytes=size,
        )
        for second, size in zip(accumulate([0, *intervals]), sizes, strict=True)
    ]


def population() -> list[Flow]:
    return [row for index in range(1, 9) for row in stream(f"198.51.100.{index}")]


def rule_free_fixture() -> tuple[AnalysisContext, str]:
    """Reusable parent-service fixture: default rules emit no evidence.

    For JSON records use ``asdict(flow) | {"timestamp": flow.timestamp.isoformat()}``
    for each flow in the returned context. No rule scores or model outputs are mocked.
    """
    return context(population() + stream(OUTLIER, unusual=True)), OUTLIER


def discover(ctx: AnalysisContext, **kwargs: object):
    # Keep the first RED an assertion about the absent feature, not an import error.
    import importlib.util

    name = "c2hunter_analysis.behavior_discovery"
    assert importlib.util.find_spec(name) is not None, "job-local discovery module is missing"
    module = __import__(name, fromlist=["discover_behavior_candidates"])
    assert (
        Path(module.__file__).parent
        == Path(__file__).resolve().parents[1] / "src/c2hunter_analysis"
    )
    assert Path(domain.__file__).parent == Path(module.__file__).parent
    return module.discover_behavior_candidates(ctx, **kwargs)


def test_jittered_single_host_outlier_is_discovered_without_beacon_rule_evidence() -> None:
    ctx, target = rule_free_fixture()
    rows = ctx.flows
    assert target == OUTLIER
    assert run_detectors(ctx) == []
    assert OUTLIER not in {item.candidate_ip for item in PeriodicBeaconDetector().analyze(ctx)}
    assert OUTLIER not in {
        item.candidate_ip for item in SingleHostCompositeBeaconDetector().analyze(ctx)
    }
    before = tuple(rows)

    result = discover(ctx)

    assert [item.candidate_ip for item in result.candidates] == [OUTLIER]
    candidate = result.candidates[0]
    assert 0 < candidate.anomaly_score <= 100
    assert {factor.name for factor in candidate.factors} >= {
        "RELATIVE_RECURRENCE",
        "RELATIVE_RECORD_SIZE_STABILITY",
    }
    assert candidate.internal_hosts == ("10.0.0.1",)
    assert candidate.protocols == ("TCP",)
    assert candidate.ports == (443,)
    assert candidate.first_seen == START
    assert candidate.last_seen == rows[-1].timestamp
    assert result.examined_peer_count == 9
    assert result.excluded_peer_count == 0
    assert "JOB_LOCAL_NO_HISTORICAL_BASELINE" in candidate.limitations
    assert tuple(rows) == before
    with pytest.raises(FrozenInstanceError):
        candidate.anomaly_score = 100
    with pytest.raises(FrozenInstanceError):
        result.examined_peer_count = 0


def test_trusted_outlier_is_excluded_without_mutating_trust_or_context() -> None:
    ctx = context(population() + stream(OUTLIER, unusual=True))
    trusted = {OUTLIER}
    result = discover(ctx, trusted_peers=trusted)
    assert result.candidates == ()
    assert result.examined_peer_count == 8
    assert result.excluded_peer_count == 1
    assert "TRUSTED_PEERS_EXCLUDED" in result.warnings
    assert trusted == {OUTLIER}


@pytest.mark.parametrize("port", [53, 123])
def test_common_service_outlier_is_not_promoted(port: int) -> None:
    rows = [
        replace(row, destination_port=port, protocol="UDP")
        for row in population() + stream("8.8.8.8", unusual=True)
    ]
    result = discover(context(rows))
    assert result.candidates == ()
    assert "COMMON_SERVICES_EXCLUDED" in result.warnings


def test_common_heartbeat_population_and_volume_alone_are_not_candidates() -> None:
    rows = [row for index in range(1, 10) for row in stream(f"198.51.100.{index}", unusual=True)]
    assert discover(context(rows)).candidates == ()
    # Multiplying every packet size changes volume, not normalized size dispersion.
    rows = population() + [
        replace(row, total_bytes=row.total_bytes * 10000) for row in stream(OUTLIER)
    ]
    assert discover(context(rows)).candidates == ()


def test_sparse_service_cohort_reports_insufficient_population() -> None:
    rows = population() + stream(OUTLIER, unusual=True, port=8443)
    result = discover(context(rows))
    assert result.candidates == ()
    assert "INSUFFICIENT_SERVICE_COHORT" in result.warnings
    assert discover(context(stream(OUTLIER, unusual=True)[:4])).excluded_peer_count == 1


def inbound(row: Flow, total_bytes: int) -> Flow:
    return replace(
        row,
        source_ip=row.destination_ip,
        destination_ip=row.source_ip,
        source_port=row.destination_port,
        destination_port=row.source_port,
        direction="INBOUND",
        total_bytes=total_bytes,
    )


def test_aggregate_min_max_and_flush_cadence_never_supply_packet_timing() -> None:
    rows = [
        replace(
            row,
            packet_count=20,
            duration_seconds=10,
            packet_sizes=(60, 1500),
            average_packet_size=300,
        )
        for row in population() + stream(OUTLIER, unusual=True)
    ]
    result = discover(context(rows))
    assert result.candidates == ()  # Size alone is not two independent families.
    assert "AGGREGATED_FLOW_TIMING_UNAVAILABLE" in result.warnings
    assert result.examined_peer_count == 9


def test_aggregate_record_size_and_direction_can_support_relative_candidate() -> None:
    outbound = [
        replace(row, packet_count=20, duration_seconds=10, packet_sizes=(60, 1500))
        for row in population() + stream(OUTLIER, unusual=True)
    ]
    rows = outbound + [
        inbound(row, row.total_bytes if row.destination_ip != OUTLIER else 1) for row in outbound
    ]
    result = discover(context(rows))
    assert [item.candidate_ip for item in result.candidates] == [OUTLIER]
    candidate = result.candidates[0]
    names = {factor.name for factor in candidate.factors}
    assert "RELATIVE_RECURRENCE" not in names
    assert {"RELATIVE_RECORD_SIZE_STABILITY", "RELATIVE_DIRECTION_BALANCE"} <= names
    assert "RECORD_MEANS_NOT_PACKET_SIZE_DISTRIBUTION" in candidate.limitations
    assert "AGGREGATED_FLOW_TIMING_UNAVAILABLE" in candidate.limitations
    assert candidate.last_seen == outbound[-1].timestamp + timedelta(seconds=10)
    # The producer's min/max tuple is deliberately not interpreted as sampled packets.
    altered = [replace(row, packet_sizes=(1, 999999), average_packet_size=999999) for row in rows]
    assert discover(context(altered)) == result


@pytest.mark.parametrize("retained_kind", ["UDP", "payload", "ACK", "inbound"])
def test_control_flood_rows_are_removed_but_same_peer_evidence_survives(retained_kind: str) -> None:
    rows = population() + stream(OUTLIER, unusual=True)
    if retained_kind == "UDP":
        rows = [replace(row, protocol="UDP") for row in rows]
    elif retained_kind == "payload":
        rows = [replace(row, payload_length=1, tcp_flags={"syn": 1}) for row in rows]
    elif retained_kind == "ACK":
        rows = [replace(row, tcp_flags={"ack": 1}) for row in rows]
    else:
        rows += [inbound(row, row.total_bytes) for row in list(rows)]
    clean = discover(context(rows))
    assert [item.candidate_ip for item in clean.candidates] == [OUTLIER]
    flood = replace(
        stream(OUTLIER)[0],
        packet_count=100000,
        total_bytes=6000000,
        duration_seconds=1,
        tcp_flags={"syn": 100000},
    )
    result = discover(context(rows + [flood]))
    assert result.candidates == clean.candidates
    assert "SUPPRESSED_CONTROL_OR_RETRY_ROWS" in result.warnings
    flood_only = discover(context(population() + [flood]))
    assert flood_only.candidates == ()
    assert flood_only.excluded_peer_count == 1


def test_syn_retry_duplicates_do_not_distort_retained_peer_profile() -> None:
    from c2hunter_analysis.tcp_sessions import syn_retry_duplicate_flow_ids

    rows = population() + stream(OUTLIER, unusual=True)
    retry = [
        replace(
            stream(OUTLIER)[0],
            timestamp=START + timedelta(seconds=second),
            source_port=55000,
            total_bytes=60,
            tcp_flags={"syn": 1},
            tcp_flags_observed=True,
            tcp_syn_count=1,
            tcp_syn_only_count=1,
            tcp_syn_only_observations=((0, 12345),),
        )
        for second in (0, 2, 6, 12)
    ]
    assert syn_retry_duplicate_flow_ids(context(rows + retry)) == {id(row) for row in retry[1:]}
    clean = discover(context(rows + retry[:1]))
    assert clean.candidates
    result = discover(context(rows + retry))
    assert result.candidates == clean.candidates
    assert "SUPPRESSED_CONTROL_OR_RETRY_ROWS" in result.warnings


def test_mixed_ack_aggregate_discovery_survives_same_peer_pure_syn_flood() -> None:
    outbound = [
        replace(row, packet_count=20, duration_seconds=10, tcp_flags={"syn": 19, "ack": 1})
        for row in population() + stream(OUTLIER, unusual=True)
    ]
    rows = outbound + [
        inbound(row, row.total_bytes if row.destination_ip != OUTLIER else 1) for row in outbound
    ]
    clean = discover(context(rows))
    assert [candidate.candidate_ip for candidate in clean.candidates] == [OUTLIER]
    flood = replace(
        stream(OUTLIER)[0],
        packet_count=100000,
        total_bytes=6000000,
        duration_seconds=1,
        tcp_flags={"syn": 100000},
    )
    result = discover(context(rows + [flood]))
    assert result.candidates == clean.candidates
    assert result.examined_peer_count == clean.examined_peer_count
    assert "SUPPRESSED_CONTROL_OR_RETRY_ROWS" in result.warnings


@pytest.mark.parametrize(
    "invalid",
    [
        {"total_bytes": float("nan")},
        {"total_bytes": float("inf")},
        {"packet_count": 0},
        {"packet_count": -1},
        {"packet_count": 10**400},
        {"duration_seconds": float("nan")},
        {"duration_seconds": -1},
        {"timestamp": START.replace(tzinfo=None)},
        {"destination_ip": "not-an-ip"},
        {"tcp_syn_count": float("inf")},
        {"tcp_flags": {"syn": float("nan")}},
    ],
)
def test_invalid_measurements_are_skipped_before_suppression(invalid: dict) -> None:
    rows = population() + stream(OUTLIER, unusual=True)
    clean = discover(context(rows))
    result = discover(context(rows + [replace(rows[-1], **invalid)]))
    assert result.candidates == clean.candidates
    assert "INVALID_FLOW_ROWS_SKIPPED" in result.warnings
    import json
    from dataclasses import asdict

    for candidate in result.candidates:
        for factor in candidate.factors:
            json.dumps(asdict(factor), allow_nan=False)


def test_capture_clock_uncertainty_is_a_negative_contribution_not_a_threat_fact() -> None:
    ctx = context(population() + stream(OUTLIER, unusual=True))
    clean = discover(ctx).candidates[0]
    result = discover(replace(ctx, clock_offsets_ms={"s1": 3000.0}))
    candidate = result.candidates[0]
    assert candidate.anomaly_score < clean.anomaly_score
    assert any(factor.points < 0 for factor in candidate.factors)
    assert candidate.anomaly_score == sum(factor.points for factor in candidate.factors)
    assert "CAPTURE_CLOCK_UNCERTAINTY" in candidate.limitations
    assert "CAPTURE_COMPLETENESS_UNVERIFIED" in candidate.limitations
    assert "CAPTURE_CLOCK_UNCERTAINTY" in result.warnings


def test_unknown_direction_is_resolved_without_combining_different_sensors() -> None:
    rows = population() + stream(OUTLIER, unusual=True)
    expected = discover(context(rows))
    assert discover(context([replace(row, direction="UNKNOWN") for row in rows])) == expected
    split = [
        replace(row, sensor_id=f"s{index % 2}")
        for index, row in enumerate(stream(OUTLIER, unusual=True))
    ]
    assert discover(context(population() + split)).candidates == ()


def test_input_budget_is_fail_closed_permutation_invariant_before_scoping() -> None:
    from c2hunter_analysis import behavior_discovery as module

    limit = getattr(module, "MAX_INPUT_FLOWS", 8192)
    rows = population() + stream(OUTLIER, unusual=True)
    filler = replace(rows[0], sensor_id="ignored")
    bounded = rows + [filler] * (limit - len(rows))
    expected = discover(context(rows, selected_sensors=("s1",)))
    assert discover(context(bounded, selected_sensors=("s1",))) == expected
    oversized = bounded + [filler]
    result = discover(context(oversized, selected_sensors=("s1",)))
    assert result.candidates == ()
    assert result.examined_peer_count == result.excluded_peer_count == 0
    assert f"INPUT_FLOW_BUDGET_EXCEEDED:{limit};PEER_COUNTS_NOT_ENUMERATED" in result.warnings
    assert discover(context(list(reversed(oversized)), selected_sensors=("s1",))) == result


def test_peer_cardinality_boundary_has_stable_complete_results_or_explicit_rejection() -> None:
    import random

    from c2hunter_analysis import behavior_discovery as module

    limit = getattr(module, "MAX_PEERS", 256)
    rows = [
        row for index in range(limit - 1) for row in stream(f"198.18.{index // 256}.{index % 256}")
    ]
    rows += stream(OUTLIER, unusual=True)
    expected = discover(context(rows))
    assert [item.candidate_ip for item in expected.candidates] == [OUTLIER]
    assert expected.examined_peer_count == limit
    for seed in range(3):
        shuffled = list(rows)
        random.Random(seed).shuffle(shuffled)
        assert discover(context(shuffled)) == expected
    oversized = rows + stream("203.0.113.251")
    result = discover(context(oversized))
    assert result.candidates == ()
    assert result.examined_peer_count == 0
    assert result.excluded_peer_count == limit + 1
    assert f"PEER_BUDGET_EXCEEDED:{limit}" in result.warnings
    assert discover(context(list(reversed(oversized)))) == result


def test_nested_syn_observation_work_is_bounded_before_suppression() -> None:
    from c2hunter_analysis import behavior_discovery as module

    limit = getattr(module, "MAX_SYN_OBSERVATIONS", 256)
    rows = population() + stream(OUTLIER, unusual=True)
    huge = replace(rows[-1], tcp_syn_only_observations=((0, 1234),) * (limit + 1))
    result = discover(context(rows + [huge]))
    assert result.candidates == ()
    assert f"SYN_OBSERVATION_BUDGET_EXCEEDED:{limit};PEER_COUNTS_NOT_ENUMERATED" in result.warnings


def test_context_cardinality_is_bounded_before_internal_address_work() -> None:
    from c2hunter_analysis import behavior_discovery as module

    limit = getattr(module, "MAX_CONTEXT_ITEMS", 128)
    ctx = context(
        population() + stream(OUTLIER, unusual=True), internal_cidrs=("10.0.0.0/8",) * (limit + 1)
    )
    result = discover(ctx)
    assert result.candidates == ()
    assert f"CONTEXT_BUDGET_EXCEEDED:{limit};PEER_COUNTS_NOT_ENUMERATED" in result.warnings


@pytest.mark.parametrize(
    "invalid",
    [
        {"tcp_syn_only_observations": ((10**100, 1),), "tcp_syn_only_count": 1},
        {"tcp_syn_only_observations": ((0, -1),), "tcp_syn_only_count": 1},
        {"destination_port": float("nan")},
        {"source_port": -1},
        {"protocol": "x" * 257},
        {"sensor_id": "s" * 257},
        {"tcp_flags": {str(index): 1 for index in range(17)}},
    ],
)
def test_invalid_nested_flow_metadata_is_rejected_before_shared_helpers(invalid: dict) -> None:
    rows = population() + stream(OUTLIER, unusual=True)
    clean = discover(context(rows))
    result = discover(context(rows + [replace(rows[-1], **invalid)]))
    assert result.candidates == clean.candidates
    assert "INVALID_FLOW_ROWS_SKIPPED" in result.warnings


def test_invalid_context_time_and_suppression_parameters_fail_closed() -> None:
    rows = population() + stream(OUTLIER, unusual=True)
    ctx = context(rows)
    result = discover(
        replace(ctx, start=ctx.start.replace(tzinfo=None), end=ctx.end.replace(tzinfo=None))
    )
    assert result.candidates == ()
    assert "INVALID_ANALYSIS_WINDOW" in result.warnings
    retry = replace(
        rows[-1],
        tcp_syn_only_count=4,
        tcp_syn_count=4,
        tcp_flags_observed=True,
        packet_count=4,
        tcp_syn_only_observations=((0, 1), (2000000, 1), (6000000, 1), (12000000, 1)),
    )
    result = discover(
        context(rows + [retry], parameters={"tcp_syn_retry_min_intervals": float("inf")})
    )
    assert result.candidates == ()
    assert "SUPPRESSION_UNAVAILABLE" in result.warnings


def test_primary_stream_evidence_is_explicit_and_peer_metadata_covers_retained_rows() -> None:
    rows = population() + stream(OUTLIER, unusual=True)
    secondary = replace(
        rows[-1],
        source_ip="10.0.0.2",
        protocol="UDP",
        destination_port=8443,
        timestamp=START + timedelta(hours=2),
    )
    candidate = discover(context(rows + [secondary])).candidates[0]
    assert candidate.internal_hosts == ("10.0.0.1", "10.0.0.2")
    assert candidate.protocols == ("TCP", "UDP")
    assert candidate.ports == (443, 8443)
    assert candidate.last_seen == secondary.timestamp
    assert "PRIMARY_STREAM_ONLY" in candidate.limitations
    for factor in candidate.factors:
        assert factor.metrics["host"] == "10.0.0.1"
        assert factor.metrics["sensor"] == "s1"
        assert factor.metrics["protocol"] == "TCP"
        assert factor.metrics["service_port"] == 443


def test_retry_timestamp_ties_are_deterministic_under_permutation() -> None:
    rows = population() + stream(OUTLIER, unusual=True)
    retry = [
        replace(
            rows[-1],
            timestamp=START + timedelta(seconds=second),
            source_port=55000,
            total_bytes=size,
            tcp_flags={"syn": 1},
            tcp_flags_observed=True,
            tcp_syn_count=1,
            tcp_syn_only_count=1,
            tcp_syn_only_observations=((0, 12345),),
        )
        for second, size in ((0, 60), (0, 64), (2, 60), (6, 60), (12, 60))
    ]
    result = discover(context(rows + retry))
    assert result == discover(context(list(reversed(rows + retry))))


def test_sparse_stream_and_invalid_context_are_explicit() -> None:
    result = discover(context(stream(OUTLIER, unusual=True)[:4]))
    assert "INSUFFICIENT_STREAM_SAMPLES" in result.warnings
    result = discover(context(population(), internal_cidrs=("invalid",)))
    assert result.candidates == ()
    assert "INVALID_INTERNAL_CIDRS" in result.warnings


def test_bidirectional_aggregates_do_not_fabricate_directional_byte_share() -> None:
    outbound = [
        replace(row, packet_count=20, duration_seconds=10, bidirectional=True)
        for row in population() + stream(OUTLIER, unusual=True)
    ]
    rows = outbound + [
        inbound(row, row.total_bytes if row.destination_ip != OUTLIER else 1) for row in outbound
    ]
    assert discover(context(rows)).candidates == ()


def test_parent_fixture_records_are_json_serializable_with_explicit_timestamp_conversion() -> None:
    import json
    from dataclasses import asdict

    ctx, target = rule_free_fixture()
    records = [asdict(flow) | {"timestamp": flow.timestamp.isoformat()} for flow in ctx.flows]
    assert json.loads(json.dumps(records, allow_nan=False))[-1]["destination_ip"] == target
    assert discover(ctx).candidates[0].candidate_ip == target


def test_factor_population_counts_only_peers_with_that_observation() -> None:
    rows = population() + stream(OUTLIER, unusual=True)
    rows = [
        replace(row, timestamp=START) if row.destination_ip == "198.51.100.1" else row
        for row in rows
    ]
    candidate = discover(context(rows)).candidates[0]
    factors = {factor.name: factor for factor in candidate.factors}
    assert factors["RELATIVE_RECURRENCE"].metrics["cohort_peers"] == 8
    assert factors["RELATIVE_RECORD_SIZE_STABILITY"].metrics["cohort_peers"] == 9


def test_overlong_flag_name_is_not_admitted_to_shared_suppression() -> None:
    ctx, _ = rule_free_fixture()
    malformed = replace(ctx.flows[-1], tcp_flags={"x" * 257: 1})
    result = discover(replace(ctx, flows=[*ctx.flows, malformed]))
    assert result.candidates == discover(ctx).candidates
    assert "INVALID_FLOW_ROWS_SKIPPED" in result.warnings


def test_tied_different_syn_sequences_do_not_make_suppression_input_order_dependent() -> None:
    ctx, _ = rule_free_fixture()
    retry = [
        replace(
            ctx.flows[-1],
            timestamp=START + timedelta(seconds=second),
            source_port=55000,
            total_bytes=60,
            tcp_flags={"syn": 1},
            tcp_flags_observed=True,
            tcp_syn_count=1,
            tcp_syn_only_count=1,
            tcp_syn_only_observations=((0, seq),),
        )
        for second, seq in ((0, 1), (0, 2), (2, 1), (6, 1), (12, 1))
    ]
    rows = [*ctx.flows, *retry]
    assert discover(context(rows)) == discover(context(list(reversed(rows))))
