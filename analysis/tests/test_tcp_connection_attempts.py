import struct
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from c2hunter_analysis.ai_candidates import PREFILTER_VERSION, generate_high_recall_candidates
from c2hunter_analysis.detectors import (
    PeriodicBeaconDetector,
    TCPCommunicationAttemptDetector,
    run_detectors,
)
from c2hunter_analysis.domain import AnalysisContext, Evidence, Flow, normalize_tcp_syn_observations
from c2hunter_analysis.pcap import parse_pcap
from c2hunter_analysis.scoring import score_candidates
from c2hunter_analysis.tcp_sessions import (
    MAX_SYN_RETRY_EPISODES_PER_CONNECTION,
    MAX_SYN_RETRY_OBSERVATIONS_PER_CONNECTION,
    MAX_SYN_RETRY_RESPONSE_ROWS,
    qualified_candidate_groups,
    syn_retry_duplicate_flow_ids,
)

START = datetime(2026, 9, 2, tzinfo=UTC)
TARGET = "203.0.113.40"
EXPECTED_RETRY_EVIDENCE_PER_CANDIDATE = 64
EXPECTED_RETRY_EVIDENCE_PER_ANALYSIS = 512


def context(flows: list[Flow], **parameters: object) -> AnalysisContext:
    return AnalysisContext(
        "dataset",
        START,
        START + timedelta(minutes=5),
        flows,
        internal_cidrs=("10.0.0.0/8",),
        parameters=parameters,
    )


def syn_observations(
    intervals_ms: tuple[int, ...], sequence: int = 12345
) -> tuple[tuple[int, int], ...]:
    offset_us = 0
    observations = [(0, sequence)]
    for interval in intervals_ms:
        offset_us += interval * 1000
        observations.append((offset_us, sequence))
    return tuple(observations)


def outbound_retry(
    host: str = "10.0.0.1",
    source_port: int = 50000,
    *,
    intervals: tuple[int, ...] = (2000, 4000, 6000),
    sequence: int = 12345,
) -> Flow:
    observations = syn_observations(intervals, sequence)
    return Flow(
        sensor_id="sensor-a",
        timestamp=START,
        source_ip=host,
        destination_ip=TARGET,
        source_port=source_port,
        destination_port=443,
        protocol="TCP",
        direction="OUTBOUND",
        packet_count=len(observations),
        total_bytes=60 * len(observations),
        duration_seconds=sum(intervals) / 1000,
        tcp_flags={"syn": len(observations)},
        tcp_flags_observed=True,
        tcp_syn_count=len(observations),
        tcp_syn_only_count=len(observations),
        tcp_syn_only_observations=observations,
    )


def inbound_response(*, syn_ack: int = 0, rst: int = 0) -> Flow:
    return Flow(
        sensor_id="sensor-a",
        timestamp=START + timedelta(seconds=12.1),
        source_ip=TARGET,
        destination_ip="10.0.0.1",
        source_port=443,
        destination_port=50000,
        protocol="TCP",
        direction="INBOUND",
        packet_count=max(1, syn_ack + rst),
        total_bytes=60,
        tcp_flags_observed=True,
        tcp_syn_count=syn_ack,
        tcp_ack_count=syn_ack,
        tcp_rst_count=rst,
        tcp_syn_ack_count=syn_ack,
        tcp_syn_only_observations=(),
    )


def outbound_ack() -> Flow:
    return Flow(
        sensor_id="sensor-a",
        timestamp=START + timedelta(seconds=12.2),
        source_ip="10.0.0.1",
        destination_ip=TARGET,
        source_port=50000,
        destination_port=443,
        protocol="TCP",
        direction="OUTBOUND",
        packet_count=1,
        total_bytes=60,
        tcp_flags_observed=True,
        tcp_ack_count=1,
        tcp_ack_only_count=1,
        tcp_syn_only_observations=(),
    )


def inbound_ack_payload() -> Flow:
    return Flow(
        sensor_id="sensor-a",
        timestamp=START + timedelta(seconds=12.1),
        source_ip=TARGET,
        destination_ip="10.0.0.1",
        source_port=443,
        destination_port=50000,
        protocol="TCP",
        direction="INBOUND",
        packet_count=1,
        total_bytes=72,
        payload_hash="payload",
        payload_length=12,
        tcp_flags_observed=True,
        tcp_ack_count=1,
        tcp_ack_only_count=1,
        tcp_syn_only_observations=(),
    )


def test_periodic_same_sequence_syns_create_neutral_attempt_pattern() -> None:
    evidence = TCPCommunicationAttemptDetector().analyze(context([outbound_retry()]))

    assert len(evidence) == 1
    assert evidence[0].type == "TCP_COMMUNICATION_ATTEMPT_PATTERN"
    assert evidence[0].contribution == 0
    assert evidence[0].metrics["outcome"] == "NO_COMPLETION_OBSERVED"
    assert evidence[0].metrics["retry_intervals_ms"] == [2000, 4000, 6000]
    assert evidence[0].metrics["retransmission_count"] == 3
    assert evidence[0].warnings == (
        "no_response_is_not_host_unavailable",
        "capture_loss_or_asymmetry_possible",
    )
    assert evidence[0].last_seen == START + timedelta(seconds=12)

    candidate = score_candidates(evidence)[0]
    assert candidate.score == 0
    assert candidate.candidate_kind == "COMMUNICATION_STATUS"
    assert candidate.adjustments == ()


def test_rst_is_a_refused_attempt_not_unreachable() -> None:
    evidence = TCPCommunicationAttemptDetector().analyze(
        context([outbound_retry(), inbound_response(rst=1)])
    )

    assert evidence[0].metrics["outcome"] == "REFUSED_OR_RESET_OBSERVED"
    assert evidence[0].warnings == ()


def test_response_and_completed_handshake_are_distinguished() -> None:
    detector = TCPCommunicationAttemptDetector()
    responded = detector.analyze(context([outbound_retry(), inbound_response(syn_ack=1)]))
    established = detector.analyze(
        context([outbound_retry(), inbound_response(syn_ack=1), outbound_ack()])
    )

    assert responded[0].metrics["outcome"] == "PEER_RESPONSE_OBSERVED"
    assert established[0].metrics["outcome"] == "ESTABLISHED_OBSERVED"


def test_outbound_ack_without_captured_reply_is_not_labeled_peer_response() -> None:
    evidence = TCPCommunicationAttemptDetector().analyze(
        context([outbound_retry(), outbound_ack()])
    )

    assert evidence[0].metrics["outcome"] == "LOCAL_ACK_OBSERVED"
    assert evidence[0].warnings == ("peer_response_not_observed",)


def test_inbound_ack_payload_is_peer_response_evidence() -> None:
    evidence = TCPCommunicationAttemptDetector().analyze(
        context([outbound_retry(), inbound_ack_payload()])
    )

    assert evidence[0].metrics["outcome"] == "PEER_RESPONSE_OBSERVED"
    assert evidence[0].warnings == ("handshake_completion_not_observed",)


def test_response_aggregate_overlapping_episode_is_correlated() -> None:
    response = replace(
        inbound_response(rst=1),
        timestamp=START - timedelta(seconds=1),
        duration_seconds=13.1,
    )

    analysis_context = replace(
        context([outbound_retry(), response]), start=START - timedelta(seconds=2)
    )

    evidence = TCPCommunicationAttemptDetector().analyze(analysis_context)[0]

    assert evidence.metrics["outcome"] == "REFUSED_OR_RESET_OBSERVED"
    assert evidence.metrics["response_timing_approximate"] is True
    assert "aggregate_response_timing_approximate" in evidence.warnings


def test_later_reused_tuple_session_does_not_change_retry_episode_outcome() -> None:
    later_syn_ack = replace(inbound_response(syn_ack=1), timestamp=START + timedelta(seconds=100))
    later_ack = replace(outbound_ack(), timestamp=START + timedelta(seconds=100.1))

    evidence = TCPCommunicationAttemptDetector().analyze(
        context([outbound_retry(), later_syn_ack, later_ack])
    )

    assert evidence[0].metrics["outcome"] == "NO_COMPLETION_OBSERVED"
    assert evidence[0].first_seen == START
    assert evidence[0].last_seen == START + timedelta(seconds=12)


def test_new_sequence_attempt_within_grace_does_not_complete_prior_episode() -> None:
    new_attempt = replace(packet_syn(13, sequence=222), sensor_id="sensor-a")
    response = replace(inbound_response(syn_ack=1), timestamp=START + timedelta(seconds=13.1))
    ack = replace(outbound_ack(), timestamp=START + timedelta(seconds=13.2))

    evidence = TCPCommunicationAttemptDetector().analyze(
        context([outbound_retry(), new_attempt, response, ack])
    )

    assert evidence[0].metrics["outcome"] == "NO_COMPLETION_OBSERVED"


def test_intervening_sequence_splits_same_sequence_retry_train() -> None:
    retry_rows = [packet_syn(offset, sequence=111) for offset in (0, 2, 6, 12)]
    new_attempt = packet_syn(10, sequence=222)
    response = replace(
        inbound_response(syn_ack=1),
        sensor_id="pcap",
        timestamp=START + timedelta(seconds=10.1),
    )
    ack = replace(
        outbound_ack(),
        sensor_id="pcap",
        timestamp=START + timedelta(seconds=10.2),
    )

    evidence = TCPCommunicationAttemptDetector().analyze(
        context([*retry_rows, new_attempt, response, ack])
    )

    assert evidence == []


def test_same_aggregate_later_sequence_ack_does_not_complete_prior_episode() -> None:
    flow = replace(
        outbound_retry(),
        packet_count=6,
        tcp_syn_count=5,
        tcp_syn_only_count=5,
        tcp_ack_count=1,
        tcp_ack_only_count=1,
        duration_seconds=13.2,
        tcp_syn_only_observations=(
            (0, 111),
            (2_000_000, 111),
            (6_000_000, 111),
            (12_000_000, 111),
            (13_000_000, 222),
        ),
    )

    evidence = TCPCommunicationAttemptDetector().analyze(context([flow]))[0]

    assert evidence.metrics["outcome"] == "NO_COMPLETION_OBSERVED"
    assert evidence.metrics["response_timing_approximate"] is True
    assert "aggregate_response_timing_approximate" in evidence.warnings


def test_same_aggregate_late_ack_does_not_cross_response_deadline() -> None:
    flow = replace(
        outbound_retry(),
        packet_count=5,
        tcp_ack_count=1,
        tcp_ack_only_count=1,
        duration_seconds=100,
    )

    evidence = TCPCommunicationAttemptDetector().analyze(context([flow]))[0]

    assert evidence.metrics["outcome"] == "NO_COMPLETION_OBSERVED"
    assert evidence.metrics["response_timing_approximate"] is True
    assert "aggregate_response_timing_approximate" in evidence.warnings


def test_different_sequence_at_episode_end_cuts_response_correlation() -> None:
    retry_rows = [packet_syn(offset, sequence=1) for offset in (0, 2, 4, 6)]
    simultaneous_attempt = packet_syn(6, sequence=2)
    response = replace(
        inbound_response(syn_ack=1),
        sensor_id="pcap",
        timestamp=START + timedelta(seconds=6.1),
    )

    evidence = TCPCommunicationAttemptDetector().analyze(
        context([*retry_rows, simultaneous_attempt, response])
    )[0]

    assert evidence.metrics["outcome"] == "NO_COMPLETION_OBSERVED"


def test_constant_linear_and_jittered_retry_templates_are_recognized() -> None:
    detector = TCPCommunicationAttemptDetector()

    constant = detector.analyze(context([outbound_retry(intervals=(2000, 2000, 2000))]))
    linear = detector.analyze(context([outbound_retry(intervals=(2000, 4000, 6000))]))
    jittered = detector.analyze(context([outbound_retry(intervals=(1900, 4100, 5900))]))

    assert constant and linear and jittered


def test_retry_interval_bounds_are_inclusive_and_fail_closed_outside() -> None:
    detector = TCPCommunicationAttemptDetector()

    def long_window(flow: Flow) -> AnalysisContext:
        return AnalysisContext(
            "dataset",
            START,
            START + timedelta(minutes=10),
            [flow],
            internal_cidrs=("10.0.0.0/8",),
        )

    assert detector.analyze(context([outbound_retry(intervals=(500, 500, 500))]))
    assert detector.analyze(long_window(outbound_retry(intervals=(120_000,) * 3)))
    assert detector.analyze(context([outbound_retry(intervals=(499, 499, 499))])) == []
    assert detector.analyze(long_window(outbound_retry(intervals=(120_001,) * 3))) == []


def test_submillisecond_rounding_cannot_cross_retry_interval_bounds() -> None:
    too_short = replace(
        outbound_retry(),
        duration_seconds=1.4988,
        tcp_syn_only_observations=(
            (0, 12345),
            (499_600, 12345),
            (999_200, 12345),
            (1_498_800, 12345),
        ),
    )
    too_long = replace(
        outbound_retry(),
        duration_seconds=360.0012,
        tcp_syn_only_observations=(
            (0, 12345),
            (120_000_400, 12345),
            (240_000_800, 12345),
            (360_001_200, 12345),
        ),
    )
    analysis_context = replace(context([too_long]), end=START + timedelta(minutes=10))

    detector = TCPCommunicationAttemptDetector()

    assert detector.analyze(context([too_short])) == []
    assert detector.analyze(analysis_context) == []


def test_valid_same_sequence_retry_prefix_survives_later_cadence_reset() -> None:
    flows = [packet_syn(offset, sequence=111) for offset in (0, 2, 4, 6, 8, 9)]
    analysis_context = context(flows, periodicity_min_samples=5)

    evidence = TCPCommunicationAttemptDetector().analyze(analysis_context)
    candidates = score_candidates(run_detectors(analysis_context))

    assert evidence[0].metrics["retry_intervals_ms"] == [2000, 2000, 2000, 2000]
    assert candidates[0].candidate_kind == "COMMUNICATION_STATUS"
    assert candidates[0].score == 0


@pytest.mark.parametrize(
    ("response_start", "duration_seconds"),
    [(12.9, 0.2), (-1.0, 14.1)],
)
def test_response_aggregate_crossing_new_sequence_boundary_is_not_attributed(
    response_start: float, duration_seconds: float
) -> None:
    new_attempt = replace(packet_syn(13, sequence=222), sensor_id="sensor-a")
    response = replace(
        inbound_response(syn_ack=1),
        timestamp=START + timedelta(seconds=response_start),
        duration_seconds=duration_seconds,
    )
    analysis_context = replace(
        context([outbound_retry(), new_attempt, response]),
        start=START - timedelta(seconds=2),
    )

    evidence = TCPCommunicationAttemptDetector().analyze(analysis_context)[0]

    assert evidence.metrics["outcome"] == "NO_COMPLETION_OBSERVED"
    assert evidence.metrics["response_timing_approximate"] is True
    assert "aggregate_response_timing_approximate" in evidence.warnings


def test_zero_tolerance_requires_exact_interval_multiples() -> None:
    detector = TCPCommunicationAttemptDetector()
    parameters = {
        "tcp_syn_retry_absolute_tolerance_ms": 0,
        "tcp_syn_retry_tolerance_ratio": 0,
    }

    assert detector.analyze(context([outbound_retry(intervals=(1000, 2000, 3000))], **parameters))
    assert (
        detector.analyze(context([outbound_retry(intervals=(1000, 2001, 3000))], **parameters))
        == []
    )


def test_retry_timeline_can_span_bounded_sensor_flush_aggregates() -> None:
    first = replace(
        outbound_retry(intervals=(2000,)),
        tcp_syn_count=2,
        tcp_syn_only_count=2,
        packet_count=2,
        duration_seconds=2,
    )
    second = replace(
        outbound_retry(intervals=(6000,)),
        timestamp=START + timedelta(seconds=6),
        tcp_syn_count=2,
        tcp_syn_only_count=2,
        packet_count=2,
        duration_seconds=6,
    )

    evidence = TCPCommunicationAttemptDetector().analyze(context([first, second]))

    assert evidence[0].metrics["retry_intervals_ms"] == [2000, 4000, 6000]


def test_subsecond_syn_burst_is_not_a_retry_attempt_pattern() -> None:
    burst = outbound_retry(intervals=(100,) * 15)

    assert TCPCommunicationAttemptDetector().analyze(context([burst])) == []


def test_slow_retry_status_survives_same_peer_control_flood_suppression() -> None:
    flood = Flow(
        sensor_id="sensor-a",
        timestamp=START,
        source_ip="10.0.0.1",
        destination_ip=TARGET,
        source_port=51000,
        destination_port=4444,
        protocol="TCP",
        direction="OUTBOUND",
        packet_count=40,
        total_bytes=2400,
        duration_seconds=1,
        tcp_flags={"syn": 40},
        tcp_flags_observed=True,
        tcp_syn_count=40,
        tcp_syn_only_count=40,
    )

    evidence = run_detectors(context([outbound_retry(), flood]))

    assert [item.type for item in evidence] == ["TCP_COMMUNICATION_ATTEMPT_PATTERN"]


def test_retry_observation_budget_overflow_fails_open() -> None:
    observations = tuple(
        (index * 2_000_000, 12345) for index in range(MAX_SYN_RETRY_OBSERVATIONS_PER_CONNECTION + 1)
    )
    flow = replace(
        outbound_retry(),
        packet_count=len(observations),
        tcp_syn_count=len(observations),
        tcp_syn_only_count=len(observations),
        tcp_syn_only_observations=observations,
        duration_seconds=(len(observations) - 1) * 2,
    )

    evidence = TCPCommunicationAttemptDetector().analyze(context([flow]))
    assert evidence[0].type == "TCP_COMMUNICATION_ATTEMPT_ANALYSIS_INCOMPLETE"
    assert evidence[0].metrics["reason"] == "observation_budget_exceeded"
    assert evidence[0].warnings == ("retry_analysis_incomplete",)


def test_retry_episode_budget_overflow_fails_open() -> None:
    observations: list[tuple[int, int]] = []
    for sequence in range(MAX_SYN_RETRY_EPISODES_PER_CONNECTION + 1):
        start_us = sequence * 20_000_000
        observations.extend((start_us + offset * 1_000_000, sequence) for offset in (0, 2, 4, 6))
    flow = replace(
        outbound_retry(),
        packet_count=len(observations),
        tcp_syn_count=len(observations),
        tcp_syn_only_count=len(observations),
        tcp_syn_only_observations=tuple(observations),
        duration_seconds=observations[-1][0] / 1_000_000,
    )

    evidence = TCPCommunicationAttemptDetector().analyze(context([flow]))
    assert evidence[0].type == "TCP_COMMUNICATION_ATTEMPT_ANALYSIS_INCOMPLETE"
    assert evidence[0].metrics["reason"] == "episode_budget_exceeded"
    assert evidence[0].warnings == ("retry_analysis_incomplete",)


def test_retry_evidence_interval_projection_is_bounded() -> None:
    flow = outbound_retry(intervals=(2000,) * 20)

    evidence = TCPCommunicationAttemptDetector().analyze(context([flow]))[0]

    assert evidence.metrics["retransmission_count"] == 20
    assert evidence.metrics["retry_intervals_ms"] == [2000] * 15
    assert evidence.metrics["retry_intervals_truncated"] is True


def test_retry_evidence_is_bounded_across_connections_for_one_candidate() -> None:
    flows = [
        replace(outbound_retry(), source_port=40_000 + index)
        for index in range(EXPECTED_RETRY_EVIDENCE_PER_CANDIDATE + 1)
    ]

    evidence = TCPCommunicationAttemptDetector().analyze(context(flows))

    assert len(evidence) == EXPECTED_RETRY_EVIDENCE_PER_CANDIDATE
    assert evidence[-1].type == "TCP_COMMUNICATION_ATTEMPT_ANALYSIS_INCOMPLETE"
    assert evidence[-1].metrics["reason"] == "candidate_evidence_budget_exceeded"


def test_exact_candidate_evidence_budget_is_complete() -> None:
    flows = [
        replace(outbound_retry(), source_port=40_000 + index)
        for index in range(EXPECTED_RETRY_EVIDENCE_PER_CANDIDATE)
    ]

    evidence = TCPCommunicationAttemptDetector().analyze(context(flows))

    assert len(evidence) == EXPECTED_RETRY_EVIDENCE_PER_CANDIDATE
    assert all(item.type == "TCP_COMMUNICATION_ATTEMPT_PATTERN" for item in evidence)


def test_retry_deduplication_fails_open_after_candidate_evidence_budget() -> None:
    flows = [
        replace(
            packet_syn(offset, sequence=port),
            source_port=port,
        )
        for port in range(40_000, 40_000 + EXPECTED_RETRY_EVIDENCE_PER_CANDIDATE + 1)
        for offset in (0, 2, 6, 12)
    ]

    duplicates = syn_retry_duplicate_flow_ids(context(flows))

    assert len(duplicates) == (EXPECTED_RETRY_EVIDENCE_PER_CANDIDATE - 1) * 3


def test_retry_evidence_is_bounded_across_candidates_for_one_analysis() -> None:
    flows = [
        replace(
            outbound_retry(),
            destination_ip=f"203.{index // 256}.{index % 256}.40",
        )
        for index in range(EXPECTED_RETRY_EVIDENCE_PER_ANALYSIS + 1)
    ]

    evidence = TCPCommunicationAttemptDetector().analyze(context(flows))

    assert len(evidence) == EXPECTED_RETRY_EVIDENCE_PER_ANALYSIS
    assert evidence[-1].type == "TCP_COMMUNICATION_ATTEMPT_ANALYSIS_INCOMPLETE"
    assert evidence[-1].metrics["reason"] == "analysis_evidence_budget_exceeded"


def test_exact_analysis_evidence_budget_is_complete() -> None:
    flows = [
        replace(
            outbound_retry(),
            destination_ip=f"203.{index // 256}.{index % 256}.40",
        )
        for index in range(EXPECTED_RETRY_EVIDENCE_PER_ANALYSIS)
    ]

    evidence = TCPCommunicationAttemptDetector().analyze(context(flows))

    assert len(evidence) == EXPECTED_RETRY_EVIDENCE_PER_ANALYSIS
    assert all(item.type == "TCP_COMMUNICATION_ATTEMPT_PATTERN" for item in evidence)


def test_operational_evidence_cannot_change_c2_scoring_adjustments() -> None:
    threat = [
        Evidence(
            TARGET,
            "SINGLE_HOST_BEACON",
            "single_host_composite_beacon",
            "1",
            35,
            35,
            "single host beacon",
            hosts=("10.0.0.1",),
        ),
        Evidence(
            TARGET,
            "NON_WELL_KNOWN_PORT",
            "non_well_known_port",
            "1",
            25,
            25,
            "high port",
            hosts=("10.0.0.1",),
        ),
    ]
    operational = Evidence(
        TARGET,
        "TCP_COMMUNICATION_ATTEMPT_PATTERN",
        "tcp_communication_attempt",
        "1",
        0,
        0,
        "retry status",
        hosts=("10.0.0.2",),
        metrics={"public_dns_ntp": True, "cdn_cloud": True},
    )

    baseline = score_candidates(threat)[0]
    enriched = score_candidates([*threat, operational])[0]

    assert enriched.score == baseline.score
    assert enriched.severity == baseline.severity
    assert enriched.adjustments == baseline.adjustments
    assert enriched.hosts == ("10.0.0.1", "10.0.0.2")


def test_response_row_budget_overflow_is_reported() -> None:
    responses = [
        replace(
            inbound_response(syn_ack=1),
            timestamp=START + timedelta(seconds=12.1, microseconds=index),
        )
        for index in range(MAX_SYN_RETRY_RESPONSE_ROWS + 1)
    ]

    evidence = TCPCommunicationAttemptDetector().analyze(context([outbound_retry(), *responses]))[0]

    assert evidence.metrics["response_rows_truncated"] is True
    assert evidence.metrics["response_row_limit"] == MAX_SYN_RETRY_RESPONSE_ROWS
    assert evidence.metrics["outcome"] == "PEER_RESPONSE_OBSERVED"
    assert "response_correlation_truncated" in evidence.warnings


def test_response_row_truncation_is_scoped_to_one_retry_episode() -> None:
    first_episode = [replace(packet_syn(offset), sensor_id="sensor-a") for offset in (0, 2, 6, 12)]
    second_episode = [
        replace(packet_syn(offset), sensor_id="sensor-a") for offset in (150, 152, 156, 162)
    ]
    responses = [
        replace(
            inbound_response(syn_ack=1),
            timestamp=START + timedelta(seconds=12.1, microseconds=index),
        )
        for index in range(MAX_SYN_RETRY_RESPONSE_ROWS + 1)
    ]

    evidence = TCPCommunicationAttemptDetector().analyze(
        context([*first_episode, *responses, *second_episode])
    )

    assert "response_correlation_truncated" in evidence[0].warnings
    assert "response_correlation_truncated" not in evidence[1].warnings


def test_irregular_short_or_changed_sequence_trains_are_not_retransmissions() -> None:
    detector = TCPCommunicationAttemptDetector()
    changed_sequence = replace(
        outbound_retry(),
        tcp_syn_only_observations=((0, 1), (2_000_000, 2), (6_000_000, 3), (12_000_000, 4)),
    )

    assert detector.analyze(context([outbound_retry(intervals=(2000, 9100, 1100))])) == []
    assert detector.analyze(context([outbound_retry(intervals=(6000, 2000, 8000))])) == []
    assert detector.analyze(context([outbound_retry(intervals=(2000, 4000))])) == []
    assert detector.analyze(context([changed_sequence])) == []


def test_missing_truncated_inbound_or_incomplete_tuple_telemetry_fails_open() -> None:
    detector = TCPCommunicationAttemptDetector()
    inbound = replace(
        outbound_retry(),
        source_ip=TARGET,
        destination_ip="10.0.0.1",
        source_port=443,
        destination_port=50000,
        direction="INBOUND",
    )

    assert (
        detector.analyze(context([replace(outbound_retry(), tcp_syn_only_observations=None)])) == []
    )
    assert (
        detector.analyze(
            context([replace(outbound_retry(), tcp_syn_only_observations_truncated=True)])
        )
        == []
    )
    assert detector.analyze(context([inbound])) == []
    assert detector.analyze(context([replace(outbound_retry(), source_port=None)])) == []


def test_changing_source_ports_remain_distinct_application_attempts() -> None:
    flows = [
        replace(
            outbound_retry(intervals=()),
            timestamp=START + timedelta(seconds=offset),
            source_port=50000 + index,
            tcp_syn_only_observations=((0, 1000 + index),),
        )
        for index, offset in enumerate((0, 2, 6, 12))
    ]

    assert TCPCommunicationAttemptDetector().analyze(context(flows)) == []


def test_unknown_direction_uses_internal_network_and_detector_can_be_disabled() -> None:
    flow = replace(outbound_retry(), direction="UNKNOWN")
    detector = TCPCommunicationAttemptDetector()

    assert detector.analyze(context([flow]))
    assert detector.analyze(context([flow], tcp_syn_retry_detection_enabled=False)) == []


def packet_syn(offset: int, sequence: int = 12345) -> Flow:
    return Flow(
        sensor_id="pcap",
        timestamp=START + timedelta(seconds=offset),
        source_ip="10.0.0.1",
        destination_ip=TARGET,
        source_port=50000,
        destination_port=443,
        protocol="TCP",
        direction="OUTBOUND",
        packet_count=1,
        total_bytes=60,
        tcp_flags={"syn": 1},
        tcp_flags_observed=True,
        tcp_syn_count=1,
        tcp_syn_only_count=1,
        tcp_syn_only_observations=((0, sequence),),
    )


def test_packet_level_pcap_retransmissions_are_collapsed_to_one_periodic_sample() -> None:
    flows = [packet_syn(offset) for offset in (0, 2, 4, 6, 8)]
    analysis = context(flows, periodicity_min_samples=5)

    evidence = run_detectors(analysis)
    prefilter = generate_high_recall_candidates(analysis)

    assert not any(item.type in {"PERIODIC_BEACON", "SINGLE_HOST_BEACON"} for item in evidence)
    assert any(item.type == "TCP_COMMUNICATION_ATTEMPT_PATTERN" for item in evidence)
    assert prefilter
    assert not any(factor.name == "SINGLE_HOST_BEACON" for factor in prefilter[0].factors)
    assert PREFILTER_VERSION == "ai-prefilter-v3"


def test_missing_sequence_timeline_does_not_suppress_existing_c2_analysis() -> None:
    legacy = [
        replace(packet_syn(offset), tcp_syn_only_observations=None) for offset in (0, 2, 4, 6, 8)
    ]
    analysis = context(legacy, periodicity_min_samples=5)

    assert PeriodicBeaconDetector().analyze(analysis)
    assert TCPCommunicationAttemptDetector().analyze(analysis) == []


def test_pcap_decoder_preserves_same_sequence_syn_timeline() -> None:
    packets: list[bytes] = []
    ethernet = b"\x00" * 12 + b"\x08\x00"
    for index, offset in enumerate((0, 2, 6, 12)):
        second = int(START.timestamp()) + offset
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            index,
            0x4000,
            64,
            6,
            0,
            b"\x0a\x00\x00\x01",
            b"\xcb\x00\x71\x28",
        )
        tcp_header = struct.pack("!HHIIHHHH", 50000, 443, 12345, 0, (5 << 12) | 0x002, 65535, 0, 0)
        packet = ethernet + ip_header + tcp_header
        packets.append(struct.pack("<IIII", second, 0, len(packet), len(packet)) + packet)
    reply_payload = b"reply"
    reply_ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(reply_payload),
        4,
        0x4000,
        64,
        6,
        0,
        b"\xcb\x00\x71\x28",
        b"\x0a\x00\x00\x01",
    )
    reply_tcp = struct.pack("!HHIIHHHH", 443, 50000, 999, 12346, (5 << 12) | 0x010, 65535, 0, 0)
    reply = ethernet + reply_ip + reply_tcp + reply_payload
    packets.append(
        struct.pack("<IIII", int(START.timestamp()) + 12, 100_000, len(reply), len(reply)) + reply
    )
    pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(packets)
    parsed = parse_pcap(
        pcap,
        sensor_id="pcap",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
    )
    flows = []
    for stored in parsed.records:
        record = dict(stored)
        record.pop("raw_packet_hex", None)
        record.pop("payload_sample_hex", None)
        record["tcp_syn_only_observations"] = normalize_tcp_syn_observations(
            record.get("tcp_syn_only_observations")
        )
        flows.append(Flow(**record))

    evidence = TCPCommunicationAttemptDetector().analyze(context(flows))

    assert evidence[0].metrics["retry_intervals_ms"] == [2000, 4000, 6000]
    assert evidence[0].metrics["distinct_initial_sequence_count"] == 1
    assert evidence[0].metrics["outcome"] == "PEER_RESPONSE_OBSERVED"


def test_packet_level_retry_sequences_split_across_long_idle_gaps() -> None:
    flows = [packet_syn(offset) for offset in (0, 2, 6, 12, 150, 152, 156, 162)]

    evidence = TCPCommunicationAttemptDetector().analyze(context(flows))

    assert len(evidence) == 2
    assert evidence[0].metrics["retry_intervals_ms"] == [2000, 4000, 6000]
    assert evidence[0].first_seen == START
    assert evidence[0].last_seen == START + timedelta(seconds=12)
    assert evidence[1].first_seen == START + timedelta(seconds=150)
    assert evidence[1].last_seen == START + timedelta(seconds=162)


def test_every_packet_level_retry_episode_is_deduplicated_for_c2_periodicity() -> None:
    flows = [packet_syn(offset) for offset in (0, 2, 4, 6, 8, 150, 152, 154, 156, 158)]
    analysis = context(flows, periodicity_min_samples=5)

    assert PeriodicBeaconDetector().analyze(analysis) == []
    candidates = generate_high_recall_candidates(analysis)
    assert not any(
        factor.name == "SINGLE_HOST_BEACON"
        for candidate in candidates
        for factor in candidate.factors
    )


def test_attempt_pattern_does_not_hide_payload_bearing_c2_evidence() -> None:
    retry = replace(outbound_retry(), last_payload_hash="payload")
    analysis = context([retry])

    assert TCPCommunicationAttemptDetector().analyze(analysis)
    assert generate_high_recall_candidates(analysis)
    assert PeriodicBeaconDetector().analyze(analysis) == []


def test_packet_level_syn_payload_is_not_removed_as_a_retry_duplicate() -> None:
    flows = [packet_syn(offset) for offset in (0, 2, 4, 6, 8)]
    payload_syn = replace(
        flows[3],
        payload_hash="payload",
        payload_length=12,
    )
    flows[3] = payload_syn
    analysis = context(flows)

    retained = qualified_candidate_groups(analysis)[TARGET]

    assert any(flow is payload_syn for _host, flow in retained)
