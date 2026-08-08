"""Regression tests for high-volume TCP session C2 suppression."""

from datetime import UTC, datetime, timedelta

from c2hunter_analysis.domain import AnalysisContext, Evidence, Flow
from c2hunter_analysis.scoring import score_candidates

NOW = datetime(2026, 8, 8, tzinfo=UTC)
CANDIDATE = "203.0.113.50"
HOSTS = ("10.0.0.1", "10.0.0.2", "10.0.0.3")


def _flow(
    *,
    protocol: str,
    packets: int,
    size: int,
    source_port: int = 50000,
    second: int = 0,
) -> Flow:
    return Flow(
        sensor_id="sensor-1",
        timestamp=NOW + timedelta(seconds=second),
        source_ip="10.0.0.1",
        destination_ip=CANDIDATE,
        source_port=source_port,
        destination_port=443,
        protocol=protocol,
        direction="OUTBOUND",
        packet_count=packets,
        total_bytes=size,
    )


def _high_confidence_evidence(*, exact_match: bool = False) -> list[Evidence]:
    evidence = [
        Evidence(
            CANDIDATE,
            "COMMON_DESTINATION",
            "common_destination",
            "1",
            20,
            20,
            "many hosts",
            hosts=HOSTS,
        ),
        Evidence(
            CANDIDATE,
            "PERIODIC_BEACON",
            "periodic_beacon",
            "1",
            15,
            15,
            "periodic",
            hosts=HOSTS,
        ),
        Evidence(
            CANDIDATE,
            "COMMAND_ATTACK_CORRELATION",
            "command_attack_correlation",
            "1",
            25,
            25,
            "attack correlation",
            hosts=HOSTS,
        ),
    ]
    if exact_match:
        evidence.append(
            Evidence(
                CANDIDATE,
                "ANALYST_PAYLOAD_SIGNATURE",
                "analyst_payload_signature",
                "1",
                80,
                80,
                "confirmed payload",
                hosts=HOSTS,
                metrics={"match_mode": "EXACT"},
            )
        )
    return evidence


def test_candidate_profile_aggregates_tcp_records_by_five_tuple() -> None:
    context = AnalysisContext(
        dataset_id="dataset",
        start=NOW,
        end=NOW + timedelta(minutes=1),
        flows=[
            _flow(protocol="TCP", packets=30, size=30_000, second=1),
            _flow(protocol="tcp", packets=25, size=25_000, second=2),
            Flow(
                sensor_id="sensor-1",
                timestamp=NOW + timedelta(seconds=3),
                source_ip=CANDIDATE,
                destination_ip="10.0.0.1",
                source_port=443,
                destination_port=50000,
                protocol="TCP",
                direction="INBOUND",
                packet_count=5,
                total_bytes=5_000,
            ),
            _flow(protocol="TCP", packets=10, size=10_000, source_port=50001, second=4),
            _flow(protocol="UDP", packets=1_000, size=1_000_000, second=5),
        ],
        internal_cidrs=("10.0.0.0/8",),
    )

    profile = context.candidate_traffic_profiles()[CANDIDATE]

    assert profile["tcp_session_count"] == 2
    assert profile["max_tcp_session_packets"] == 60
    assert profile["max_tcp_session_bytes"] == 60_000


def test_high_volume_tcp_session_caps_c2_score() -> None:
    candidate = score_candidates(
        _high_confidence_evidence(),
        traffic_profiles={
            CANDIDATE: {
                "max_tcp_session_bytes": 55_000,
                "max_tcp_session_packets": 55,
            }
        },
        high_volume_bytes_threshold=0,
        high_volume_packet_threshold=0,
        high_volume_tcp_session_bytes_threshold=50_000,
        high_volume_tcp_session_packet_threshold=0,
        high_volume_tcp_session_score_cap=20,
    )[0]

    assert candidate.score == 20
    adjustment = next(
        item for item in candidate.adjustments if item.kind == "HIGH_VOLUME_TCP_SESSION"
    )
    assert adjustment.points == -40
    assert "55,000" in adjustment.explanation


def test_exact_analyst_match_bypasses_tcp_session_cap() -> None:
    candidate = score_candidates(
        _high_confidence_evidence(exact_match=True),
        traffic_profiles={
            CANDIDATE: {
                "max_tcp_session_bytes": 100_000,
                "max_tcp_session_packets": 100,
            }
        },
        high_volume_bytes_threshold=0,
        high_volume_packet_threshold=0,
        high_volume_tcp_session_bytes_threshold=50_000,
        high_volume_tcp_session_packet_threshold=0,
        high_volume_tcp_session_score_cap=20,
    )[0]

    assert candidate.score == 100
    assert not any(item.kind == "HIGH_VOLUME_TCP_SESSION" for item in candidate.adjustments)


def test_tcp_session_packet_threshold_can_cap_when_byte_threshold_is_disabled() -> None:
    candidate = score_candidates(
        _high_confidence_evidence(),
        traffic_profiles={
            CANDIDATE: {
                "max_tcp_session_bytes": 1,
                "max_tcp_session_packets": 100_000,
            }
        },
        high_volume_bytes_threshold=0,
        high_volume_packet_threshold=0,
        high_volume_tcp_session_bytes_threshold=0,
        high_volume_tcp_session_packet_threshold=100_000,
        high_volume_tcp_session_score_cap=20,
    )[0]

    assert candidate.score == 20
    assert any(item.kind == "HIGH_VOLUME_TCP_SESSION" for item in candidate.adjustments)


def test_disabled_tcp_session_thresholds_do_not_change_score() -> None:
    candidate = score_candidates(
        _high_confidence_evidence(),
        traffic_profiles={
            CANDIDATE: {
                "max_tcp_session_bytes": 1_000_000_000,
                "max_tcp_session_packets": 1_000_000,
            }
        },
        high_volume_bytes_threshold=0,
        high_volume_packet_threshold=0,
        high_volume_tcp_session_bytes_threshold=0,
        high_volume_tcp_session_packet_threshold=0,
        high_volume_tcp_session_score_cap=20,
    )[0]

    assert candidate.score == 60
    assert not any(item.kind == "HIGH_VOLUME_TCP_SESSION" for item in candidate.adjustments)


def test_udp_volume_and_multiple_small_tcp_sessions_do_not_trigger_session_cap() -> None:
    context = AnalysisContext(
        dataset_id="dataset",
        start=NOW,
        end=NOW + timedelta(minutes=1),
        flows=[
            _flow(protocol="TCP", packets=30, size=30_000, source_port=50000, second=1),
            _flow(protocol="TCP", packets=30, size=30_000, source_port=50001, second=2),
            _flow(protocol="UDP", packets=1_000_000, size=1_000_000_000, second=3),
        ],
        internal_cidrs=("10.0.0.0/8",),
    )
    profile = context.candidate_traffic_profiles()[CANDIDATE]

    candidate = score_candidates(
        _high_confidence_evidence(),
        traffic_profiles={CANDIDATE: profile},
        high_volume_bytes_threshold=0,
        high_volume_packet_threshold=0,
        high_volume_tcp_session_bytes_threshold=50_000,
        high_volume_tcp_session_packet_threshold=100,
        high_volume_tcp_session_score_cap=20,
    )[0]

    assert profile["total_bytes"] > 1_000_000_000
    assert profile["max_tcp_session_bytes"] == 30_000
    assert profile["max_tcp_session_packets"] == 30
    assert candidate.score == 60
    assert not any(item.kind == "HIGH_VOLUME_TCP_SESSION" for item in candidate.adjustments)
