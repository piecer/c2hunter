from datetime import UTC, datetime, timedelta

from c2hunter_analysis.domain import (
    AllowlistEntry,
    AnalysisContext,
    Evidence,
    PacketObservation,
)
from c2hunter_analysis.ingestion import deduplicate_observations
from c2hunter_analysis.scoring import score_candidates, severity_for

NOW = datetime(2026, 7, 20, tzinfo=UTC)


def test_analysis_context_rejects_invalid_time_range() -> None:
    try:
        AnalysisContext(dataset_id="d", start=NOW, end=NOW - timedelta(seconds=1), flows=[])
    except ValueError as exc:
        assert "end" in str(exc)
    else:
        raise AssertionError("invalid range accepted")


def test_dedup_preserves_all_sensor_observations() -> None:
    observations = [
        PacketObservation("s1", NOW, "10.0.0.1", "203.0.113.9", 1200, 443, "TCP", 5, 7, 30, "abc"),
        PacketObservation(
            "s2",
            NOW + timedelta(milliseconds=1),
            "10.0.0.1",
            "203.0.113.9",
            1200,
            443,
            "TCP",
            5,
            7,
            30,
            "abc",
        ),
    ]
    packets = deduplicate_observations(observations, timestamp_bucket_ms=10)
    assert len(packets) == 1
    assert packets[0].logical_count == 1
    assert {item.sensor_id for item in packets[0].observations} == {"s1", "s2"}


def test_scoring_caps_each_detector_and_assigns_boundaries() -> None:
    evidence = [
        Evidence("203.0.113.9", "COMMON_DESTINATION", "common", "1", 99, 99, "many hosts"),
        Evidence("203.0.113.9", "PERIODIC_BEACON", "beacon", "1", 99, 99, "periodic"),
        Evidence("203.0.113.9", "COMMAND_ATTACK_CORRELATION", "attack", "1", 99, 99, "attack"),
    ]
    candidate = score_candidates(evidence)[0]
    assert candidate.score == 60
    assert candidate.severity == "HIGH"
    assert [severity_for(value) for value in (0, 39, 40, 59, 60, 79, 80, 100)] == [
        "LOW",
        "LOW",
        "MEDIUM",
        "MEDIUM",
        "HIGH",
        "HIGH",
        "CRITICAL",
        "CRITICAL",
    ]


def test_allowlist_suppresses_matching_ip_and_cidr() -> None:
    evidence = [Evidence("203.0.113.9", "COMMON_DESTINATION", "common", "1", 10, 10, "x")]
    entries = [AllowlistEntry("CIDR", "203.0.113.0/24", "test network")]
    assert score_candidates(evidence, allowlist=entries) == []


def test_score_applies_single_host_and_low_sample_penalties() -> None:
    evidence = [
        Evidence(
            "198.51.100.2",
            "COMMON_DESTINATION",
            "common",
            "1",
            20,
            20,
            "x",
            hosts=("10.0.0.1",),
            metrics={"sample_count": 2},
        )
    ]
    candidate = score_candidates(evidence, minimum_samples=5)[0]
    assert candidate.score == 0
    assert {a.kind for a in candidate.adjustments} == {"SINGLE_HOST", "LOW_SAMPLE"}
