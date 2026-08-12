from datetime import UTC, datetime, timedelta

import pytest

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


def test_scoring_applies_per_run_detector_weights_with_auditable_adjustment() -> None:
    evidence = [
        Evidence(
            "203.0.113.9",
            "COMMON_DESTINATION",
            "common_destination",
            "1",
            20,
            20,
            "many hosts",
            hosts=("10.0.0.1", "10.0.0.2", "10.0.0.3"),
        ),
        Evidence(
            "203.0.113.9",
            "PERIODIC_BEACON",
            "periodic_beacon",
            "1",
            15,
            15,
            "periodic",
            hosts=("10.0.0.1", "10.0.0.2", "10.0.0.3"),
        ),
    ]

    default = score_candidates(evidence)[0]
    tuned = score_candidates(
        evidence,
        detector_weights={"common_destination": 0.25},
    )[0]

    assert default.score == 35
    assert tuned.score == 20
    assert tuned.evidence == default.evidence
    assert [(item.kind, item.points) for item in tuned.adjustments] == [
        ("DETECTOR_WEIGHT_COMMON_DESTINATION", -15)
    ]


def test_scoring_weight_above_one_exceeds_base_cap_and_keeps_final_cap() -> None:
    evidence = [
        Evidence(
            "203.0.113.9",
            "COMMON_DESTINATION",
            "common_destination",
            "1",
            20,
            20,
            "many hosts",
            hosts=("10.0.0.1", "10.0.0.2", "10.0.0.3"),
        ),
        Evidence(
            "203.0.113.9",
            "ANALYST_PAYLOAD_SIGNATURE",
            "analyst_payload_signature",
            "1",
            80,
            80,
            "analyst match",
            hosts=("10.0.0.1", "10.0.0.2", "10.0.0.3"),
            metrics={"match_mode": "EXACT"},
        ),
    ]

    tuned = score_candidates(
        evidence,
        detector_weights={
            "common_destination": 2.0,
            "analyst_payload_signature": 2.0,
        },
    )[0]

    assert tuned.score == 100
    assert [(item.kind, item.points) for item in tuned.adjustments] == [
        ("DETECTOR_WEIGHT_ANALYST_PAYLOAD_SIGNATURE", 80),
        ("DETECTOR_WEIGHT_COMMON_DESTINATION", 20),
    ]


def test_scoring_preserves_fractional_detector_weight_adjustment_until_final_rounding() -> None:
    evidence = [
        Evidence(
            "203.0.113.45",
            "COMMON_DESTINATION",
            "common_destination",
            "1",
            2.5,
            2.5,
            "fractional contribution",
            hosts=("10.0.0.1", "10.0.0.2", "10.0.0.3"),
        )
    ]

    tuned = score_candidates(
        evidence,
        detector_weights={"common_destination": 2.0},
    )[0]

    assert tuned.score == 5
    assert [(item.kind, item.points) for item in tuned.adjustments] == [
        ("DETECTOR_WEIGHT_COMMON_DESTINATION", 2.5)
    ]


def test_allowlist_suppresses_matching_ip_and_cidr() -> None:
    evidence = [Evidence("203.0.113.9", "COMMON_DESTINATION", "common", "1", 10, 10, "x")]
    entries = [AllowlistEntry("CIDR", "203.0.113.0/24", "test network")]
    assert score_candidates(evidence, allowlist=entries) == []


def test_allowlist_is_inactive_at_exact_expiration_instant() -> None:
    entry = AllowlistEntry(
        "IP",
        "203.0.113.9",
        "expires exactly now",
        expires_at=NOW,
    )

    assert entry.is_active(NOW) is False


def test_allowlist_legacy_naive_expiration_is_inactive() -> None:
    entry = AllowlistEntry.from_mapping(
        {
            "type": "IP",
            "value": "203.0.113.9",
            "description": "legacy",
            "expires_at": "2026-07-20T01:00:00",
        }
    )

    assert entry.is_active(datetime(2026, 7, 20, 0, 59, tzinfo=UTC)) is False


@pytest.mark.parametrize(
    "expires_at",
    [
        "",
        "07/20/2026 01:00",
        4_089_758_200,
        {"timestamp": "2099-08-13T09:30:00Z"},
        ["2099-08-13T09:30:00Z"],
    ],
)
def test_allowlist_malformed_legacy_expiration_is_inactive(expires_at: object) -> None:
    entry = AllowlistEntry.from_mapping(
        {
            "type": "IP",
            "value": "203.0.113.9",
            "description": "malformed legacy",
            "expires_at": expires_at,
        }
    )

    assert entry.is_active(NOW) is False


def test_allowlist_missing_legacy_expiration_remains_active() -> None:
    entry = AllowlistEntry.from_mapping(
        {
            "type": "IP",
            "value": "203.0.113.9",
            "description": "no expiration",
            "expires_at": None,
        }
    )

    assert entry.is_active(NOW) is True


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
