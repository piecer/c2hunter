import pytest
from pydantic import ValidationError

from c2hunter_controller.capture_limits import limit_flow_records
from c2hunter_controller.schemas import AnalysisParameters, FlowRecord


def tcp_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "sensor_id": "sensor-a",
        "timestamp": "2026-08-07T00:00:00+00:00",
        "source_ip": "10.0.0.10",
        "destination_ip": "203.0.113.10",
        "source_port": 50000,
        "destination_port": 443,
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "packet_count": 3,
        "total_bytes": 180,
        "tcp_flags_observed": True,
        "tcp_syn_count": 1,
        "tcp_ack_count": 1,
        "tcp_syn_only_count": 1,
        "tcp_ack_only_count": 1,
        "bidirectional": True,
    }
    record.update(overrides)
    return record


def test_flow_record_accepts_consistent_tcp_metadata() -> None:
    parsed = FlowRecord.model_validate(
        tcp_record(
            packet_count=4,
            tcp_syn_count=4,
            tcp_ack_count=0,
            tcp_syn_only_count=4,
            tcp_ack_only_count=0,
            bidirectional=False,
            duration_seconds=12,
            tcp_syn_only_observations=[
                {"offset_us": 0, "sequence": 12345},
                {"offset_us": 2_000_000, "sequence": 12345},
                {"offset_us": 6_000_000, "sequence": 12345},
                {"offset_us": 12_000_000, "sequence": 12345},
            ],
        )
    )
    assert parsed.tcp_syn_only_count == 4
    assert parsed.tcp_ack_only_count == 0
    assert parsed.bidirectional is False
    assert [item.offset_us for item in parsed.tcp_syn_only_observations or []] == [
        0,
        2_000_000,
        6_000_000,
        12_000_000,
    ]


def test_flow_record_normalizes_tcp_flag_names_and_preserves_duration() -> None:
    parsed = FlowRecord.model_validate(
        tcp_record(
            packet_count=3,
            tcp_flags={" SYN ": 2, "ACK": 1},
            duration_seconds=6.4,
        )
    )

    assert parsed.tcp_flags == {"syn": 2, "ack": 1}
    assert parsed.duration_seconds == 6.4

    sensor_aggregate = FlowRecord.model_validate(
        tcp_record(
            tcp_flags={
                "NS": 1,
                "rst_ratio": 0.5,
                "syn_ack_ratio": 2.0,
                "connection_count": 2,
            }
        )
    )
    assert sensor_aggregate.tcp_flags == {
        "ns": 1,
        "rst_ratio": 0.5,
        "syn_ack_ratio": 2.0,
        "connection_count": 2,
    }


def test_flow_record_rejects_duplicate_tcp_flag_names() -> None:
    with pytest.raises(ValidationError, match="duplicate TCP flag"):
        FlowRecord.model_validate(tcp_record(tcp_flags={"SYN": 1, "syn": 1}))


def test_flow_record_rejects_fractional_tcp_flag_counts() -> None:
    with pytest.raises(ValidationError, match="must be an integer count"):
        FlowRecord.model_validate(tcp_record(tcp_flags={"syn": 0.5}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"duration_seconds": float("inf")},
        {"duration_seconds": 1e308},
        {"tcp_flags": {"syn": float("inf")}},
    ],
)
def test_flow_record_rejects_non_finite_or_unbounded_numeric_metadata(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        FlowRecord.model_validate(tcp_record(**overrides))


@pytest.mark.parametrize("count", [2**64 - 2, 2**64 - 1])
def test_flow_record_preserves_uint64_tcp_flag_boundaries(count: int) -> None:
    parsed = FlowRecord.model_validate(tcp_record(tcp_flags={"syn": count}))

    assert parsed.tcp_flags == {"syn": count}


def test_flow_record_rejects_oversized_integer_as_validation_error() -> None:
    with pytest.raises(ValidationError, match="exceeds uint64"):
        FlowRecord.model_validate(tcp_record(tcp_flags={"syn": 10**1_000}))


def test_tcp_session_gating_defaults_are_safe_and_configurable() -> None:
    defaults = AnalysisParameters()
    configured = AnalysisParameters(
        tcp_session_gating_enabled=False,
        tcp_allow_legacy_without_flags=False,
        tcp_scan_min_targets=12,
        tcp_scan_probe_ratio=0.9,
    )

    assert defaults.tcp_session_gating_enabled is True
    assert defaults.tcp_allow_legacy_without_flags is True
    assert defaults.tcp_scan_min_targets == 8
    assert defaults.tcp_scan_probe_max_packets == 4
    assert defaults.tcp_scan_probe_ratio == 0.8
    assert defaults.tcp_syn_retry_detection_enabled is True
    assert defaults.tcp_syn_retry_min_intervals == 3
    assert defaults.tcp_syn_retry_min_interval_ms == 500
    assert defaults.tcp_syn_retry_max_interval_ms == 120_000
    assert configured.tcp_session_gating_enabled is False
    assert configured.tcp_allow_legacy_without_flags is False
    assert configured.tcp_scan_min_targets == 12
    assert configured.tcp_scan_probe_ratio == 0.9


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tcp_outbound_initiated_contribution", 16),
        ("tcp_established_contribution", -1),
        ("tcp_scan_min_targets", 1),
        ("tcp_scan_probe_max_packets", 0),
        ("tcp_scan_probe_ratio", 1.1),
        ("tcp_syn_retry_min_intervals", 2),
        ("tcp_syn_retry_min_interval_ms", 0),
        ("tcp_syn_retry_max_interval_ms", 300_001),
        ("tcp_syn_retry_tolerance_ratio", 0.51),
        ("tcp_syn_retry_max_interval_multiple", 33),
    ],
)
def test_tcp_session_gating_rejects_unsafe_parameters(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        AnalysisParameters(**{field: value})


def test_syn_retry_interval_bounds_must_be_ordered() -> None:
    with pytest.raises(ValidationError, match="maximum interval"):
        AnalysisParameters(
            tcp_syn_retry_min_interval_ms=5000,
            tcp_syn_retry_max_interval_ms=2000,
        )


def test_flow_record_rejects_tcp_counters_without_observation_marker() -> None:
    with pytest.raises(ValidationError):
        FlowRecord.model_validate(tcp_record(tcp_flags_observed=False))


def test_flow_record_rejects_impossible_combination_totals() -> None:
    with pytest.raises(ValidationError):
        FlowRecord.model_validate(tcp_record(tcp_syn_count=0))


def test_packet_limit_clears_uncertain_tcp_session_metadata() -> None:
    limited, summary = limit_flow_records(
        [
            tcp_record(
                packet_count=10,
                total_bytes=1000,
                tcp_ack_count=8,
                tcp_ack_only_count=8,
                tcp_syn_only_observations=[
                    {"offset_us": 0, "sequence": 1},
                    {"offset_us": 2_000_000, "sequence": 1},
                ],
            )
        ],
        3,
    )
    assert limited[0]["packet_count"] == 3
    assert limited[0]["tcp_flags_observed"] is True
    assert limited[0]["tcp_ack_count"] == 0
    assert limited[0]["tcp_ack_only_count"] == 0
    assert limited[0]["bidirectional"] is False
    assert limited[0]["tcp_syn_only_observations"] == []
    assert limited[0]["tcp_syn_only_observations_truncated"] is True
    assert summary["retained_packets"] == 3


@pytest.mark.parametrize(
    "observations",
    [
        [{"offset_us": -1, "sequence": 1}],
        [{"offset_us": 0, "sequence": 2**32}],
        [{"offset_us": index, "sequence": 1} for index in range(17)],
        [{"offset_us": 2, "sequence": 1}, {"offset_us": 1, "sequence": 1}],
    ],
)
def test_flow_record_rejects_invalid_syn_observations(
    observations: list[dict[str, int]],
) -> None:
    with pytest.raises(ValidationError):
        FlowRecord.model_validate(
            tcp_record(
                tcp_syn_count=len(observations),
                tcp_syn_only_count=len(observations),
                tcp_syn_only_observations=observations,
            )
        )


def test_flow_record_rejects_complete_syn_observation_count_mismatch() -> None:
    with pytest.raises(ValidationError, match="must match SYN-only count"):
        FlowRecord.model_validate(
            tcp_record(
                tcp_syn_count=2,
                tcp_syn_only_count=2,
                tcp_syn_only_observations=[{"offset_us": 0, "sequence": 1}],
            )
        )


def test_packet_limit_does_not_mutate_original_nested_tcp_flags() -> None:
    original = tcp_record(packet_count=10, tcp_flags={"syn": 1, "ack": 1})

    limited, _summary = limit_flow_records([original], 3)

    assert original["tcp_flags"] == {"syn": 1, "ack": 1}
    assert limited[0]["tcp_flags"] == {}
