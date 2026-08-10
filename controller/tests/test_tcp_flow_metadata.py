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
    parsed = FlowRecord.model_validate(tcp_record())
    assert parsed.tcp_syn_only_count == 1
    assert parsed.tcp_ack_only_count == 1
    assert parsed.bidirectional is True


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
    ],
)
def test_tcp_session_gating_rejects_unsafe_parameters(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        AnalysisParameters(**{field: value})


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
            )
        ],
        3,
    )
    assert limited[0]["packet_count"] == 3
    assert limited[0]["tcp_flags_observed"] is True
    assert limited[0]["tcp_ack_count"] == 0
    assert limited[0]["tcp_ack_only_count"] == 0
    assert limited[0]["bidirectional"] is False
    assert summary["retained_packets"] == 3


def test_packet_limit_does_not_mutate_original_nested_tcp_flags() -> None:
    original = tcp_record(packet_count=10, tcp_flags={"syn": 1, "ack": 1})

    limited, _summary = limit_flow_records([original], 3)

    assert original["tcp_flags"] == {"syn": 1, "ack": 1}
    assert limited[0]["tcp_flags"] == {}
