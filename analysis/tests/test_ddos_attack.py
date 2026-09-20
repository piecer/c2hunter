from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta

import pytest

from c2hunter_analysis.ddos_attack import analyze_ddos_attack

START = datetime(2026, 9, 15, tzinfo=UTC)
PARAMETERS = {
    "ddos_min_duration_seconds": 2,
    "ddos_min_source_count": 3,
    "ddos_min_packet_count": 6,
    "ddos_min_packets_per_second": 2,
    "ddos_min_bits_per_second": 1_000_000,
    "ddos_baseline_min_buckets": 5,
}


def record(
    second: float,
    source: str,
    target: str = "10.0.0.10",
    *,
    protocol: str = "TCP",
    direction: str = "INBOUND",
    source_port: int = 40000,
    destination_port: int = 443,
    flags: dict[str, int] | None = None,
    size: int = 100,
    icmp_type: int | None = None,
    packet_count: int = 1,
    duration: float = 0,
    complete: bool = True,
) -> dict[str, object]:
    return {
        "sensor_id": "sensor-a",
        "timestamp": START + timedelta(seconds=second),
        "source_ip": source,
        "destination_ip": target,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "direction": direction,
        "packet_count": packet_count,
        "total_bytes": size,
        "duration_seconds": duration,
        "tcp_flags": flags,
        "tcp_flags_observed": flags is not None,
        "tcp_syn_count": int(bool(flags and flags.get("syn"))) * packet_count,
        "tcp_ack_count": int(bool(flags and flags.get("ack"))) * packet_count,
        "tcp_rst_count": int(bool(flags and flags.get("rst"))) * packet_count,
        "tcp_syn_only_count": int(bool(flags and flags.get("syn") and not flags.get("ack")))
        * packet_count,
        "tcp_syn_ack_count": int(bool(flags and flags.get("syn") and flags.get("ack")))
        * packet_count,
        "tcp_ack_only_count": int(
            bool(flags and flags.get("ack") and not flags.get("syn") and not flags.get("rst"))
        )
        * packet_count,
        "transport_payload_length": 0,
        "icmp_type": icmp_type,
        "packet_evidence_complete": complete,
    }


def distributed_tcp(flags: dict[str, int], target: str = "10.0.0.10") -> list[dict[str, object]]:
    return [
        record(second, f"198.51.100.{source}", target, flags=flags)
        for second in range(25)
        for source in range(1, 5)
    ]


def finding(report: dict[str, object], attack_type: str) -> dict[str, object]:
    return next(item for item in report["findings"] if item["attack_type"] == attack_type)  # type: ignore[index,union-attr]


def test_inbound_syn_flood_reports_type_resource_goal_and_human_approved_response() -> None:
    report = analyze_ddos_attack(
        distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0}),
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )

    item = finding(report, "TCP_SYN_FLOOD")
    assert report["version"] == "ddos-attack-report-v2"
    assert report["verdict"] == "suspicious_traffic"
    assert item["attack_role"] == "VICTIM_SIDE_INBOUND"
    assert item["target"] == {"ip": "10.0.0.10", "port": 443}
    assert item["objective"] == "CONNECTION_STATE_EXHAUSTION"
    assert item["likelihood"] == "POSSIBLE"
    assert item["metrics"]["distinct_sources"] == 4
    assert item["metrics"]["syn_only_ratio"] == 1.0
    assert "TCP_RESPONSE_VISIBILITY_UNKNOWN" in item["uncertainty_codes"]
    assert "ENABLE_SYN_PROXY_OR_COOKIES" in item["recommendation_codes"]
    assert all(action["requires_human_approval"] for action in report["recommendations"])
    assert "BASELINE_UNAVAILABLE" not in report["warnings"]


def test_outbound_udp_flood_is_participant_traffic_not_a_c2_candidate() -> None:
    records = [
        record(
            second,
            f"10.0.0.{source}",
            "203.0.113.80",
            protocol="UDP",
            direction="OUTBOUND",
            source_port=50000 + source,
            destination_port=53,
            flags=None,
            size=400,
        )
        for second in range(25)
        for source in range(1, 5)
    ]

    report = analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    item = finding(report, "UDP_FLOOD")

    assert item["attack_role"] == "PARTICIPANT_SIDE_OUTBOUND"
    assert item["target"]["ip"] == "203.0.113.80"
    assert item["objective"] == "BANDWIDTH_EXHAUSTION"
    assert "ISOLATE_INTERNAL_SOURCES" in item["recommendation_codes"]
    assert "APPLY_EGRESS_RATE_LIMIT" in item["recommendation_codes"]


def test_reflection_shape_is_possible_and_never_claims_a_measured_amplification_ratio() -> None:
    records = [
        record(
            second,
            f"198.51.100.{source}",
            protocol="UDP",
            source_port=53,
            destination_port=53000,
            flags=None,
            size=600,
        )
        for second in range(25)
        for source in range(1, 5)
    ]
    report = analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    item = finding(report, "POSSIBLE_REFLECTION_AMPLIFICATION")

    assert item["likelihood"] == "POSSIBLE"
    assert item["objective"] == "REFLECTED_BANDWIDTH_EXHAUSTION"
    assert item["metrics"]["dominant_reflection_source_port"] == 53
    assert item["metrics"]["amplification_ratio"] is None
    assert "AMPLIFICATION_RATIO_UNOBSERVED" in item["uncertainty_codes"]


def test_phase1_classifies_reflection_and_emits_bounded_signatures() -> None:
    records = [
        {
            **record(
                second,
                f"198.51.100.{source}",
                protocol="UDP",
                source_port=53,
                destination_port=53000,
                flags=None,
                size=600,
            ),
            "packet_count": 3,
            "total_bytes": 1800,
            "packet_sizes": [590, 600, 610],
            "payload_prefix_hash": "a" * 64,
        }
        for second in range(25)
        for source in range(1, 5)
    ]

    item = finding(
        analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS),
        "POSSIBLE_REFLECTION_AMPLIFICATION",
    )

    assert item["classification"] == {
        "delivery_mechanism": "REFLECTION_AMPLIFICATION",
        "source_population": "REFLECTOR_SET",
        "source_authenticity": "SPOOFING_UNCONFIRMED",
        "confidence": "medium",
    }
    assert {pattern["type"] for pattern in item["common_patterns"]} >= {
        "REFLECTION_SERVICE_CONVERGENCE",
        "PACKET_SIZE_CLUSTER",
        "PAYLOAD_PREFIX_CLUSTER",
    }
    patterns = {pattern["type"]: pattern for pattern in item["common_patterns"]}
    assert patterns["REFLECTION_SERVICE_CONVERGENCE"]["support_count"] == len(records)
    assert patterns["PACKET_SIZE_CLUSTER"]["support_count"] == len(records)
    assert any(
        signature["kind"] == "REFLECTION_PROFILE"
        and signature["requires_human_approval"] is True
        and signature["source_ports"] == [53]
        for signature in item["signature_candidates"]
    )
    assert len(item["common_patterns"]) <= 8
    assert len(item["signature_candidates"]) <= 4


def test_phase1_marks_outbound_distributed_sources_as_botnet_like_without_attribution() -> None:
    records = [
        {
            **record(
                second,
                f"10.0.0.{source}",
                "203.0.113.80",
                protocol="UDP",
                direction="OUTBOUND",
                source_port=50000 + source,
                destination_port=443,
                flags=None,
                size=400,
            ),
            "payload_prefix_hash": "b" * 64,
        }
        for second in range(25)
        for source in range(1, 5)
    ]

    item = finding(
        analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS),
        "UDP_FLOOD",
    )

    assert item["classification"]["delivery_mechanism"] == "DIRECT_DISTRIBUTED"
    assert item["classification"]["source_population"] == "BOTNET_LIKE_COORDINATION"
    assert item["classification"]["source_authenticity"] == "SOURCE_CONSISTENT"
    assert "BOTNET_ATTRIBUTION_UNCONFIRMED" in item["uncertainty_codes"]


def test_phase2_network_identity_statistics_raise_spoofing_suspicion_without_claiming_proof() -> (
    None
):
    records = [
        {
            **row,
            "hop_limit_min": 32,
            "hop_limit_max": 128,
            "hop_limit_mode": 64,
            "hop_limit_distinct_count": 5,
            "ip_id_observed_count": 8,
            "ip_id_distinct_count": 8,
            "ip_id_monotonic_transitions": 0,
            "ip_id_transition_count": 7,
        }
        for row in distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    ]

    item = finding(
        analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS),
        "TCP_SYN_FLOOD",
    )

    assert item["classification"]["source_authenticity"] == "SPOOFING_SUSPECTED"
    assert item["metrics"]["network_identity_anomaly_records"] == len(records)
    assert "SOURCE_SPOOFING_NOT_CONFIRMED" in item["uncertainty_codes"]
    assert {pattern["type"] for pattern in item["common_patterns"]} >= {
        "HOP_LIMIT_DIVERSITY",
        "IP_ID_INCONSISTENCY",
    }
    assert any(
        signature["kind"] == "SPOOFING_HEURISTIC" for signature in item["signature_candidates"]
    )


def test_packet_icmp_echo_and_aggregate_icmp_keep_distinct_precision(monkeypatch) -> None:
    echo = [
        record(second, f"198.51.100.{source}", protocol="ICMP", flags=None, icmp_type=8)
        for second in range(25)
        for source in range(1, 5)
    ]
    echo_report = analyze_ddos_attack(echo, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert finding(echo_report, "ICMP_ECHO_FLOOD")["metrics"]["measurement_precision"] == "PACKET"

    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    aggregate = [
        record(
            source,
            f"198.51.100.{source}",
            protocol="ICMP",
            flags=None,
            packet_count=10,
            duration=2,
            complete=False,
            size=1000,
        )
        for source in range(1, 5)
    ]
    aggregate_report = analyze_ddos_attack(
        aggregate, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    item = finding(aggregate_report, "ICMP_FLOOD")
    assert item["metrics"]["measurement_precision"] == "AGGREGATED_FLOW"
    assert item["metrics"]["peak_packets_per_second"] is None
    assert item["metrics"]["average_packets_per_second"] == 8.0
    assert "ICMP_TYPE_UNAVAILABLE" in item["uncertainty_codes"]


def test_icmp_echo_type_is_protocol_specific(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    wrong_v4 = analyze_ddos_attack(
        [
            record(
                second,
                f"198.51.100.{second + 1}",
                protocol="ICMP",
                icmp_type=128,
                packet_count=3,
                duration=1,
                complete=False,
            )
            for second in range(3)
        ],
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    wrong_v6 = analyze_ddos_attack(
        [
            record(
                second,
                f"2001:db8::{second + 1}",
                protocol="ICMPV6",
                icmp_type=8,
                packet_count=3,
                duration=1,
                complete=False,
            )
            for second in range(3)
        ],
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    assert finding(wrong_v4, "ICMP_FLOOD")
    assert finding(wrong_v6, "ICMP_FLOOD")

    partial = [
        record(0, "198.51.100.1", protocol="ICMP", flags=None, icmp_type=8),
        record(
            2,
            "198.51.100.2",
            protocol="ICMP",
            flags=None,
            packet_count=2_000,
            icmp_type=None,
        ),
    ]
    partial_report = analyze_ddos_attack(
        partial,
        internal_cidrs=("10.0.0.0/8",),
        parameters={**PARAMETERS, "ddos_min_source_count": 2},
    )
    assert finding(partial_report, "ICMP_FLOOD")
    assert not any(item["attack_type"] == "ICMP_ECHO_FLOOD" for item in partial_report["findings"])


def test_ack_and_reset_flood_shapes_keep_legitimate_response_uncertainty() -> None:
    cases = (
        ({"ack": 1, "syn": 0, "rst": 0}, "TCP_ACK_FLOOD", "ACK_TRAFFIC_MAY_BE_LEGITIMATE"),
        ({"rst": 1, "syn": 0, "ack": 0}, "TCP_RST_FLOOD", "RESETS_MAY_BE_DEFENSIVE_RESPONSES"),
    )
    for flags, attack_type, warning in cases:
        report = analyze_ddos_attack(
            distributed_tcp(flags),
            internal_cidrs=("10.0.0.0/8",),
            parameters=PARAMETERS,
        )
        item = finding(report, attack_type)
        assert item["objective"] == "PACKET_PROCESSING_EXHAUSTION"
        assert warning in item["uncertainty_codes"]

    reset_ack = analyze_ddos_attack(
        distributed_tcp({"ack": 1, "rst": 1}),
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    assert not any(item["attack_type"] == "TCP_ACK_FLOOD" for item in reset_ack["findings"])

    legacy_sensor_rows = distributed_tcp({"ack": 1})
    for row in legacy_sensor_rows:
        row.pop("transport_payload_length")
    legacy_report = analyze_ddos_attack(
        legacy_sensor_rows,
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    legacy_item = finding(legacy_report, "TCP_ACK_FLOOD")
    assert legacy_item["likelihood"] == "POSSIBLE"
    assert "TCP_PAYLOAD_VISIBILITY_UNKNOWN" in legacy_item["uncertainty_codes"]

    authoritative_rows = [
        {**row, "transport_payload_packet_count": 0} for row in legacy_sensor_rows
    ]
    authoritative_report = analyze_ddos_attack(
        authoritative_rows,
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    authoritative_item = finding(authoritative_report, "TCP_ACK_FLOOD")
    assert "TCP_PAYLOAD_VISIBILITY_UNKNOWN" not in authoritative_item["uncertainty_codes"]


def test_single_source_and_ambiguous_direction_cannot_be_called_ddos() -> None:
    single = [record(second, "198.51.100.1", flags={"syn": 1}) for second in range(10)]
    report = analyze_ddos_attack(single, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert report["findings"] == []
    assert report["verdict"] == "insufficient_evidence"
    assert "DOS_LIKE_TRAFFIC" in report["warnings"]

    ambiguous = [
        record(second, f"192.0.2.{source}", "198.51.100.10", direction="UNKNOWN", flags={"syn": 1})
        for second in range(3)
        for source in range(1, 5)
    ]
    report = analyze_ddos_attack(ambiguous, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert report["findings"] == []
    assert report["summary"]["skipped_records"] == len(ambiguous)
    assert "AMBIGUOUS_DIRECTION" in report["warnings"]


def test_multi_vector_retains_base_findings_and_deterministic_bytes() -> None:
    tcp = distributed_tcp({"syn": 1})
    udp = [
        record(second + 0.1, f"203.0.113.{source}", protocol="UDP", flags=None, size=100)
        for second in range(25)
        for source in range(1, 5)
    ]
    records = tcp + udp
    first = analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    shuffled = list(records)
    random.Random(17).shuffle(shuffled)
    second = analyze_ddos_attack(shuffled, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)

    assert {item["attack_type"] for item in first["findings"]} >= {
        "MULTI_VECTOR",
        "TCP_SYN_FLOOD",
        "UDP_FLOOD",
    }

    def canonical(value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    assert canonical(first) == canonical(second)


def test_complete_low_volume_capture_reports_no_clear_attack_without_claiming_health() -> None:
    records = [
        record(second, f"198.51.100.{source}", protocol="UDP", flags=None)
        for second, source in enumerate(range(1, 12))
    ]
    report = analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert report["findings"] == []
    assert report["verdict"] == "insufficient_evidence"
    assert report["summary"]["coverage_complete"] is True
    assert "SAMPLE_WINDOW_SHORT" in report["warnings"]
    assert "NO_FINDING_DOES_NOT_PROVE_HEALTH" in report["limitations"]


def test_qualified_low_baseline_can_raise_a_udp_flood_to_likely() -> None:
    quiet = [
        record(second, f"198.51.100.{second + 1}", protocol="UDP", flags=None)
        for second in range(20)
    ]
    burst = [
        record(second, f"203.0.113.{source}", protocol="UDP", flags=None)
        for second in range(20, 45)
        for source in range(1, 5)
    ]
    report = analyze_ddos_attack(
        quiet + burst,
        internal_cidrs=("10.0.0.0/8",),
        parameters={**PARAMETERS, "ddos_baseline_ratio": 3.0},
    )
    assert report["verdict"] == "attack_likely"
    assert finding(report, "UDP_FLOOD")["likelihood"] == "LIKELY"

    with_sparse_decoy = analyze_ddos_attack(
        quiet
        + burst
        + [
            record(
                50,
                "192.0.2.1",
                target="10.0.0.99",
                protocol="UDP",
                flags=None,
            )
        ],
        internal_cidrs=("10.0.0.0/8",),
        parameters={**PARAMETERS, "ddos_baseline_ratio": 3.0},
    )
    assert with_sparse_decoy["verdict"] == "attack_likely"
    assert finding(with_sparse_decoy, "UDP_FLOOD")["likelihood"] == "LIKELY"

    coverage_limited = analyze_ddos_attack(
        quiet + burst,
        internal_cidrs=("10.0.0.0/8",),
        parameters={**PARAMETERS, "ddos_baseline_ratio": 3.0},
        coverage_context={"parser_skipped_packet_count": 1},
    )
    limited_finding = finding(coverage_limited, "UDP_FLOOD")
    assert limited_finding["likelihood"] == "POSSIBLE"
    assert limited_finding["severity"] == "MEDIUM"
    assert limited_finding["confidence"] == "low"


def test_input_limit_plus_one_stops_analysis_and_forbids_a_clear_result(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MAX_SCANNED_RECORDS", 2)
    records = [
        record(second, f"198.51.100.{second + 1}", protocol="UDP", flags=None)
        for second in range(3)
    ]
    report = analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert report["summary"]["scanned_records"] == 3
    assert report["summary"]["evaluated_records"] == 0
    assert report["summary"]["counts_are_lower_bounds"] is True
    assert report["verdict"] == "insufficient_evidence"
    assert "INPUT_RECORD_LIMIT_REACHED" in report["warnings"]


def test_sequence_input_limit_plus_one_is_order_independent(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MAX_SCANNED_RECORDS", 4)
    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    rows = [
        record(
            0,
            source,
            target=target,
            protocol=protocol,
            flags=flags,
            packet_count=10,
            duration=2,
            complete=False,
        )
        for source, target, protocol, flags in (
            ("198.51.100.1", "10.0.0.1", "UDP", None),
            ("198.51.100.2", "10.0.0.1", "UDP", None),
            ("198.51.100.3", "10.0.0.2", "TCP", {"syn": 1}),
            ("198.51.100.4", "10.0.0.2", "TCP", {"syn": 1}),
            ("198.51.100.5", "10.0.0.3", "ICMP", None),
        )
    ]
    parameters = {
        **PARAMETERS,
        "ddos_min_source_count": 2,
        "ddos_min_packet_count": 1,
        "ddos_min_duration_seconds": 1,
        "ddos_min_packets_per_second": 1,
    }
    forward = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=parameters)
    reverse = analyze_ddos_attack(
        list(reversed(rows)), internal_cidrs=("10.0.0.0/8",), parameters=parameters
    )
    assert json.dumps(forward, sort_keys=True) == json.dumps(reverse, sort_keys=True)


def test_input_limit_plus_one_is_identical_for_lists_and_generators(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MAX_SCANNED_RECORDS", 2)
    rows = [
        record(second, f"198.51.100.{second + 1}", protocol="UDP", flags=None)
        for second in range(3)
    ]
    reports = [
        analyze_ddos_attack(source, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
        for source in (rows, iter(rows), iter(reversed(rows)))
    ]
    expected = json.dumps(reports[0], sort_keys=True)
    assert all(json.dumps(item, sort_keys=True) == expected for item in reports)


def test_ten_second_packet_bucket_is_normalized_to_per_second_rate(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    rows = [record(second, f"198.51.100.{second + 1}", flags={"syn": 1}) for second in range(10)]
    report = analyze_ddos_attack(
        rows,
        internal_cidrs=("10.0.0.0/8",),
        parameters={
            **PARAMETERS,
            "ddos_bucket_seconds": 10,
            "ddos_min_packet_count": 10,
            "ddos_min_packets_per_second": 1,
        },
    )
    assert finding(report, "TCP_SYN_FLOOD")["metrics"]["peak_packets_per_second"] == 1.0


def test_simultaneous_aggregate_flows_sum_rates_and_use_flow_interval(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    rows = [
        record(
            0,
            f"198.51.100.{source}",
            protocol="ICMP",
            flags=None,
            packet_count=10,
            duration=1,
            size=1000,
            complete=False,
        )
        for source in range(1, 4)
    ]
    report = analyze_ddos_attack(
        rows,
        internal_cidrs=("10.0.0.0/8",),
        parameters={
            **PARAMETERS,
            "ddos_min_duration_seconds": 1,
            "ddos_min_packet_count": 30,
            "ddos_min_packets_per_second": 25,
        },
    )
    metrics = finding(report, "ICMP_FLOOD")["metrics"]
    assert metrics["duration_seconds"] == 1.0
    assert metrics["average_packets_per_second"] == 30.0
    assert metrics["peak_packets_per_second"] is None
    assert report["summary"]["last_seen"] == (START + timedelta(seconds=1)).isoformat()
    assert finding(report, "ICMP_FLOOD")["last_seen"] == (START + timedelta(seconds=1)).isoformat()


def test_reflection_source_port_share_is_weighted_by_packet_count(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    rows = [
        record(0, f"198.51.100.{source}", protocol="UDP", flags=None, source_port=53, size=600)
        for source in range(1, 4)
    ] + [
        record(
            1,
            "198.51.100.4",
            protocol="UDP",
            flags=None,
            source_port=40000,
            packet_count=1000,
            duration=2,
            size=600_000,
            complete=False,
        )
    ]
    report = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    item = finding(report, "UDP_FLOOD")
    assert item["metrics"]["reflection_source_port_ratio"] == pytest.approx(3 / 1003)
    assert all(
        entry["attack_type"] != "POSSIBLE_REFLECTION_AMPLIFICATION" for entry in report["findings"]
    )


def test_equal_reflection_port_counts_use_the_lowest_port_tiebreak(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    rows = [
        record(
            second,
            f"198.51.100.{second + 1}",
            protocol="UDP",
            flags=None,
            source_port=53 if second % 2 == 0 else 123,
            packet_count=2,
            duration=1,
            size=1200,
            complete=False,
        )
        for second in range(10)
    ]
    forward = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    reverse = analyze_ddos_attack(
        list(reversed(rows)), internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    item = finding(forward, "POSSIBLE_REFLECTION_AMPLIFICATION")
    assert item["metrics"]["dominant_reflection_source_port"] == 53
    assert json.dumps(forward, sort_keys=True) == json.dumps(reverse, sort_keys=True)


def test_invalid_ddos_parameter_fails_closed_before_record_processing() -> None:
    with pytest.raises(ValueError, match="ddos_bucket_seconds must be between 1 and 60"):
        analyze_ddos_attack([], parameters={"ddos_bucket_seconds": 0})
    assert (
        analyze_ddos_attack([], parameters={"ddos_reflection_min_average_packet_bytes": 1})[
            "version"
        ]
        == "ddos-attack-report-v2"
    )


def test_internal_networks_are_precompiled_and_hard_bounded() -> None:
    networks = [f"10.{index // 256}.{index % 256}.0/24" for index in range(257)]
    with pytest.raises(ValueError, match="too many internal networks"):
        analyze_ddos_attack([], internal_cidrs=networks)


def test_integer_policy_accepts_its_documented_maximum_without_float_loss() -> None:
    report = analyze_ddos_attack([], parameters={"ddos_min_packet_count": 2**63 - 1})
    assert report["version"] == "ddos-attack-report-v2"


def test_timestamp_interval_overflow_is_skipped_instead_of_crashing() -> None:
    invalid = record(0, "198.51.100.1", protocol="UDP", flags=None, duration=1)
    invalid["timestamp"] = datetime.max.replace(tzinfo=UTC)
    report = analyze_ddos_attack([invalid], internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert report["summary"]["skipped_records"] == 1

    invalid["timestamp"] = "0001-01-01T00:00:00+14:00"
    report = analyze_ddos_attack([invalid], internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert report["summary"]["skipped_records"] == 1
    assert "INCOMPLETE_RECORDS" in report["warnings"]


def test_aggregate_counter_overflow_is_skipped_before_report_publication() -> None:
    rows = [
        record(
            second,
            f"198.51.100.{second + 1}",
            protocol="UDP",
            flags=None,
            packet_count=2**53 - 1,
            size=2**53 - 1,
            complete=False,
        )
        for second in range(2)
    ]
    report = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    reverse = analyze_ddos_attack(
        list(reversed(rows)), internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    assert report["summary"]["evaluated_records"] == 0
    assert report["summary"]["packet_count"] == 0
    assert report["verdict"] == "insufficient_evidence"
    assert json.dumps(report, sort_keys=True) == json.dumps(reverse, sort_keys=True)


def test_malformed_timestamp_and_oversized_sensor_id_are_skipped() -> None:
    bad_timestamp = record(0, "198.51.100.1", protocol="UDP", flags=None)
    bad_timestamp["timestamp"] = "not-a-timestamp"
    bad_sensor = record(1, "198.51.100.2", protocol="UDP", flags=None)
    bad_sensor["sensor_id"] = "s" * 129
    report = analyze_ddos_attack(
        [bad_timestamp, bad_sensor],
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    assert report["summary"]["skipped_records"] == 2
    assert "INCOMPLETE_RECORDS" in report["warnings"]


def test_optional_null_payload_is_unknown_but_impossible_counter_is_skipped() -> None:
    valid = record(0, "198.51.100.1", protocol="UDP", flags=None)
    valid["transport_payload_length"] = None
    impossible = record(1, "198.51.100.2", flags={"syn": 1})
    impossible["tcp_syn_only_count"] = 2
    report = analyze_ddos_attack(
        [valid, impossible], internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    assert report["summary"]["evaluated_records"] == 1
    assert report["summary"]["skipped_records"] == 1
    assert report["summary"]["first_seen"] == START.isoformat()


def test_mutually_exclusive_tcp_shape_counters_are_rejected() -> None:
    impossible = record(
        0,
        "198.51.100.1",
        flags=None,
        packet_count=10,
        duration=1,
        complete=False,
    )
    impossible.update(
        tcp_flags_observed=True,
        tcp_ack_count=10,
        tcp_ack_only_count=10,
        tcp_rst_count=10,
    )
    report = analyze_ddos_attack(
        [impossible], internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    assert report["summary"]["evaluated_records"] == 0
    assert report["summary"]["skipped_records"] == 1
    assert report["findings"] == []

    impossible.update(
        tcp_syn_count=10,
        tcp_ack_count=10,
        tcp_syn_only_count=8,
        tcp_syn_ack_count=2,
        tcp_ack_only_count=8,
        tcp_rst_count=0,
    )
    report = analyze_ddos_attack(
        [impossible], internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    assert report["summary"]["evaluated_records"] == 0
    assert report["summary"]["skipped_records"] == 1
    assert report["findings"] == []


def test_target_overflow_report_is_input_order_independent_and_fail_closed(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MAX_TARGETS", 2)
    rows = [
        record(index, f"198.51.100.{index + 1}", target=f"10.0.0.{index + 1}", flags={"syn": 1})
        for index in range(3)
    ]
    forward = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    reverse = analyze_ddos_attack(
        list(reversed(rows)), internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    assert json.dumps(forward, sort_keys=True) == json.dumps(reverse, sort_keys=True)
    assert forward["findings"] == []
    assert forward["summary"]["evaluated_records"] == 3
    assert forward["summary"]["packet_count"] == 3


def test_dual_stack_target_limit_rank_is_input_order_independent(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MAX_TARGETS", 1)
    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    rows = [
        record(0, f"198.51.100.{source}", target="0.0.0.1", protocol="UDP", flags=None)
        for source in (1, 2)
    ] + [
        record(0, f"2001:db8::{source}", target="::1", protocol="UDP", flags=None)
        for source in (1, 2)
    ]
    parameters = {
        **PARAMETERS,
        "ddos_min_source_count": 2,
        "ddos_min_packet_count": 2,
        "ddos_min_duration_seconds": 1,
        "ddos_min_packets_per_second": 1,
        "ddos_min_bits_per_second": 1,
    }
    forward = analyze_ddos_attack(rows, internal_cidrs=("0.0.0.0/8", "::/8"), parameters=parameters)
    reverse = analyze_ddos_attack(
        list(reversed(rows)), internal_cidrs=("0.0.0.0/8", "::/8"), parameters=parameters
    )
    assert json.dumps(forward, sort_keys=True) == json.dumps(reverse, sort_keys=True)


def test_target_overflow_preserves_complete_deterministic_retained_finding(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MAX_TARGETS", 2)
    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    retained = distributed_tcp({"syn": 1}, target="10.0.0.1")
    decoys = [
        record(0, "198.51.100.200", target="10.0.0.2", flags={"syn": 1}),
        record(0, "198.51.100.201", target="10.0.0.3", flags={"syn": 1}),
    ]
    report = analyze_ddos_attack(
        decoys + retained,
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    assert finding(report, "TCP_SYN_FLOOD")["target"]["ip"] == "10.0.0.1"
    assert "TARGET_LIMIT_REACHED" in report["warnings"]


def test_target_limit_ranking_work_is_not_records_times_target_limit(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MAX_TARGETS", 8)
    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    original_rank = ddos_attack._target_rank
    rank_calls = 0

    def counted_rank(key):
        nonlocal rank_calls
        rank_calls += 1
        return original_rank(key)

    monkeypatch.setattr(ddos_attack, "_target_rank", counted_rank)
    rows = [
        record(
            0,
            f"198.51.{index // 256}.{index % 256}",
            target=f"10.{index // 65536}.{index // 256 % 256}.{index % 256}",
            protocol="UDP",
            flags=None,
        )
        for index in range(1, 1001)
    ]
    report = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert report["summary"]["target_count"] == 8
    assert rank_calls < len(rows) * 3


def test_syn_without_reverse_visibility_is_never_promoted_to_likely() -> None:
    quiet = [record(second, f"198.51.100.{second + 1}", flags={"syn": 1}) for second in range(20)]
    burst = [
        record(second, f"203.0.113.{source}", flags={"syn": 1})
        for second in range(20, 45)
        for source in range(1, 5)
    ]
    report = analyze_ddos_attack(
        quiet + burst,
        internal_cidrs=("10.0.0.0/8",),
        parameters={**PARAMETERS, "ddos_baseline_ratio": 3.0},
    )
    item = finding(report, "TCP_SYN_FLOOD")
    assert item["likelihood"] == "POSSIBLE"
    assert "TCP_RESPONSE_VISIBILITY_UNKNOWN" in item["uncertainty_codes"]


def test_reverse_syn_ack_is_correlated_to_inbound_protected_target() -> None:
    inbound = distributed_tcp({"syn": 1})
    outbound = [
        record(
            second,
            "10.0.0.10",
            target=f"198.51.100.{source}",
            source_port=443,
            destination_port=40000 + source,
            direction="OUTBOUND",
            flags={"syn": 1, "ack": 1},
        )
        for second in range(25)
        for source in range(1, 5)
    ]
    report = analyze_ddos_attack(
        outbound + inbound,
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    item = finding(report, "TCP_SYN_FLOOD")
    assert item["metrics"]["response_ratio"] == 0.5
    assert "TCP_RESPONSE_VISIBILITY_UNKNOWN" not in item["uncertainty_codes"]


def test_multi_sensor_aggregation_warns_that_duplicate_capture_was_not_excluded() -> None:
    rows = distributed_tcp({"syn": 1})
    for row in rows[::2]:
        row["sensor_id"] = "sensor-b"
    report = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert "DUPLICATE_CAPTURE_NOT_EXCLUDED" in report["warnings"]
    assert finding(report, "TCP_SYN_FLOOD")["metrics"]["distinct_sensors"] == 2


def test_bucket_limit_plus_one_is_deterministic_and_preserves_partial_finding(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 1)
    monkeypatch.setattr(ddos_attack, "MAX_BUCKETS_PER_TARGET", 2)
    rows = [
        record(second, f"198.51.100.{source}", flags={"syn": 1})
        for second, count in enumerate((2, 4, 8))
        for source in range(1, count + 1)
    ]
    forward = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    reverse = analyze_ddos_attack(
        list(reversed(rows)), internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    assert finding(forward, "TCP_SYN_FLOOD")
    assert finding(forward, "TCP_SYN_FLOOD")["metrics"]["peak_packets_per_second"] == 4
    assert finding(forward, "TCP_SYN_FLOOD")["metrics"]["peak_is_lower_bound"] is True
    assert "BUCKET_LIMIT_REACHED" in forward["warnings"]
    assert json.dumps(forward, sort_keys=True) == json.dumps(reverse, sort_keys=True)


def test_short_positive_sample_is_preserved_with_limited_confidence(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MIN_TARGET_RECORDS", 100)
    report = analyze_ddos_attack(
        distributed_tcp({"syn": 1})[:99],
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    item = finding(report, "TCP_SYN_FLOOD")
    assert item["likelihood"] == "POSSIBLE"
    assert item["confidence"] == "low"
    assert "SAMPLE_WINDOW_SHORT" in report["warnings"]


def test_ack_dominant_payload_traffic_is_not_classified_as_ack_flood() -> None:
    rows = distributed_tcp({"ack": 1})
    for row in rows:
        row["transport_payload_length"] = 128
    report = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert all(item["attack_type"] != "TCP_ACK_FLOOD" for item in report["findings"])


def test_multi_vector_uses_only_overlapping_cross_type_subset() -> None:
    tcp = distributed_tcp({"syn": 1})
    udp = [
        record(second, f"203.0.113.{source}", protocol="UDP", flags=None)
        for second in range(25)
        for source in range(1, 5)
    ]
    distant_icmp = [
        record(100 + second, f"192.0.2.{source}", protocol="ICMP", flags=None)
        for second in range(25)
        for source in range(1, 5)
    ]
    report = analyze_ddos_attack(
        tcp + udp + distant_icmp,
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
    )
    item = finding(report, "MULTI_VECTOR")
    assert item["metrics"]["component_types"] == ["TCP_SYN_FLOOD", "UDP_FLOOD"]
    assert item["metrics"]["component_finding_count"] == 2


def test_finding_limit_plus_one_retains_deterministic_prefix(monkeypatch) -> None:
    from c2hunter_analysis import ddos_attack

    monkeypatch.setattr(ddos_attack, "MAX_FINDINGS", 1)
    rows = distributed_tcp({"syn": 1}, "10.0.0.20") + distributed_tcp({"syn": 1}, "10.0.0.10")
    forward = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    reverse = analyze_ddos_attack(
        list(reversed(rows)), internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS
    )
    assert forward["summary"]["finding_count"] == 2
    assert forward["summary"]["displayed_finding_count"] == 1
    assert forward["omitted_finding_count"] == 1
    assert forward["findings"][0]["target"]["ip"] == "10.0.0.10"
    assert json.dumps(forward, sort_keys=True) == json.dumps(reverse, sort_keys=True)


def test_external_capture_coverage_qualifiers_forbid_no_clear_verdict() -> None:
    rows = [
        record(second, f"198.51.100.{second % 100 + 1}", protocol="UDP", flags=None)
        for second in range(100)
    ]
    parser_limited = analyze_ddos_attack(
        rows,
        internal_cidrs=("10.0.0.0/8",),
        parameters={**PARAMETERS, "ddos_min_packet_count": 10_000},
        coverage_context={"parser_skipped_packet_count": 3},
    )
    assert parser_limited["verdict"] == "insufficient_evidence"
    assert parser_limited["summary"]["coverage_complete"] is False
    assert parser_limited["summary"]["counts_are_lower_bounds"] is True
    assert "PARSER_SKIPPED_PACKETS" in parser_limited["warnings"]

    attack_limited = analyze_ddos_attack(
        distributed_tcp({"syn": 1}),
        internal_cidrs=("10.0.0.0/8",),
        parameters=PARAMETERS,
        coverage_context={"sensor_dropped_packet_count": 1},
    )
    assert attack_limited["verdict"] == "suspicious_traffic"
    assert attack_limited["confidence"] == "low"
    assert attack_limited["findings"][0]["likelihood"] == "POSSIBLE"
    assert attack_limited["findings"][0]["confidence"] == "low"

    clock_qualified = analyze_ddos_attack(
        rows,
        internal_cidrs=("10.0.0.0/8",),
        parameters={**PARAMETERS, "ddos_min_packet_count": 10_000},
        coverage_context={"sensor_clock_skew_detected": True},
    )
    assert clock_qualified["verdict"] == "insufficient_evidence"
    assert clock_qualified["summary"]["coverage_complete"] is False
    assert clock_qualified["summary"]["counts_are_lower_bounds"] is False
    assert "SENSOR_CLOCK_SKEW" in clock_qualified["warnings"]
