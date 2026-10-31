from __future__ import annotations

import importlib.util
from typing import Any

import pytest
from test_ddos_attack import PARAMETERS, distributed_tcp, record

from c2hunter_analysis.ddos_attack import analyze_ddos_attack


def job_result(rows: Any, **extra: Any) -> dict[str, Any]:
    assert importlib.util.find_spec("c2hunter_analysis.ddos_job") is not None
    from c2hunter_analysis.ddos_job import analyze_ddos_job

    return analyze_ddos_job(
        {
            "id": "guide-job",
            "dataset_id": "guide-dataset",
            "source_type": "PCAP_UPLOAD",
            "analysis": {"module": "ddos_attack"},
            "internal_networks": ["10.0.0.0/8"],
            "flow_records": rows,
            **extra,
        }
    )


def burst(
    count: int = 160,
    start: float = 0,
    sources: int = 1,
    protocol: str = "TCP",
    flags: dict[str, int] | None = None,
) -> list[dict[str, object]]:
    return [
        record(
            start + i / count * 2,
            f"198.51.100.{i % sources + 1}",
            protocol=protocol,
            flags={"syn": 1} if flags is None else flags,
        )
        for i in range(count)
    ]


def test_single_source_syn_candidate_is_not_a_ddos_finding() -> None:
    result = job_result(iter(burst()))
    assert result["ddos_attack"]["version"] == "ddos-attack-report-v4"
    assert result["ddos_attack"]["findings"] == []
    guide = result["pcap_attack_guidance"]
    assert guide["version"] == "pcap-attack-guidance-v1"
    assert guide["job_id"] == "guide-job"
    assert guide["dataset_id"] == "guide-dataset"
    assert guide["status"] == "REVIEW_CANDIDATES"
    (candidate,) = guide["candidates"]
    assert candidate["family"] == "SYN_CONCENTRATION"
    assert candidate["packet_count"] == 160
    assert candidate["source_count"] == 1
    assert candidate["source_count_is_lower_bound"] is False
    assert candidate["window_start"] == "2026-09-15T00:00:00.000000Z"
    assert candidate["window_end"] == "2026-09-15T00:00:05.000000Z"
    assert candidate["first_seen"] != candidate["last_seen"]
    assert "LOW_SOURCE_DIVERSITY" in candidate["uncertainty_codes"]
    assert "SHORT_OBSERVATION" in candidate["uncertainty_codes"]


def test_strongest_local_syn_survives_later_benign_and_weaker_windows() -> None:
    original = job_result(burst())["pcap_attack_guidance"]["candidates"][0]
    rows = burst() + burst(40, start=10) + burst(600, start=20, flags={"ack": 1})
    for row in rows[-600:]:
        row["transport_payload_length"] = 900
    guide = job_result(rows)["pcap_attack_guidance"]
    assert guide["candidates"] == [original]


def test_matching_bidirectional_handshakes_are_not_review_candidates() -> None:
    requests = burst()
    responses = []
    for request in requests:
        response = dict(request)
        response.update(
            source_ip=request["destination_ip"],
            destination_ip=request["source_ip"],
            source_port=request["destination_port"],
            destination_port=request["source_port"],
            direction="OUTBOUND",
            tcp_syn_only_count=0,
            tcp_syn_ack_count=1,
            tcp_flags={"syn": 1, "ack": 1},
        )
        responses.append(response)
    assert job_result(requests + responses)["pcap_attack_guidance"]["candidates"] == []
    for response in responses:
        response["source_port"] = 8443
    assert len(job_result(requests + responses)["pcap_attack_guidance"]["candidates"]) == 1


def test_relative_udp_uses_three_prior_occupied_eligible_windows_not_idle_time() -> None:
    baseline = sum((burst(32, start=i * 5, protocol="UDP", flags={}) for i in range(3)), [])
    peak = burst(160, start=30, protocol="UDP", flags={})
    (candidate,) = job_result(baseline + peak)["pcap_attack_guidance"]["candidates"]
    assert candidate["family"] == "UDP_BURST"
    assert candidate["baseline_window_count"] == 3
    assert candidate["baseline_packet_count"] == 96
    assert candidate["reason_codes"] == ["RELATIVE_RATE_INCREASE"]
    assert "WITHIN_CAPTURE_NOT_KNOWN_NORMAL" in candidate["uncertainty_codes"]
    assert job_result(baseline[:64] + peak)["pcap_attack_guidance"]["candidates"] == []
    stable = sum((burst(32, start=i * 5, protocol="UDP", flags={}) for i in range(20)), [])
    assert job_result(stable)["pcap_attack_guidance"]["candidates"] == []
    assert job_result(peak)["pcap_attack_guidance"]["candidates"] == []


@pytest.mark.parametrize(
    ("protocol", "flags", "family"),
    [
        ("TCP", {"ack": 1}, "PAYLOAD_FREE_ACK_BURST"),
        ("TCP", {"rst": 1}, "RST_BURST"),
        ("UDP", {}, "UDP_BURST"),
        ("ICMP", {}, "ICMP_BURST"),
    ],
)
def test_volume_bursts_have_family_specific_passive_checks(protocol, flags, family) -> None:
    rows = burst(1000, protocol=protocol, flags=flags)
    (candidate,) = job_result(rows)["pcap_attack_guidance"]["candidates"]
    assert candidate["family"] == family
    assert candidate["reason_codes"] == ["ABSOLUTE_VOLUME"]
    assert candidate["next_check_codes"]
    assert job_result(rows[:31])["pcap_attack_guidance"]["candidates"] == []
    if family == "PAYLOAD_FREE_ACK_BURST":
        for row in rows:
            row["transport_payload_length"] = 1000
        assert job_result(rows)["pcap_attack_guidance"]["candidates"] == []
        for row in rows:
            row.pop("transport_payload_length")
        assert job_result(rows)["pcap_attack_guidance"]["candidates"] == []


def test_caps_and_exclusions_are_truthful_and_serialization_is_bounded() -> None:
    rows = []
    for target in range(1, 258):
        part = burst(40, sources=40)
        for row in part:
            row["destination_ip"] = f"10.0.{target // 256}.{target % 256}"
        rows.extend(part)
    guide = job_result(rows)["pcap_attack_guidance"]
    assert len(guide["candidates"]) == 32
    assert guide["summary"]["omitted_candidate_count"] == 224
    assert guide["summary"]["omitted_observation_count"] == 40
    candidate = guide["candidates"][0]
    assert candidate["source_count"] == 32
    assert candidate["source_count_is_lower_bound"] is True
    assert len(candidate["source_examples"]) == 8
    import json

    assert (
        len(json.dumps(guide, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
        < 128 * 1024
    )


def test_aggregate_unsupported_partial_and_input_overflow_are_not_clean(monkeypatch) -> None:
    aggregate = burst()
    for row in aggregate:
        row["packet_count"] = 2
    unsupported = burst(protocol="IP_99")
    guide = job_result(
        aggregate + unsupported,
        ddos_coverage_context={"capture_partial": True, "parser_skipped_packet_count": 3},
    )["pcap_attack_guidance"]
    assert guide["candidates"] == []
    assert guide["status"] == "INSUFFICIENT_OBSERVATION"
    assert guide["summary"]["excluded_record_count"] == 160
    assert guide["summary"]["rejected_record_count"] == 160
    assert {"CAPTURE_PARTIAL", "PARSER_GAPS", "RECORDS_REJECTED", "INELIGIBLE_RECORDS"} <= set(
        guide["coverage_codes"]
    )
    monkeypatch.setattr("c2hunter_analysis.ddos_attack.MAX_SCANNED_RECORDS", 40)
    overflow = job_result(burst())["pcap_attack_guidance"]
    assert overflow["candidates"] == []
    assert overflow["summary"]["eligible_packet_count"] == 0
    assert "INPUT_LIMIT" in overflow["coverage_codes"]


def test_window_and_reverse_state_caps(monkeypatch) -> None:
    import c2hunter_analysis.pcap_attack_guidance as module

    monkeypatch.setattr(module, "MAX_WINDOWS", 4)
    monkeypatch.setattr(module, "MAX_TARGET_WINDOWS", 3)
    rows = sum((burst(32, start=i * 5, sources=32) for i in range(6)), [])
    guide = job_result(rows)["pcap_attack_guidance"]
    assert guide["summary"]["retained_window_count"] == 3
    assert guide["summary"]["response_state_count"] == 4
    assert guide["summary"]["response_omitted_count"] > 0
    assert guide["summary"]["omitted_observation_count"] == 96
    assert "RESPONSE_STATE_LIMIT" in guide["coverage_codes"]


def test_unrepresentable_window_and_non_ddos_helper_abstain():
    from datetime import UTC, datetime

    rows = burst(32)
    for row in rows:
        row["timestamp"] = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
    guide = job_result(rows)["pcap_attack_guidance"]
    assert guide["status"] == "INSUFFICIENT_OBSERVATION"
    assert guide["summary"]["excluded_record_count"] == 32


def test_shared_ddos_helper_rejects_other_modules():
    with pytest.raises(ValueError):
        job_result(burst(), analysis={"module": "c2"})


def test_output_byte_budget_and_real_total_window_bound(monkeypatch):
    import c2hunter_analysis.pcap_attack_guidance as module

    rows = []
    for i in range(3):
        part = burst()
        for row in part:
            row["destination_port"] = 440 + i
        rows.extend(part)
    monkeypatch.setattr(module, "MAX_BYTES", 2500)
    guide = job_result(rows)["pcap_attack_guidance"]
    assert len(module.canonical_bytes(guide)) <= 2500
    assert guide["summary"]["omitted_candidate_count"] > 0
    monkeypatch.undo()
    rows = [
        record(window * 5, "198.51.100.1", f"10.0.0.{target}", protocol="UDP")
        for target in range(1, 18)
        for window in range(512)
    ]
    guide = job_result(rows)["pcap_attack_guidance"]
    assert guide["summary"]["retained_window_count"] == 8192
    assert guide["summary"]["omitted_observation_count"] == 512
    assert guide["candidates"] == []


def test_low_source_warning_survives_an_unrelated_finding() -> None:
    rows = distributed_tcp({"syn": 1}) + [
        record(second, "198.51.100.90", "10.0.0.11", flags={"syn": 1}) for second in range(25)
    ]
    result = analyze_ddos_attack(rows, internal_cidrs=("10.0.0.0/8",), parameters=PARAMETERS)
    assert result["findings"]
    assert "DOS_LIKE_TRAFFIC" in result["warnings"]
