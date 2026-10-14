from datetime import UTC, datetime, timedelta

import pytest
from c2hunter_controller.schemas import FlowRecord
from ddos_packet_cases import classic_rows, ipudp, ng_rows

from c2hunter_analysis.ddos_attack import analyze_ddos_attack


def test_historical_fractional_microseconds_are_exact():
    rows = classic_rows(
        [(1104537600, 2, ipudp("198.51.100.1", "10.0.0.10", 40000, 53000, b"valid"))]
    )
    row = FlowRecord.model_validate(rows[0]).model_dump(mode="json")
    assert row["ddos_packet_evidence"]["samples"][0]["timestamp_us"] == 1104537600000002
    assert analyze_ddos_attack([row])["summary"]["evaluated_records"] == 1


def test_signed_pre_epoch_pcapng_preserves_counts_and_time():
    rows = ng_rows(
        [(0, 0, 500000, ipudp("198.51.100.1", "10.0.0.10", 40000, 53000, b"valid"))], offset=-1
    )
    assert rows[0]["timestamp"] == datetime(1969, 12, 31, 23, 59, 59, 500000, tzinfo=UTC)
    assert rows[0]["ddos_packet_evidence"]["samples"][0]["timestamp_us"] == -500000
    row = FlowRecord.model_validate(rows[0]).model_dump(mode="json")
    assert analyze_ddos_attack([row])["summary"]["evaluated_records"] == 1


@pytest.mark.parametrize("stamp", [-(2**53 - 1), 2**53 - 1])
def test_signed_safe_integer_sample_boundary(stamp):
    from c2hunter_analysis.ddos_packets import packet_sample, validate_packet_evidence

    sample = packet_sample(
        datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=stamp),
        "UDP",
        33,
        0,
        b"valid",
        40000,
        53000,
    )
    assert sample["timestamp_us"] == stamp
    bundle = {"version": 1, "samples": [sample], "omitted_samples": 0}
    assert validate_packet_evidence(bundle, 1, stamp, stamp, "UDP", 40000, 53000) == bundle
    sample["timestamp_us"] += 1 if stamp > 0 else -1
    with pytest.raises(ValueError, match="outside flow interval"):
        validate_packet_evidence(bundle, 1, stamp - 2, stamp + 2, "UDP", 40000, 53000)


@pytest.mark.parametrize(
    "body,port",
    [
        (bytes.fromhex("12348380000100000000000001610000010001"), 53),
        (bytes.fromhex("12348980000100000000000001610000010001"), 53),
        (bytes.fromhex("1234818000010000000000000161"), 53),
        (bytes([0x27, 2]) + bytes(46), 123),
        (b"unsupported-reply", 17),
        (b"unsupported-reply", 19),
        (b"unsupported-reply", 389),
        (b"HTTP/1.1 200 OK", 1900),
        (b"STAT items 100", 11211),
    ],
)
def test_unknown_service_replies_abstain_from_coordination_at_defaults(body, port):
    from ddos_packet_cases import flood

    rows = flood(body, port)
    report = analyze_ddos_attack(rows)
    assert report["findings"]
    for finding in report["findings"]:
        c = finding["classification"]
        assert c["source_population"] != "BOTNET_LIKE_COORDINATION"
        assert c["evidence"]["sample_count"] == 1024
        assert c["evidence"]["direct_samples"] == 0
        assert c["evidence"]["coordinated_sources"] == 0
        assert c["evidence"]["response_samples"] == 0


def test_real_direct_packets_still_coordinate_at_defaults():
    from ddos_packet_cases import flood

    finding = analyze_ddos_attack(flood(b"shared", 40000))["findings"][0]
    c = finding["classification"]
    assert c["source_population"] == "BOTNET_LIKE_COORDINATION"
    assert c["evidence"]["sample_count"] == c["evidence"]["direct_samples"] == 1024
    assert c["evidence"]["coordinated_sources"] == 64


@pytest.mark.parametrize("count", [32, 33, 1000])
def test_real_go_reverse_source_quota_qualifies_dependent_response(count):
    import json
    from pathlib import Path

    from c2hunter_controller.schemas import DDoSAttackReport
    from test_ddos_attack import PARAMETERS

    wire = json.loads(
        (Path(__file__).parent / "fixtures/ddos-live-reverse-requests.json").read_text()
    )[str(count)]
    rows = [FlowRecord.model_validate(row).model_dump(mode="json") for row in wire["flows"]]
    requests = [r for r in rows if r["source_port"] != 53]
    assert sum(len(r["ddos_packet_evidence"]["samples"]) for r in requests) == 32
    assert sum(r["ddos_packet_evidence"]["omitted_samples"] for r in requests) == count - 32
    report = analyze_ddos_attack(
        rows, parameters=None if count == 1000 else {**PARAMETERS, "ddos_min_duration_seconds": 1}
    )
    DDoSAttackReport.model_validate(report)
    finding = next(f for f in report["findings"] if f["attack_role"] == "VICTIM_SIDE_INBOUND")
    c = finding["classification"]
    assert c["evidence"]["response_samples"] == count
    assert c["evidence"]["matched_response_samples"] == 32
    assert c["evidence"]["omitted_samples"] == 0  # reverse loss is NOT this denominator
    assert finding["metrics"]["packet_count"] == count
    if count == 32:
        assert c["delivery_mechanism"] != "REFLECTION_AMPLIFICATION"
        assert c["evidence"]["coverage_limited"] is False
    else:
        assert c["delivery_mechanism"] == "REFLECTION_AMPLIFICATION"
        assert c["axes"]["delivery_mechanism"]["confidence"] == "low"
        assert c["evidence"]["coverage_limited"] is True
        assert "EVIDENCE_COVERAGE_LIMITED" in c["axes"]["delivery_mechanism"]["unknown_codes"]


def test_full_pcap_request_countercontrol_still_matches_all_1000():
    from ddos_packet_cases import BASE, DNS_RESPONSE, QUESTION

    events = []
    for n in range(10):
        for s in range(1, 101):
            ident = n.to_bytes(2, "big")
            request = ident + bytes.fromhex("01000001000000000000") + QUESTION
            response = ident + DNS_RESPONSE[2:]
            server = f"198.51.100.{s}"
            events.append((BASE + n, 0, ipudp("10.0.0.10", server, 53000, 53, request)))
            events.append((BASE + n, 100000, ipudp(server, "10.0.0.10", 53, 53000, response)))
    report = analyze_ddos_attack(classic_rows(events))
    finding = next(f for f in report["findings"] if f["attack_role"] == "VICTIM_SIDE_INBOUND")
    c = finding["classification"]
    assert c["evidence"]["matched_response_samples"] == 1000
    assert c["evidence"]["coverage_limited"] is False
    assert c["delivery_mechanism"] != "REFLECTION_AMPLIFICATION"


@pytest.mark.parametrize("offset", [-10000000000, 10000000000])
def test_out_of_safe_range_pcapng_abstains_without_rejecting_packet(offset):
    rows = ng_rows(
        [(0, 0, 500000, ipudp("198.51.100.1", "10.0.0.10", 40000, 53000, b"valid"))], offset=offset
    )
    row = FlowRecord.model_validate(rows[0]).model_dump(mode="json")
    assert row["packet_count"] == 1
    assert row["ddos_packet_evidence"] == {"version": 1, "samples": [], "omitted_samples": 1}
    result = analyze_ddos_attack([row])
    assert result["summary"]["evaluated_records"] == 1
    assert result["summary"]["packet_count"] == 1


def test_reverse_loss_state_is_globally_bounded_at_cap_and_cap_plus_one():
    from ddos_packet_cases import BASE, QUESTION

    from c2hunter_analysis.ddos_attack import _compile_networks, _normalize
    from c2hunter_analysis.ddos_evidence import empty_evidence
    from c2hunter_analysis.ddos_packets import MAX_REVERSE_LOSS_SCOPES, PacketEvidenceCollector

    assert MAX_REVERSE_LOSS_SCOPES == 4096
    collector = PacketEvidenceCollector()
    request = bytes.fromhex("123401000001000000000000") + QUESTION
    rows = classic_rows(
        (BASE, 0, ipudp("10.0.0.10", "198.51.100.1", port, 53, request))
        for port in range(10000, 10000 + MAX_REVERSE_LOSS_SCOPES + 1)
    )
    networks = _compile_networks(["10.0.0.0/8"])
    for index, raw in enumerate(rows):
        # Legacy absent evidence is known unobserved request-direction traffic.
        raw.pop("ddos_packet_evidence")
        collector.add(("request",), _normalize(raw, networks), empty_evidence())
        assert len(collector.reverse_loss_scopes) == min(index + 1, MAX_REVERSE_LOSS_SCOPES)
        assert collector.reverse_loss_overflow is (index >= MAX_REVERSE_LOSS_SCOPES)
    assert collector.total == 0


def test_reverse_loss_scope_and_overflow_degrade_without_relabeling_direct_packets(monkeypatch):
    from ddos_packet_cases import BASE, DNS_RESPONSE, QUESTION, flood

    import c2hunter_analysis.ddos_packets as packets

    monkeypatch.setattr(packets, "MAX_REVERSE_LOSS_SCOPES", 2)
    request = bytes.fromhex("123401000001000000000000") + QUESTION
    lost = classic_rows(
        (BASE, 0, ipudp("10.0.0.99", "198.51.100.1", port, 53, request))
        for port in (10000, 10001, 10002)
    )
    for row in lost:
        row.pop("ddos_packet_evidence")
    for count in (2, 3):
        report = analyze_ddos_attack(lost[:count] + flood(DNS_RESPONSE, 53))
        c = next(f for f in report["findings"] if f["target"]["ip"] == "10.0.0.10")[
            "classification"
        ]
        assert c["evidence"]["coverage_limited"] is (count == 3)
        assert c["axes"]["delivery_mechanism"]["confidence"] == ("low" if count == 3 else "medium")
    direct = analyze_ddos_attack(lost + flood(b"direct", 40000))["findings"][0]["classification"]
    assert direct["source_population"] == "BOTNET_LIKE_COORDINATION"
