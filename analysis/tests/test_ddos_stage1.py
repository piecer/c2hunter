import ipaddress
import struct

import pytest
from c2hunter_controller.schemas import DDoSAttackReport
from test_ddos_attack import PARAMETERS, record

from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from c2hunter_analysis.pcap import parse_pcap


def packet_rows(
    payload=b"shared-packet",
    source_port=40000,
    *,
    stagger=False,
    request=False,
    distinct_payload=False,
    multicast=False,
    unspecified=False,
    count=3,
    sources=3,
    target="10.0.0.10",
):
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for source in range(1, sources + 1):
        for second in range(count):
            src, dst = (f"224.0.0.{source}" if multicast else f"198.51.100.{source}"), target
            if unspecified and source == 1:
                src = "0.0.0.0"
            sp, dp = source_port, 53000
            body = payload + str(source).encode() if distinct_payload else payload
            if request:
                src, dst, sp, dp = dst, src, dp, sp
                if source_port == 123:
                    body = bytes([0x23, 0]) + bytes(38) + payload[24:32]
                else:
                    body = payload[:2] + b"\x01\x00" + payload[4:6] + b"\x00\x00" + payload[8:19]
            udp = struct.pack("!HHHH", sp, dp, 8 + len(body), 0) + body
            ip = (
                struct.pack(
                    "!BBHHHBBH4s4s",
                    0x45,
                    0,
                    20 + len(udp),
                    source * 97 + second * 41,
                    0,
                    32 + (source % 20) * 8,
                    17,
                    0,
                    ipaddress.ip_address(src).packed,
                    ipaddress.ip_address(dst).packed,
                )
                + udp
            )
            stamp = 1784544000 + second + (source * 20 if stagger else 0) - int(request)
            capture.extend(struct.pack("<IIII", stamp, 0, len(ip), len(ip)) + ip)
    return list(
        parse_pcap(
            bytes(capture),
            sensor_id="fixture",
            internal_networks=["10.0.0.0/8"],
            retain_packet_bytes=False,
            retain_network_evidence=True,
        ).records
    )


def test_real_pcap_shared_profile_timing_and_negative_controls():
    rows = packet_rows()
    assert rows[0].get("ddos_packet_evidence") is not None
    report = analyze_ddos_attack(rows, parameters=PARAMETERS)
    c = report["findings"][0]["classification"]
    assert c["source_population"] == "BOTNET_LIKE_COORDINATION"
    assert c["evidence"]["coordinated_sources"] == 3
    assert c["evidence"]["shared_buckets"] == 3
    assert c["source_authenticity"] == "SPOOFING_UNCONFIRMED"
    DDoSAttackReport.model_validate(report)
    for control in (
        packet_rows(stagger=True),
        packet_rows(distinct_payload=True),
        [{k: v for k, v in row.items() if k != "ddos_packet_evidence"} for row in rows],
    ):
        result = analyze_ddos_attack(
            control,
            parameters={
                **PARAMETERS,
                "ddos_min_packets_per_second": 1,
                "ddos_min_bits_per_second": 1,
            },
        )
        assert result["findings"], "negative control must retain a volume-qualified finding"
        assert all(
            f["classification"]["source_population"] != "BOTNET_LIKE_COORDINATION"
            for f in result["findings"]
        )


@pytest.mark.parametrize(
    "payload,port,semantic",
    [
        (
            b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01",
            53,
            "DNS_RESPONSE",
        ),
        (bytes([0x24, 2]) + bytes(22) + b"12345678" + bytes(16), 123, "NTP_RESPONSE"),
    ],
)
def test_real_response_semantics_and_request_counterevidence(payload, port, semantic):
    rows = packet_rows(payload, port)
    assert rows[0]["ddos_packet_evidence"]["samples"][0]["semantic"] == semantic
    result = analyze_ddos_attack(rows, parameters=PARAMETERS)
    c = result["findings"][0]["classification"]
    assert c["delivery_mechanism"] == "REFLECTION_AMPLIFICATION"
    assert c["source_authenticity"] == "SPOOFING_UNCONFIRMED"
    assert c["evidence"]["amplification_ratio"] is None
    DDoSAttackReport.model_validate(result)
    if port in {53, 123}:
        result = analyze_ddos_attack(
            packet_rows(payload, port, request=True) + rows, parameters=PARAMETERS
        )
        c = next(f for f in result["findings"] if f["attack_role"] == "VICTIM_SIDE_INBOUND")[
            "classification"
        ]
        assert c["evidence"]["matched_response_samples"] == 9
        assert c["delivery_mechanism"] != "REFLECTION_AMPLIFICATION"


def test_axis_evidence_mutations_and_partial_capture_fail_closed():
    from copy import deepcopy

    result = analyze_ddos_attack(packet_rows(), parameters=PARAMETERS)
    for change in (
        lambda c: c["evidence"].update(amplification_ratio=0),
        lambda c: c["axes"]["source_population"].update(unknown_codes=["FUTURE"]),
        lambda c: c["evidence"].update(eligible_sources=True),
        lambda c: c["evidence"].update(observed_sources=4),
        lambda c: c["evidence"].update(unobserved_packets=1),
    ):
        bad = deepcopy(result)
        change(bad["findings"][0]["classification"])
        with pytest.raises(ValueError):
            DDoSAttackReport.model_validate(bad)
    for context in (
        {"capture_partial": True},
        {"sensor_clock_skew_detected": True},
        {"sensor_dropped_packet_count": 1},
    ):
        partial = analyze_ddos_attack(
            packet_rows(), parameters=PARAMETERS, coverage_context=context
        )
        c = partial["findings"][0]["classification"]
        assert c["source_population"] != "BOTNET_LIKE_COORDINATION"
        assert c["axes"]["source_population"]["confidence"] == "low"
        DDoSAttackReport.model_validate(partial)


def test_sample_caps_exact_and_plus_one(monkeypatch):
    import c2hunter_analysis.ddos_packets as packets

    for cap, limit in (
        ("MAX_SAMPLES_GLOBAL", 9),
        ("MAX_SAMPLES_TARGET", 9),
        ("MAX_SAMPLES_SOURCE", 3),
    ):
        with monkeypatch.context() as m:
            m.setattr(packets, cap, limit)
            rows = packet_rows()
            exact = analyze_ddos_attack(rows, parameters=PARAMETERS)["findings"][0][
                "classification"
            ]
            assert exact["source_population"] == "BOTNET_LIKE_COORDINATION"
            overflow = analyze_ddos_attack(rows + [rows[0]], parameters=PARAMETERS)["findings"][0][
                "classification"
            ]
            assert overflow["evidence"]["omitted_samples"] == 1
            assert overflow["source_population"] != "BOTNET_LIKE_COORDINATION"


def test_real_packet_metadata_ingress_roundtrip_and_malformed_rejection():
    from copy import deepcopy

    from c2hunter_controller.schemas import FlowRecord

    rows = packet_rows()
    stored = [FlowRecord.model_validate(row).model_dump(mode="json") for row in rows]
    report = analyze_ddos_attack(stored, parameters=PARAMETERS)
    assert (
        report["findings"][0]["classification"]["source_population"] == "BOTNET_LIKE_COORDINATION"
    )
    for mutate in (
        lambda b: b.update(version=2),
        lambda b: b.update(extra=True),
        lambda b: b["samples"][0].update(timestamp_us=True),
        lambda b: b["samples"][0].update(semantic="FUTURE"),
        lambda b: b["samples"][0].update(semantic="DNS_RESPONSE", transaction="a" * 64),
    ):
        bad = deepcopy(rows[0])
        mutate(bad["ddos_packet_evidence"])
        with pytest.raises(ValueError):
            FlowRecord.model_validate(bad)
    legacy = {k: v for k, v in rows[0].items() if k != "ddos_packet_evidence"}
    assert FlowRecord.model_validate(legacy).model_dump().get("ddos_packet_evidence") is None


def test_outbound_aggregate_abstains_and_v3_roundtrips():
    rows = [
        record(
            i,
            f"10.0.0.{i + 1}",
            "203.0.113.1",
            direction="OUTBOUND",
            protocol="UDP",
            packet_count=100,
            size=60000,
            duration=5,
            complete=False,
        )
        for i in range(3)
    ]
    report = analyze_ddos_attack(rows, parameters=PARAMETERS)
    classification = report["findings"][0]["classification"]
    assert classification["source_population"] == "DISTRIBUTED_UNATTRIBUTED"
    assert classification["source_authenticity"] == "SPOOFING_UNCONFIRMED"
    assert report["version"] == "ddos-attack-report-v4"
    assert (
        "PACKET_TIMING_OR_PROFILE_UNAVAILABLE"
        in classification["axes"]["source_population"]["unknown_codes"]
    )
    DDoSAttackReport.model_validate(report)


@pytest.mark.parametrize(
    "sources,count,targets,total", [(3, 32, 1, 96), (64, 32, 1, 2048), (64, 32, 16, 32768)]
)
def test_actual_production_sample_limits(sources, count, targets, total):
    rows = [
        row
        for target in range(targets)
        for row in packet_rows(sources=sources, count=count, target=f"10.0.0.{target + 10}")
    ]
    exact = analyze_ddos_attack(rows, parameters=PARAMETERS)
    assert sum(f["classification"]["evidence"]["sample_count"] for f in exact["findings"]) == total
    assert all(
        f["classification"]["source_population"] == "BOTNET_LIKE_COORDINATION"
        for f in exact["findings"]
    )
    overflow = analyze_ddos_attack(rows + [rows[0]], parameters=PARAMETERS)
    assert (
        sum(f["classification"]["evidence"]["omitted_samples"] for f in overflow["findings"]) == 1
    )
    affected = next(f for f in overflow["findings"] if f["target"]["ip"] == "10.0.0.10")
    assert affected["classification"]["source_population"] != "BOTNET_LIKE_COORDINATION"
    if targets > 1:
        assert all(
            f["classification"]["source_population"] != "BOTNET_LIKE_COORDINATION"
            for f in overflow["findings"]
        )
    DDoSAttackReport.model_validate(exact)
    DDoSAttackReport.model_validate(overflow)


def test_multicast_source_evidence_is_independent_and_real_parser_derived():
    normal = analyze_ddos_attack(packet_rows(), parameters=PARAMETERS)
    invalid = analyze_ddos_attack(packet_rows(multicast=True), parameters=PARAMETERS)
    assert normal["findings"][0]["classification"]["source_authenticity"] == "SPOOFING_UNCONFIRMED"
    c = invalid["findings"][0]["classification"]
    assert c["source_authenticity"] == "SPOOFING_SUSPECTED"
    assert c["evidence"]["invalid_source_records"] == 9
    assert c["axes"]["source_authenticity"]["supporting_codes"] == [
        "INVALID_SOURCE_ADDRESS_OBSERVED"
    ]
    DDoSAttackReport.model_validate(invalid)


def test_reordered_missing_partial_and_mixed_packet_evidence():
    from copy import deepcopy

    rows = packet_rows()
    forward = analyze_ddos_attack(rows, parameters=PARAMETERS)
    assert analyze_ddos_attack(list(reversed(rows)), parameters=PARAMETERS) == forward
    partial = deepcopy(rows)
    partial[0].pop("ddos_packet_evidence")
    c = analyze_ddos_attack(partial, parameters=PARAMETERS)["findings"][0]["classification"]
    assert c["source_population"] != "BOTNET_LIKE_COORDINATION"
    assert c["evidence"]["unobserved_packets"] == 1
    reflection = packet_rows(bytes([0x24, 2]) + bytes(46), 123)
    mixed = analyze_ddos_attack(rows + reflection, parameters=PARAMETERS)
    c = mixed["findings"][0]["classification"]
    assert c["delivery_mechanism"] == "MIXED"
    assert c["source_authenticity"] == "SPOOFING_UNCONFIRMED"
    DDoSAttackReport.model_validate(mixed)


@pytest.mark.parametrize(
    "name,payload,port",
    [
        ("dns_response", bytes.fromhex("12348180000100010000000001610000010001"), 53),
        ("ntp_response", bytes([0x24, 2]) + bytes(46), 123),
    ],
)
def test_frozen_live_flowbatch_matches_real_pcap_samples(name, payload, port):
    import json
    from pathlib import Path

    from c2hunter_controller.schemas import FlowRecord

    batch = json.loads((Path(__file__).parent / "fixtures" / f"ddos-live-{name}.json").read_text())
    flow = FlowRecord.model_validate(batch["flows"][0]).model_dump(mode="json")
    rows = packet_rows(payload, port, count=16, sources=1)
    assert flow["ddos_packet_evidence"]["samples"] == [
        row["ddos_packet_evidence"]["samples"][0] for row in rows
    ]
    # Aggregate wall-clock start/end is never substituted for packet timestamps.
    assert len(flow["ddos_packet_evidence"]["samples"]) == 16
    assert flow["packet_evidence_complete"] is False


def test_pcap_fixture_bytes_are_from_current_decoder_and_wire_serializer():
    import json
    from pathlib import Path

    from c2hunter_controller.schemas import FlowRecord

    actual = (
        json.dumps(
            [FlowRecord.model_validate(row).model_dump(mode="json") for row in packet_rows()],
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    assert actual == (Path(__file__).parent / "fixtures/ddos-pcap-coordination.json").read_text()


def test_axis_sample_denominators_cannot_invent_unobserved_packets():
    from c2hunter_analysis.ddos_evidence import assess

    report = analyze_ddos_attack(packet_rows(), parameters=PARAMETERS)
    item = report["findings"][0]
    item["classification"]["evidence"]["unobserved_packets"] = 1
    item["classification"] = assess(item["classification"]["evidence"])
    item["uncertainty_codes"].remove("BOTNET_ATTRIBUTION_UNCONFIRMED")
    with pytest.raises(ValueError):
        DDoSAttackReport.model_validate(report)


def test_real_partial_and_fragmented_packets_emit_no_complete_samples():
    from test_network_anomaly import frame, records

    complete = frame(payload=b"actual")
    fragment = bytearray(complete)
    fragment[20:22] = b"\x20\x00"
    for raw in (complete[:-2], bytes(fragment)):
        row = records(raw)[0]
        assert row["packet_evidence_complete"] is False
        assert row["ddos_packet_evidence"]["samples"] == []
    assert len(records(complete)[0]["ddos_packet_evidence"]["samples"]) == 1


@pytest.mark.parametrize("identity", ["ttl", "ipid"])
def test_qualified_identity_observation_alone_never_authenticates_or_proves_spoofing(identity):
    from c2hunter_controller.schemas import FlowRecord

    rows = [
        record(
            i,
            f"198.51.100.{i + 1}",
            protocol="UDP",
            packet_count=8,
            size=480,
            duration=3,
            complete=False,
        )
        for i in range(3)
    ]
    fields = (
        {
            "hop_limit_min": 32,
            "hop_limit_max": 128,
            "hop_limit_mode": 64,
            "hop_limit_distinct_count": 5,
        }
        if identity == "ttl"
        else {
            "ip_id_observed_count": 8,
            "ip_id_distinct_count": 8,
            "ip_id_transition_count": 7,
            "ip_id_monotonic_transitions": 0,
        }
    )
    admitted = [
        FlowRecord.model_validate({**row, **fields}).model_dump(mode="json") for row in rows
    ]
    c = analyze_ddos_attack(admitted, parameters=PARAMETERS)["findings"][0]["classification"]
    assert c["source_authenticity"] == "SPOOFING_UNCONFIRMED"
    assert c["axes"]["source_authenticity"]["supporting_codes"] == []
    assert "TTL_IPID_VARIATION_NOT_PROOF" in c["axes"]["source_authenticity"]["unknown_codes"]


def test_unspecified_source_is_not_universal_forgery_proof():
    # Unspecified source addressing has protocol-specific legitimate uses.
    report = analyze_ddos_attack(packet_rows(unspecified=True), parameters=PARAMETERS)
    c = report["findings"][0]["classification"]
    assert c["source_authenticity"] == "SPOOFING_UNCONFIRMED"
    assert c["evidence"]["invalid_source_records"] == 0
