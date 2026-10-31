"""Real packet/parser regressions for temporal SYN reply counterevidence."""

from __future__ import annotations

import struct

import pytest
from c2hunter_analysis.ddos_job import analyze_ddos_job
from c2hunter_analysis.pcap import parse_pcap
from pcap_guidance_fixture_builder import EPOCH, packets, pcap_bytes

from c2hunter_controller.pcap_attack_guidance_schema import validate_job_guidance


def shifted(samples, micros):
    return [(time + micros, packet) for time, packet in samples]


def analyze_samples(samples, *, file_order=False, sensor="temporal"):
    if file_order:
        data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for micros, packet in samples:
            seconds, fraction = divmod(micros, 1_000_000)
            data.extend(struct.pack("<IIII", EPOCH + seconds, fraction, len(packet), len(packet)))
            data.extend(packet)
        content = bytes(data)
    else:
        content = pcap_bytes(samples)
    parsed = parse_pcap(
        content,
        sensor_id=sensor,
        internal_networks=["10.0.0.0/8"],
        max_packets=20000,
        retain_packet_bytes=False,
        retain_network_evidence=True,
    )
    assert parsed.skipped_packet_count == 0
    assert len(parsed.records) == len(samples)
    return parsed.records


def guide_for(records):
    job = {
        "id": "temporal-job",
        "dataset_id": "temporal-dataset",
        "source_type": "PCAP_UPLOAD",
        "analysis": {"module": "ddos_attack"},
        "internal_networks": ["10.0.0.0/8"],
        "flow_records": records,
    }
    job.update(analyze_ddos_job(job))
    return validate_job_guidance(job)


@pytest.mark.parametrize(
    "request_us,reply_us,suppressed",
    [
        (1_000_000, 1_020_000, True),
        (4_990_000, 5_010_000, True),
        (2_000_000, 1_000_000, False),
        (1_000_000, 1_000_000, True),
        (1_000_000, 6_000_000, True),
        (1_000_000, 6_000_001, False),
    ],
)
@pytest.mark.parametrize("file_order", [False, True])
def test_temporal_reply_horizon_across_buckets(request_us, reply_us, suppressed, file_order):
    # Identical review inputs: 160 SYNs and reverse replies, 1ms spread.
    span = 0 if reply_us - request_us >= 5_000_000 else 1000
    requests = shifted(packets(160, span_us=span), request_us)
    replies = shifted(packets(160, flags=18, reverse=True, span_us=span), reply_us)
    guide = guide_for(analyze_samples(replies + requests, file_order=file_order))
    assert guide["summary"]["eligible_packet_count"] == 320
    assert guide["summary"]["suppressed_handshake_window_count"] == int(suppressed)
    assert len(guide["candidates"]) == int(not suppressed)
    if not suppressed:
        assert guide["candidates"][0]["packet_count"] == 160


@pytest.mark.parametrize(
    "wrong", ["sensor", "initiator_ip", "initiator_port", "target_ip", "target_port"]
)
def test_reverse_tuple_and_sensor_are_required(wrong):
    requests = shifted(packets(160, sources=1, span_us=0), 4_990_000)
    replies = shifted(packets(160, sources=1, span_us=0, flags=18, reverse=True), 5_010_000)
    if wrong != "sensor":
        offset, replacement = {
            "initiator_ip": (30, b"\xc6\x33\x64\x02"),
            "initiator_port": (36, struct.pack("!H", 40001)),
            "target_ip": (26, b"\x0a\x00\x00\x0b"),
            "target_port": (34, struct.pack("!H", 8443)),
        }[wrong]
        replies = [
            (time, packet[:offset] + replacement + packet[offset + len(replacement) :])
            for time, packet in replies
        ]
    rows = analyze_samples(requests)
    rows += analyze_samples(replies, sensor="other" if wrong == "sensor" else "temporal")
    guide = guide_for(rows)
    assert guide["summary"]["suppressed_handshake_window_count"] == 0
    assert len(guide["candidates"]) == 1


def test_fifo_each_reply_consumed_once_and_credited_to_original_window():
    samples = (
        shifted(packets(32, sources=1, span_us=0), 4_000_000)
        + shifted(packets(32, sources=1, span_us=0), 5_000_000)
        + shifted(packets(32, sources=1, span_us=0, flags=18, reverse=True), 5_500_000)
    )
    guide = guide_for(analyze_samples(list(reversed(samples)), file_order=True))
    assert guide["summary"]["suppressed_handshake_window_count"] == 1
    assert guide["candidates"][0]["window_start"] == "2026-09-15T00:00:05.000000Z"


def test_expired_pending_syn_does_not_consume_fresh_reply():
    samples = (
        packets(32, sources=1, span_us=0)
        + shifted(packets(32, sources=1, span_us=0), 5_000_000)
        + shifted(packets(32, sources=1, span_us=0, flags=18, reverse=True), 6_000_000)
    )
    guide = guide_for(analyze_samples(samples))
    assert guide["summary"]["suppressed_handshake_window_count"] == 1
    assert guide["candidates"][0]["window_start"] == "2026-09-15T00:00:00.000000Z"


def test_retained_and_discarded_response_events_cannot_exceed_eligible_population():
    from c2hunter_controller.pcap_attack_guidance_schema import PcapAttackGuidance

    guide = guide_for(analyze_samples(packets(8200, sources=1, span_us=0)))
    guide["summary"]["response_omitted_count"] += 1
    with pytest.raises(ValueError):
        PcapAttackGuidance.model_validate(guide)


def test_real_response_event_cap_counts_every_discarded_observation():
    # Repeated identical tuples must not bypass the global event-state bound.
    rows = analyze_samples(packets(8200, sources=1, span_us=0))
    guide = guide_for(rows)
    assert guide["summary"]["response_state_count"] == 8192
    assert guide["summary"]["response_omitted_count"] == 8
    assert "RESPONSE_STATE_LIMIT" in guide["coverage_codes"]
    assert guide["summary"]["coverage_complete"] is False
    assert guide["candidates"][0]["packet_count"] == 8200
