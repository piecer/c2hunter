"""Capture-local vantage identities through native wire bytes and the worker."""

import importlib
import struct
from pathlib import Path

import pytest
from c2hunter_controller.schemas import FlowRecord
from test_network_anomaly import frame, internet_checksum

from c2hunter_analysis.pcap import parse_pcap


@pytest.fixture
def worker(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / "sensor/worker/src"))
    module = importlib.import_module("c2hunter_worker.analysis")
    assert Path(module.__file__).resolve().is_relative_to(root)
    return module


def sll2(packet, index, packet_type=0):
    ip = packet[14:]
    # Independently check both wire checksums before wrapping native IP/TCP.
    assert internet_checksum(ip[:20]) == 0
    pseudo = ip[12:20] + struct.pack("!BBH", 0, ip[9], len(ip) - 20)
    assert internet_checksum(pseudo + ip[20:]) == 0
    return struct.pack("!HHIHBB8s", 0x0800, 0, index, 1, packet_type, 6, b"\x01" * 6) + ip


def classic(packets, link=276, endian="<"):
    result = struct.pack(f"{endian}IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    for ordinal, packet in enumerate(packets):
        result += struct.pack(f"{endian}IIII", 1700000000, ordinal * 1000, len(packet), len(packet))
        result += packet
    return result


def parse(content, **kwargs):
    return parse_pcap(
        content,
        sensor_id=kwargs.pop("sensor_id", "capture-a"),
        internal_networks=["10.0.0.0/8"],
        retain_network_evidence=True,
        retain_packet_bytes=kwargs.pop("retain_packet_bytes", False),
        **kwargs,
    )


def report(records, worker):
    rows = [FlowRecord.model_validate(row).model_dump(mode="json") for row in records]
    assert [row["capture_interface_id"] for row in rows] == [
        row["capture_interface_id"] for row in records
    ]
    return worker.execute_analysis(
        {"analysis": {"module": "network_anomaly"}, "flow_records": rows}
    )["network_anomaly"]


def forwarded():
    syn = frame()
    synack = frame(flags=18, seq=500, ack=101, reverse=True)
    return [sll2(syn, 2), sll2(syn, 3, 4), sll2(synack, 3), sll2(synack, 2, 4)]


def test_sll2_forwarding_vantages_do_not_create_syn_retransmission(worker):
    records = parse(classic(forwarded())).records
    result = report(records, worker)
    assert result["issues"] == []
    assert result["summary"]["flow_count"] == 2
    ids = [row["capture_interface_id"] for row in records]
    assert ids[0] == ids[3] and ids[1] == ids[2] and ids[0] != ids[1]
    assert all(type(value) is int and 0 <= value < 2**32 for value in ids)


@pytest.mark.parametrize("index", [2, 3])
def test_sll2_single_interface_handshake_control(worker, index):
    packets = [sll2(frame(), index), sll2(frame(flags=18, seq=500, ack=101, reverse=True), index)]
    records = parse(classic(packets)).records
    result = report(records, worker)
    assert result["issues"] == []
    assert result["summary"]["flow_count"] == 1
    assert result["summary"]["evaluated_records"] == 2
    assert records[0]["capture_interface_id"] == records[1]["capture_interface_id"]


def block(kind, body, endian="<"):
    body += b"\0" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(f"{endian}II", kind, size) + body + struct.pack(f"{endian}I", size)


def section(endian="<"):
    return block(0x0A0D0D0A, struct.pack(f"{endian}IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def idb(link=276, endian="<"):
    return block(1, struct.pack(f"{endian}HHI", link, 0, 65535), endian)


def packet_block(packet, interface=0, ordinal=0, endian="<", kind=6):
    ticks = 1700000000 * 1_000_000 + ordinal * 1000
    prefix = struct.pack(f"{endian}I", interface)
    if kind == 2:
        prefix = struct.pack(f"{endian}HH", interface, 0)
    body = prefix + struct.pack(
        f"{endian}IIII", ticks >> 32, ticks & 0xFFFFFFFF, len(packet), len(packet)
    )
    return block(kind, body + packet, endian)


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("kind", [2, 6])
def test_pcapng_same_ifindex_in_later_idb_stays_isolated(worker, endian, kind):
    packets = forwarded()
    # Both IDBs carry the *same* OS index; the second IDB is declared late.
    packets = [sll2(frame(), 2), sll2(frame(), 2), packets[3], packets[3]]
    content = section(endian) + idb(endian=endian)
    content += packet_block(packets[0], endian=endian, kind=kind)
    content += idb(endian=endian)
    for ordinal, interface in enumerate([1, 0, 1], 1):
        content += packet_block(packets[ordinal], interface, ordinal, endian, kind)
    records = parse(content).records
    ids = [row["capture_interface_id"] for row in records]
    assert ids[0] == ids[2] and ids[1] == ids[3] and ids[0] != ids[1]
    result = report(records, worker)
    assert result["issues"] == []
    assert result["summary"]["flow_count"] == 2


@pytest.mark.parametrize("endian", ["<", ">"])
def test_classic_byte_order_does_not_change_sll2_network_order(worker, endian):
    records = parse(classic(forwarded(), endian=endian)).records
    assert records == parse(classic(forwarded())).records
    assert report(records, worker)["summary"]["flow_count"] == 2


@pytest.mark.parametrize("index", [1, 2, 0xFFFFFFFF])
def test_same_sll2_interface_actual_repeat_remains_detected(worker, index):
    syn = sll2(frame(), index)
    records = parse(classic([syn, syn])).records
    result = report(records, worker)
    assert result["summary"]["flow_count"] == 1
    assert [(issue["pattern"], issue["event_count"]) for issue in result["issues"]] == [
        ("syn_retransmissions", 1)
    ]


def test_pcapng_section_reset_does_not_reuse_sll2_identity(worker):
    from c2hunter_controller.pcap import build_capture_result

    packet = sll2(frame(), 7)
    content = section() + idb() + packet_block(packet)
    content += section(">") + idb(endian=">") + packet_block(packet, endian=">", ordinal=1)
    records = parse(content).records
    assert records[0]["capture_interface_id"] != records[1]["capture_interface_id"]
    result = report(records, worker)
    assert result["issues"] == []
    assert result["summary"]["flow_count"] == 2
    raw = parse(content, retain_packet_bytes=True).records
    assert [row["raw_packet_interface_id"] for row in raw] == [0, 1]
    exported = build_capture_result(list(raw))
    assert exported.capture_format == "PCAPNG"
    assert parse(exported.content, retain_packet_bytes=True).records == raw


def other_link(packet, link):
    if link == 1:
        return packet
    if link == 113:
        return struct.pack("!HHH8sH", 0, 1, 6, b"\x01" * 6, 0x0800) + packet[14:]
    return packet[14:]


@pytest.mark.parametrize("link", [1, 113, 101, 228])
def test_later_non_sll2_idb_keeps_legacy_identity_without_collision(worker, link):
    packet = frame()
    content = section() + idb() + packet_block(sll2(packet, 1))
    content += idb(link) + packet_block(other_link(packet, link), 1, 1)
    records = parse(content).records
    assert records[1]["capture_interface_id"] == 1
    assert records[0]["capture_interface_id"] != 1
    assert report(records, worker)["issues"] == []
    assert (
        parse(classic([other_link(packet, link)], link=link)).records[0]["capture_interface_id"]
        == 0
    )


@pytest.mark.parametrize("pcapng", [False, True])
def test_zero_ifindex_is_unknown_not_a_correlatable_vantage(worker, pcapng):
    packets = [sll2(frame(), 0), sll2(frame(), 0), sll2(frame(), 2)]
    content = (
        section() + idb() + b"".join(packet_block(p, ordinal=i) for i, p in enumerate(packets))
        if pcapng
        else classic(packets)
    )
    records = parse(content).records
    assert [row["capture_interface_id"] for row in records[:2]] == [None, None]
    assert [row["packet_evidence_complete"] for row in records] == [False, False, True]
    # Unknown vantage does not destroy independent packet-local DDoS samples.
    assert all(len(row["ddos_packet_evidence"]["samples"]) == 1 for row in records)
    result = report(records, worker)
    assert result["issues"] == []
    assert result["summary"]["incomplete_records"] == 2
    assert result["summary"]["evaluated_records"] == 1
    assert result["summary"]["coverage_complete"] is False


def test_source_sensor_namespace_remains_part_of_worker_identity(worker):
    content = classic([sll2(frame(), 2)])
    first = parse(content, sensor_id="capture-a").records
    second = parse(content, sensor_id="capture-b").records
    assert first[0]["capture_interface_id"] == second[0]["capture_interface_id"]
    result = report(first + second, worker)
    assert result["issues"] == []
    assert result["summary"]["flow_count"] == 2


@pytest.mark.parametrize("pcapng", [False, True])
@pytest.mark.parametrize("as_bytes", [False, True])
def test_export_preserves_raw_container_identity_packet_order_and_wire_bytes(pcapng, as_bytes):
    from c2hunter_controller.pcap import _legacy_build_capture_result, build_capture_result

    from c2hunter_analysis.pcap import find_pcap_record

    packets = forwarded()
    if pcapng:
        content = section() + idb() + idb(1)
        # Backward timestamps must not reorder packet/container identity.
        content += packet_block(packets[0], ordinal=2)
        content += packet_block(frame(), 1, 0)
        content += packet_block(packets[1], 0, 1)
        expected_containers = [0, 1, 0]
    else:
        content = classic(packets)
        expected_containers = [0] * len(packets)
    records = parse(
        content, retain_packet_bytes=True, retain_packet_bytes_as_bytes=as_bytes
    ).records
    assert [row["raw_packet_interface_id"] for row in records] == expected_containers
    assert [row["raw_packet_index"] for row in records] == list(range(len(records)))
    # Reverse input exercises the existing export ordinal sort, not timestamp sorting.
    exported = build_capture_result(list(reversed(records)))
    oracle = _legacy_build_capture_result(list(reversed(records)))
    assert exported == oracle
    assert exported.capture_format == ("PCAPNG" if pcapng else "PCAP")
    replayed = parse(
        exported.content, retain_packet_bytes=True, retain_packet_bytes_as_bytes=as_bytes
    ).records
    assert replayed == records
    found = find_pcap_record(
        exported.content,
        sensor_id="capture-a",
        internal_networks=["10.0.0.0/8"],
        predicate=lambda row: row["tcp_syn_ack_count"] == int(not pcapng),
    )
    assert found is not None


def test_export_two_source_namespaces_do_not_merge_same_container_and_ifindex(worker):
    from c2hunter_controller.pcap import build_capture_result

    content = classic([sll2(frame(), 2)])
    records = []
    for source in range(2):
        row = dict(parse(content, retain_packet_bytes=True).records[0])
        row["raw_packet_source_order"] = source
        records.append(row)
    exported = build_capture_result(records)
    assert exported.capture_format == "PCAPNG"
    replayed = parse(exported.content).records
    assert replayed[0]["capture_interface_id"] != replayed[1]["capture_interface_id"]
    assert report(replayed, worker)["issues"] == []


def test_truncated_sll2_header_is_skipped_without_changing_packet_ordinals():
    packets = [sll2(frame(), 2), b"\0" * 19, sll2(frame(), 3)]
    parsed = parse(classic(packets), retain_packet_bytes=True)
    assert (
        parsed.captured_packet_count,
        parsed.parsed_packet_count,
        parsed.skipped_packet_count,
    ) == (
        3,
        2,
        1,
    )
    assert [row["raw_packet_index"] for row in parsed.records] == [0, 2]
    assert [row["raw_packet_interface_id"] for row in parsed.records] == [0, 0]


def test_mapping_budget_abstains_without_recycling_or_losing_known_identity(worker, monkeypatch):
    import c2hunter_analysis.pcap as parser

    monkeypatch.setattr(parser, "_MAX_SLL2_INTERFACES", 2)
    packets = [sll2(frame(), i) for i in [2, 3, 4, 4, 2]]
    records = parse(classic(packets)).records
    ids = [row["capture_interface_id"] for row in records]
    assert ids[0] != ids[1] and ids[0] == ids[4]
    assert ids[2:4] == [None, None]
    result = report(records, worker)
    assert result["summary"]["incomplete_records"] == 2
    assert result["summary"]["evaluated_records"] == 3
    assert [(issue["pattern"], issue["event_count"]) for issue in result["issues"]] == [
        ("syn_retransmissions", 1)
    ]


def test_identity_map_hard_cap_and_uint32_namespace_exhaustion():
    from datetime import UTC, datetime

    from c2hunter_analysis.pcap import (
        _MAX_SLL2_INTERFACES,
        _capture_interface_id,
        _CapturedPacket,
    )

    assert _MAX_SLL2_INTERFACES == 65_536
    identities = {}
    now = datetime(2026, 1, 1, tzinfo=UTC)

    def packet(index):
        data = struct.pack("!HHIHBB8s", 0x0800, 0, index, 1, 0, 6, b"\0" * 8)
        return _CapturedPacket(now, 276, data, len(data), 0, 0)

    for index in range(1, _MAX_SLL2_INTERFACES + 1):
        identity = _capture_interface_id(packet(index), identities, 1)
        assert identity == 2**32 - index
    assert _capture_interface_id(packet(_MAX_SLL2_INTERFACES + 1), identities, 1) is None
    assert len(identities) == _MAX_SLL2_INTERFACES
    assert _capture_interface_id(packet(1), identities, 1) == 2**32 - 1
    # No huge file allocation: exercise the arithmetic namespace guard directly.
    sparse = {}
    assert _capture_interface_id(packet(1), sparse, 2**32 - 1) == 2**32 - 1
    assert _capture_interface_id(packet(2), sparse, 2**32 - 1) is None
    assert len(sparse) == 1


def test_packet_limit_and_evidence_opt_out_preserve_existing_contract():
    from c2hunter_analysis.pcap import PcapParseError

    content = classic(forwarded())
    partial = parse(content, max_packets=2, truncate_at_max_packets=True)
    assert partial.truncated and partial.captured_packet_count == 2
    assert partial.records == parse(content).records[:2]
    with pytest.raises(PcapParseError) as error:
        parse(content, max_packets=2)
    assert error.value.code == "PCAP_PACKET_LIMIT_EXCEEDED"
    without = parse_pcap(content, sensor_id="capture-a", internal_networks=["10.0.0.0/8"])
    assert all("capture_interface_id" not in row for row in without.records)
    assert [row["raw_packet_interface_id"] for row in without.records] == [0, 0, 0, 0]
