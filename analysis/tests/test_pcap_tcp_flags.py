import struct

from c2hunter_analysis.pcap import parse_pcap


def classic_pcap(frame: bytes) -> bytes:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1, 0, len(frame), len(frame))
    return global_header + packet_header + frame


def ethernet_ipv4_tcp(flags: int) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    tcp = struct.pack(
        "!HHIIBBHHH",
        50000,
        443,
        1,
        0,
        5 << 4,
        flags,
        8192,
        0,
        0,
    )
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0,
        64,
        6,
        0,
        bytes((10, 0, 0, 10)),
        bytes((203, 0, 113, 10)),
    )
    return ethernet + ipv4 + tcp


def test_parse_pcap_exports_tcp_flag_combinations() -> None:
    result = parse_pcap(
        classic_pcap(ethernet_ipv4_tcp(0x02)),
        sensor_id="sensor-a",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
    )
    record = result.records[0]
    assert record["direction"] == "OUTBOUND"
    assert record["tcp_flags_observed"] is True
    assert record["tcp_syn_count"] == 1
    assert record["tcp_syn_only_count"] == 1
    assert record["tcp_ack_count"] == 0
    assert record["tcp_ack_only_count"] == 0
