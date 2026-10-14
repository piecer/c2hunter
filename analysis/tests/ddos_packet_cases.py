"""Bounded real PCAP/PCAPNG fixtures; never opens a capture interface."""

import struct
from ipaddress import ip_address

from c2hunter_analysis.pcap import parse_pcap

BASE = 1784544000
QUESTION = b"\x01a\x00\x00\x01\x00\x01"
DNS_RESPONSE = (
    bytes.fromhex("123481800001000100000000")
    + QUESTION
    + bytes.fromhex("c00c000100010000003c0004c0000201")
)
DNS_TRUNCATED = bytes.fromhex("123483800001000000000000") + QUESTION


def ipudp(src, dst, sport, dport, body):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(body), 0) + body
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(udp),
            1,
            0,
            64,
            17,
            0,
            ip_address(src).packed,
            ip_address(dst).packed,
        )
        + udp
    )


def classic_rows(events):
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for second, micro, ip in events:
        data.extend(struct.pack("<IIII", second, micro, len(ip), len(ip)) + ip)
    return list(
        parse_pcap(
            bytes(data),
            sensor_id="review",
            internal_networks=["10.0.0.0/8"],
            retain_packet_bytes=False,
            retain_network_evidence=True,
        ).records
    )


def flood(body, sport, sources=64, per_source=16):
    return classic_rows(
        (BASE + n % 4, 0, ipudp(f"198.51.100.{s}", "10.0.0.10", sport, 53000, body))
        for n in range(per_source)
        for s in range(1, sources + 1)
    )


def block(kind, body):
    size = 12 + len(body)
    assert size % 4 == 0
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def ng_rows(events, offset=0):
    data = bytearray(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    for _ in range(2):
        options = struct.pack("<HHq", 14, 8, offset) + bytes(4)
        data += block(1, struct.pack("<HHI", 101, 0, 65535) + options)
    for iface, sec, micro, ip in events:
        stamp = sec * 1000000 + micro
        body = (
            struct.pack("<IIIII", iface, stamp >> 32, stamp & 0xFFFFFFFF, len(ip), len(ip))
            + ip
            + bytes((-len(ip)) % 4)
        )
        data += block(6, body)
    return list(
        parse_pcap(
            bytes(data),
            sensor_id="review",
            internal_networks=["10.0.0.0/8"],
            retain_packet_bytes=False,
            retain_network_evidence=True,
        ).records
    )
