"""Real packet/FlowRecord fixtures; public transport reuses the epoch harness only."""

from __future__ import annotations


import struct
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / p) for p in ("analysis/tests", "web/tests")]
import test_network_anomaly as packets  # noqa: E402
from network_epoch_fixture import _public_case, canonical  # noqa: E402


def peer_frame(peer: int, **kwargs) -> bytes:
    wire = bytearray(packets.frame(**kwargs))
    reverse = kwargs.get("reverse", False)
    offset = 26 if reverse else 30
    wire[offset : offset + 4] = bytes((203, 0, 113, peer))
    wire[24:26] = b"\0\0"
    wire[24:26] = struct.pack("!H", packets.internet_checksum(bytes(wire[14:34])))
    protocol = wire[23]
    checksum_offset = 34 + {6: 16, 17: 6}.get(protocol, 2)
    wire[checksum_offset : checksum_offset + 2] = b"\0\0"
    pseudo = (
        bytes(wire[26:34]) + struct.pack("!BBH", 0, protocol, len(wire) - 34)
        if protocol in (6, 17)
        else b""
    )
    wire[checksum_offset : checksum_offset + 2] = struct.pack(
        "!H", packets.internet_checksum(pseudo + bytes(wire[34:])) or 65535
    )
    assert packets.internet_checksum(bytes(wire[14:34])) == 0
    assert packets.internet_checksum(pseudo + bytes(wire[34:])) == 0
    return bytes(wire)


def capture(udp_groups: int = 20, *, all_families: bool = False) -> bytes:
    frames = [
        peer_frame(peer, protocol=17, payload=b"query")
        for peer in range(1, udp_groups + 1)
        for _ in range(4)
    ]
    frames += [peer_frame(240), peer_frame(240, flags=20, ack=101, reverse=True)]
    if all_families:
        data = peer_frame(242, flags=24, seq=101, payload=b"abc")
        ack = peer_frame(242, flags=16, seq=500, ack=101, reverse=True)
        frames += [peer_frame(241), peer_frame(241), data, data, ack, ack]
        frames += [peer_frame(243, protocol=1, reverse=True)]
    return packets.capture(*frames, start_time=datetime.fromtimestamp(1700000000, UTC))


def records(content: bytes):
    from c2hunter_analysis.pcap import parse_pcap
    from c2hunter_controller.schemas import FlowRecord

    parsed = parse_pcap(
        content,
        sensor_id="family-fixture",
        internal_networks=["10.0.0.0/8"],
        retain_network_evidence=True,
        retain_packet_bytes=False,
    )
    return [
        FlowRecord.model_validate(row).model_dump(mode="json") for row in parsed.records
    ]


def build_bundle():
    from c2hunter_analysis.network_report import analyze_network_report
    from c2hunter_controller.network_ai import build_network_input

    cases = {"dominant": _public_case("family-dominant", capture())}
    for name, rows in {
        "empty": [],
        "normal": records(
            packets.capture(
                packets.frame(), packets.frame(flags=18, ack=101, reverse=True)
            )
        ),
    }.items():
        report = analyze_network_report(rows)
        cases[name] = {"report": report, "ai": build_network_input(report)}
    for limit in (1, 5, 6, 7, 100):
        report = analyze_network_report(
            records(capture(100, all_families=True)), max_issues=limit
        )
        cases[f"limit-{limit}"] = {"report": report, "ai": build_network_input(report)}
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in list(sys.modules.items())
        if name.startswith(
            ("c2hunter_analysis", "c2hunter_controller", "c2hunter_worker")
        )
        and getattr(module, "__file__", None)
    }
    assert origins and all(Path(path).is_relative_to(ROOT) for path in origins.values())
    return {
        "cases": cases,
        "origins": origins,
        "maximum_case": "analyzer-only, not API limit",
    }


if __name__ == "__main__":
    print(canonical(build_bundle()))
