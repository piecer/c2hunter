"""Deterministic packet fixtures. Explicit --write; tests only compare bytes."""

from __future__ import annotations

import hashlib
import struct
import sys
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from c2hunter_analysis.ddos_job import analyze_ddos_job
from c2hunter_analysis.pcap import parse_pcap
from c2hunter_analysis.pcap_attack_guidance import canonical_bytes

from c2hunter_controller.pcap_attack_guidance_schema import (
    REGISTRY,
    PcapAttackGuidance,
    validate_job_guidance,
)

FIXTURES = Path(__file__).parent / "fixtures/pcap_attack_guidance"
EPOCH = int(datetime(2026, 9, 15, tzinfo=UTC).timestamp())


def packets(
    count: int,
    *,
    start: int = 0,
    span_us: int = 4_000_000,
    sources: int = 20,
    protocol: int = 6,
    flags: int = 2,
    payload: bytes = b"",
    target: str = "10.0.0.10",
    reverse: bool = False,
) -> list[tuple[int, bytes]]:
    result = []
    for index in range(count):
        source = f"198.51.100.{index % sources + 1}"
        destination = target
        source_port, destination_port = 40000 + index % sources, 443
        if reverse:
            source, destination = destination, source
            source_port, destination_port = destination_port, source_port
        if protocol == 6:
            transport = (
                struct.pack(
                    "!HHIIBBHHH",
                    source_port,
                    destination_port,
                    index + 1,
                    0,
                    0x50,
                    flags,
                    64240,
                    0,
                    0,
                )
                + payload
            )
        elif protocol == 17:
            transport = (
                struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
            )
        elif protocol == 1:
            transport = struct.pack("!BBHHH", 8, 0, 0, 1, index) + payload
        else:
            transport = b"\0" * 8
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(transport),
            index,
            0,
            64,
            protocol,
            0,
            ip_address(source).packed,
            ip_address(destination).packed,
        )
        ethernet = b"\0" * 12 + b"\x08\0"
        result.append((start * 1_000_000 + index * span_us // count, ethernet + ip + transport))
    return result


def pcap_bytes(samples: list[tuple[int, bytes]]) -> bytes:
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for micros, packet in sorted(samples, key=lambda item: item[0]):
        second, fraction = divmod(micros, 1_000_000)
        data.extend(struct.pack("<IIII", EPOCH + second, fraction, len(packet), len(packet)))
        data.extend(packet)
    return bytes(data)


def generated() -> dict[str, bytes]:
    syn = packets(1200)
    cases = {
        "positive": syn,
        "mixed": syn + packets(600, start=20, flags=16, payload=b"normal transfer"),
        "low_source": packets(160, sources=1),
        "short": packets(1200, span_us=1_000_000),
        "relative_udp": sum((packets(32, start=i * 5, protocol=17) for i in range(3)), [])
        + packets(160, start=20, protocol=17),
        "quiet_relative_udp": packets(20, span_us=20_000_000, protocol=17)
        + packets(600, start=20, span_us=3_000_000, protocol=17),
        "clean_payload": packets(1200, flags=16, payload=b"normal transfer"),
        "clean_handshake": packets(160) + packets(160, flags=18, reverse=True),
        "cross_boundary_replies": [
            (time + 4_990_000, packet) for time, packet in packets(160, span_us=1000)
        ]
        + [
            (time + 5_010_000, packet)
            for time, packet in packets(160, flags=18, reverse=True, span_us=1000)
        ],
        "preceding_only_replies": packets(160, start=2, span_us=1000)
        + packets(160, start=1, flags=18, reverse=True, span_us=1000),
        "partial_edge_baseline": [
            (4_999_999, packets(1, protocol=17)[0][1]),
            *packets(1, start=5, protocol=17),
            *packets(1, start=10, protocol=17),
            *packets(160, start=15, protocol=17),
        ],
        "stable_udp": sum((packets(32, start=i * 5, protocol=17) for i in range(4)), []),
        "partial": packets(160),
        "unsupported": packets(32, protocol=99),
        "overflow": sum(
            (packets(40, sources=40, target=f"10.1.{i // 256}.{i % 256}") for i in range(257)), []
        ),
        "ack": packets(1000, flags=16),
        "rst": packets(1000, flags=4),
        "icmp": packets(1000, protocol=1),
    }
    outputs: dict[str, bytes] = {}
    for name, samples in cases.items():
        content = pcap_bytes(samples)
        parsed = parse_pcap(
            content,
            sensor_id="fixture-sensor",
            internal_networks=["10.0.0.0/8"],
            max_packets=20000,
            retain_packet_bytes=False,
            retain_network_evidence=True,
        )
        job: dict[str, Any] = {
            "id": f"fixture-{name}",
            "dataset_id": "pcap:" + hashlib.sha256(content).hexdigest(),
            "source_type": "PCAP_UPLOAD",
            "analysis": {"module": "ddos_attack"},
            "internal_networks": ["10.0.0.0/8"],
            "flow_records": parsed.records,
            "ddos_coverage_context": {"capture_partial": True, "parser_skipped_packet_count": 3}
            if name == "partial"
            else {},
        }
        job.update(analyze_ddos_job(job))
        validate_job_guidance(job)
        public = {
            key: job[key]
            for key in (
                "id",
                "dataset_id",
                "source_type",
                "analysis",
                "ddos_attack",
                "pcap_attack_guidance",
            )
        }
        public.update(status="COMPLETED", candidate_count=0)
        outputs[f"{name}.job.json"] = canonical_bytes(public)
        outputs[f"{name}.guide.json"] = canonical_bytes(job["pcap_attack_guidance"])
    outputs["schema.json"] = canonical_bytes(PcapAttackGuidance.model_json_schema())
    outputs["registry.json"] = canonical_bytes(REGISTRY)
    return outputs


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        raise SystemExit("only explicit --write regenerates canonical fixtures")
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, data in generated().items():
        (FIXTURES / name).write_bytes(data)
        print(name, len(data), hashlib.sha256(data).hexdigest())
