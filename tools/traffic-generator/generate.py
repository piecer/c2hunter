#!/usr/bin/env python3
"""Deterministic, dependency-free defensive PCAP fixtures for Scenarios A–G."""

import argparse
import hashlib
import ipaddress
import json
import random
import struct
from pathlib import Path

EPOCH = 1_784_544_000
SEED = 20_260_720


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def udp_packet(
    src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int
) -> bytes:
    src_bytes, dst_bytes = (
        ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed,
    )
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip_head = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        ident & 0xFFFF,
        0,
        64,
        17,
        0,
        src_bytes,
        dst_bytes,
    )
    ip_head = ip_head[:10] + struct.pack("!H", checksum(ip_head)) + ip_head[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip_head + udp


def write_pcap(path: Path, packets):
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, packet in packets:
            sec = int(timestamp)
            micros = int(round((timestamp - sec) * 1_000_000))
            output.write(struct.pack("<IIII", sec, micros, len(packet), len(packet)))
            output.write(packet)


def scenarios(rng: random.Random):
    c2, target = "203.0.113.10", "198.51.100.20"
    result = {}
    a = []
    for host in range(1, 51):
        ip = f"10.0.0.{host}"
        for sample in range(6):
            when = EPOCH + sample * 30 + rng.uniform(-3, 3) + host / 1000
            a.append(
                (
                    when,
                    udp_packet(
                        ip, c2, 40000 + host, 443, b"beacon-v1", host * 10 + sample
                    ),
                )
            )
    result["A"] = (
        a,
        {
            "minimum_score": 60,
            "evidence": ["PERIODIC_BEACON"],
            "distinct_internal_hosts": 50,
        },
    )
    b = []
    for host in range(1, 101):
        ip = f"10.1.{(host - 1) // 254}.{(host - 1) % 254 + 1}"
        command_at = EPOCH + host / 1000
        b.append((command_at, udp_packet(c2, ip, 8443, 41000 + host, b"cmd", host)))
        b.append(
            (
                command_at + 15,
                udp_packet(c2, ip, 8443, 41000 + host, b"cmd", host + 10_000),
            )
        )
        lag = rng.uniform(1, 3)
        for burst in range(10):
            b.append(
                (
                    command_at + lag + burst / 100,
                    udp_packet(
                        ip,
                        target,
                        41000 + host,
                        53,
                        bytes([host % 256]) * 256,
                        host * 20 + burst,
                    ),
                )
            )
    result["B"] = (
        b,
        {
            "minimum_score": 80,
            "evidence": ["COMMAND_ATTACK_CORRELATION", "MULTI_SENSOR_CONTEXT"],
            "attack_target": target,
            "sensors": ["sensor-a", "sensor-b"],
        },
    )
    c = []
    for host in range(1, 51):
        ip = f"10.2.0.{host}"
        c += [
            (
                EPOCH + host,
                udp_packet(ip, "192.0.2.53", 45000 + host, 53, b"example.test", host),
            ),
            (
                EPOCH + host + 0.2,
                udp_packet(ip, "192.0.2.123", 45000 + host, 123, b"ntp", host + 100),
            ),
        ]
    result["C"] = (c, {"maximum_score": 39, "adjustment": "PUBLIC_DNS_NTP"})
    d = [
        (
            EPOCH + host / 10,
            udp_packet(
                f"10.3.0.{host}",
                "192.0.2.80",
                46000 + host,
                443,
                f"sni-{host}.cdn.test".encode(),
                host,
            ),
        )
        for host in range(1, 51)
    ]
    result["D"] = (d, {"maximum_score": 39, "reason": "DIVERSE_SNI"})
    duplicate = udp_packet("10.4.0.1", c2, 47000, 443, b"mirrored", 77)
    result["E"] = (
        [(EPOCH, duplicate), (EPOCH, duplicate)],
        {
            "logical_packet_count": 1,
            "sensor_observations": 2,
            "sensors": ["sensor-a", "sensor-b"],
        },
    )
    f = []
    for repetition in range(2):
        for host in range(1, 4):
            f.append(
                (
                    EPOCH + repetition * 30 + host / 1000,
                    udp_packet(f"10.5.0.{host}", c2, 48000 + host, 443, b"clock", host),
                )
            )
            f.append(
                (
                    EPOCH + repetition * 30 + 3 + host / 1000,
                    udp_packet(
                        f"10.5.0.{host + 100}",
                        c2,
                        48100 + host,
                        443,
                        b"clock",
                        host + 100,
                    ),
                )
            )
    result["F"] = (
        f,
        {
            "clock_skew_seconds": 3,
            "sensor_status": "DEGRADED",
            "warning": "CLOCK_SKEW",
            "confidence_reduced": True,
        },
    )
    g = [
        (
            float(EPOCH + i),
            udp_packet(f"10.6.0.{i}", c2, 49000 + i, 443, b"sensor-a-only", i),
        )
        for i in range(1, 21)
    ]
    result["G"] = (
        g,
        {
            "status": "PARTIALLY_COMPLETED",
            "completed_sensors": ["sensor-a"],
            "failed_sensors": ["sensor-b"],
            "loss_reported": True,
        },
    )
    return result


def fixture_metadata(
    name: str, packets: list[tuple[float, bytes]]
) -> dict[str, object]:
    """Return explicit capture/operations context that a PCAP cannot encode."""
    if name == "E":
        sensor_ids = ["sensor-a", "sensor-b"]
    elif name == "B":
        sensor_ids = []
        for _timestamp, packet in packets:
            source = ipaddress.ip_address(packet[26:30])
            destination = ipaddress.ip_address(packet[30:34])
            internal_network = ipaddress.ip_network("10.0.0.0/8")
            internal = source if source in internal_network else destination
            sensor_ids.append(
                "sensor-a" if int(str(internal).split(".")[-1]) <= 50 else "sensor-b"
            )
    elif name == "F":
        sensor_ids = [
            "sensor-b" if packet[29] > 100 else "sensor-a"
            for _timestamp, packet in packets
        ]
    else:
        sensor_ids = ["sensor-a"] * len(packets)

    metadata: dict[str, object] = {"observations": {"packet_sensor_ids": sensor_ids}}
    if name == "C":
        metadata["analysis_context"] = {
            "public_dns_ntp_servers": ["192.0.2.53", "192.0.2.123"]
        }
    elif name == "D":
        metadata["analysis_context"] = {"cdn_domain_suffixes": ["cdn.test"]}
    elif name == "F":
        metadata["operations"] = {
            "completed_sensors": ["sensor-a", "sensor-b"],
            "failed_sensors": [],
            "sensors": {
                "sensor-a": {"status": "HEALTHY", "clock_offset_ms": 0},
                "sensor-b": {"status": "DEGRADED", "clock_offset_ms": 3000},
            },
        }
    elif name == "G":
        metadata["operations"] = {
            "completed_sensors": ["sensor-a"],
            "failed_sensors": ["sensor-b"],
            "sensors": {
                "sensor-a": {"status": "HEALTHY", "observed_packets": len(packets)},
                "sensor-b": {
                    "status": "DISCONNECTED",
                    "observed_packets": 0,
                    "loss_reason": "sensor disconnected during collection",
                },
            },
        }
    return metadata


def generate_all(output_dir: Path, seed: int = SEED):
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_scenarios: dict[str, dict[str, object]] = {}
    manifest: dict[str, object] = {
        "seed": seed,
        "format": "pcap",
        "scenarios": generated_scenarios,
    }
    for name, (packets, oracle) in scenarios(random.Random(seed)).items():
        packets.sort(key=lambda item: item[0])
        path = output_dir / f"scenario-{name.lower()}.pcap"
        write_pcap(path, packets)
        metadata = {
            "scenario": name,
            "seed": seed,
            "packet_count": len(packets),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "oracle": oracle,
        }
        metadata.update(fixture_metadata(name, packets))
        (output_dir / f"scenario-{name.lower()}.json").write_text(
            json.dumps(metadata, indent=2) + "\n"
        )
        generated_scenarios[name] = metadata
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return generated_scenarios


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("testdata/generated"))
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    result = generate_all(args.output, args.seed)
    print(f"generated {len(result)} deterministic scenarios in {args.output}")


if __name__ == "__main__":
    main()
