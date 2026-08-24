#!/usr/bin/env python3
"""Deterministic Classic PCAP export baseline and report comparator."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import random
import resource
import struct
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from c2hunter_analysis.pcap import bounded_pcap_prefix, parse_pcap
from c2hunter_controller.pcap import build_capture_result, filter_records

STAGES = ("source_read", "hash", "frame", "decode", "filter", "write", "save", "total")
IMPLEMENTATION = "classic-materialized-v1"
DEFAULT_SEED = 20260720
_T = TypeVar("_T")


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _udp_packet(index: int, rng: random.Random) -> bytes:
    source = ipaddress.ip_address(
        f"10.0.{(index // 254) % 256}.{index % 254 + 1}"
    ).packed
    destination = ipaddress.ip_address("203.0.113.77").packed
    payload = rng.randbytes(48 + index % 32)
    udp = (
        struct.pack("!HHHH", 40_000 + index % 20_000, 443, 8 + len(payload), 0)
        + payload
    )
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        index % 65_536,
        0,
        64,
        17,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + udp


def classic_pcap(packet_count: int, seed: int) -> bytes:
    if packet_count < 1:
        raise ValueError("packet_count must be positive")
    rng = random.Random(seed)  # noqa: S311 -- deterministic benchmark input, not cryptography
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
    epoch = int(datetime(2026, 7, 20, tzinfo=UTC).timestamp())
    for index in range(packet_count):
        packet = _udp_packet(index, rng)
        output.extend(
            struct.pack(
                "<IIII", epoch + index, index % 1_000_000, len(packet), len(packet)
            )
        )
        output.extend(packet)
    return bytes(output)


def workload_fingerprint(*, packet_count: int, seed: int, source_sha256: str) -> str:
    """Identify deterministic input independently of the implementation under test."""
    encoded = json.dumps(
        {"packet_count": packet_count, "seed": seed, "source_sha256": source_sha256},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _rss_bytes() -> int:
    """Return peak RSS using the documented Linux and macOS ru_maxrss units."""
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform.startswith("linux"):
        return value * 1024
    if sys.platform == "darwin":
        return value
    raise RuntimeError(f"unsupported ru_maxrss units on platform {sys.platform!r}")


def _stage(
    stages: dict[str, dict[str, int | float]],
    name: str,
    operation: Callable[[], _T],
    *,
    packets: int = 0,
    bytes_count: int = 0,
) -> _T:
    started = time.perf_counter()
    result = operation()
    elapsed = time.perf_counter() - started
    row = stages[name]
    row["duration_seconds"] = float(row["duration_seconds"]) + elapsed
    row["packets"] = int(row["packets"]) + packets
    row["bytes"] = int(row["bytes"]) + bytes_count
    row["rss_bytes"] = max(int(row["rss_bytes"]), _rss_bytes())
    return result


def run(
    packet_count: int, output_dir: Path, seed: int = DEFAULT_SEED
) -> dict[str, Any]:
    """Run the bounded materialized export path and write a JSON baseline report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    source = classic_pcap(packet_count, seed)
    stages: dict[str, dict[str, int | float]] = {
        stage: {
            "duration_seconds": 0.0,
            "packets": 0,
            "bytes": 0,
            "rss_bytes": _rss_bytes(),
        }
        for stage in STAGES
    }
    total_started = time.perf_counter()

    content = _stage(
        stages,
        "source_read",
        lambda: bytes(bytearray(source)),
        packets=packet_count,
        bytes_count=len(source),
    )
    source_digest = _stage(
        stages,
        "hash",
        lambda: hashlib.sha256(content).hexdigest(),
        bytes_count=len(content),
    )
    prefix = _stage(
        stages,
        "frame",
        lambda: bounded_pcap_prefix(content, len(content), max_packets=packet_count),
        packets=packet_count,
        bytes_count=len(content),
    )
    parsed = _stage(
        stages,
        "decode",
        lambda: parse_pcap(
            prefix.content,
            sensor_id="benchmark-sensor",
            internal_networks=["10.0.0.0/8"],
            max_packets=packet_count,
            retain_packet_bytes=True,
            retain_packet_bytes_as_bytes=True,
            allow_no_supported_packets=True,
        ),
        packets=prefix.packet_count,
        bytes_count=prefix.scanned_bytes,
    )
    records = _stage(
        stages,
        "filter",
        lambda: filter_records(parsed.records, {}, internal_networks=["10.0.0.0/8"]),
        packets=parsed.captured_packet_count,
        bytes_count=prefix.scanned_bytes,
    )
    capture = _stage(
        stages,
        "write",
        lambda: build_capture_result(records, max_output_bytes=len(content)),
        packets=len(records),
    )
    output_digest = _stage(
        stages,
        "hash",
        lambda: hashlib.sha256(capture.content).hexdigest(),
        bytes_count=len(capture.content),
    )
    artifact = output_dir / "pcap-export-baseline.pcap"
    _stage(
        stages,
        "save",
        lambda: artifact.write_bytes(capture.content),
        packets=capture.exported_packet_count,
        bytes_count=len(capture.content),
    )
    total_elapsed = time.perf_counter() - total_started
    stages["write"]["bytes"] = len(capture.content)
    stages["total"] = {
        "duration_seconds": total_elapsed,
        "packets": capture.exported_packet_count,
        "bytes": len(capture.content),
        "rss_bytes": _rss_bytes(),
    }

    report: dict[str, Any] = {
        "schema_version": 1,
        "implementation": IMPLEMENTATION,
        "workload": {
            "capture_format": "PCAP",
            "packet_count": packet_count,
            "seed": seed,
            "source_sha256": source_digest,
            "output_sha256": output_digest,
            "fingerprint": workload_fingerprint(
                packet_count=packet_count,
                seed=seed,
                source_sha256=source_digest,
            ),
        },
        "stages": stages,
        "counters": {
            "packets": {
                "source": packet_count,
                "scanned": parsed.captured_packet_count,
                "matched": capture.matched_packet_count,
                "exported": capture.exported_packet_count,
                "omitted": capture.omitted_packet_count,
            },
            "bytes": {"source": len(content), "output": len(capture.content)},
        },
        "peak_rss_bytes": _rss_bytes(),
    }
    Path(output_dir, "pcap-export-baseline.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def compare_reports(
    current: dict[str, Any], baseline: dict[str, Any]
) -> dict[str, Any]:
    """Compare timings only when deterministic workload fingerprints match."""
    current_fingerprint = str(current["workload"]["fingerprint"])
    baseline_fingerprint = str(baseline["workload"]["fingerprint"])
    compatible = current_fingerprint == baseline_fingerprint
    if not compatible:
        return {
            "compatible": False,
            "workload_fingerprint": current_fingerprint,
            "baseline_workload_fingerprint": baseline_fingerprint,
            "duration_ratio_by_stage": {},
            "total_duration_ratio": None,
        }
    ratios = {
        stage: float(current["stages"][stage]["duration_seconds"])
        / max(float(baseline["stages"][stage]["duration_seconds"]), 1e-12)
        for stage in STAGES
    }
    return {
        "compatible": True,
        "workload_fingerprint": current_fingerprint,
        "baseline_workload_fingerprint": baseline_fingerprint,
        "duration_ratio_by_stage": ratios,
        "total_duration_ratio": ratios["total"],
        "peak_rss_ratio": float(current["peak_rss_bytes"])
        / max(float(baseline["peak_rss_bytes"]), 1.0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output", type=Path, default=Path("artifacts"))
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    report = run(args.packets, args.output, args.seed)
    payload: dict[str, Any] = report
    if args.compare is not None:
        baseline = json.loads(args.compare.read_text(encoding="utf-8"))
        payload = {"report": report, "comparison": compare_reports(report, baseline)}
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
