#!/usr/bin/env python3
"""Measure bounded DDoS analysis on deterministic synthetic flow records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from c2hunter_analysis import ddos_attack

MAX_RELEASE_SECONDS = 180
MAX_RELEASE_RSS_MIB = 8192
SOURCE_FILES = (
    "analysis/src/c2hunter_analysis/ddos_attack.py",
    "tools/benchmark/ddos_analysis.py",
)

START = datetime(2026, 9, 15, tzinfo=UTC)


def positive_bounded_records(value: str) -> int:
    count = int(value)
    if not 1 <= count <= ddos_attack.MAX_SCANNED_RECORDS:
        raise argparse.ArgumentTypeError(
            f"records must be between 1 and {ddos_attack.MAX_SCANNED_RECORDS}"
        )
    return count


def records(count: int):
    for index in range(count):
        source = index % 250 + 1
        yield {
            "sensor_id": "benchmark-sensor",
            "timestamp": (START + timedelta(milliseconds=index)).isoformat(),
            "source_ip": f"198.51.100.{source}",
            "destination_ip": "10.0.0.10",
            "source_port": 40000 + index % 20000,
            "destination_port": 443,
            "protocol": "TCP",
            "direction": "INBOUND",
            "packet_count": 1,
            "total_bytes": 60,
            "duration_seconds": 0,
            "tcp_flags": {"syn": 1, "ack": 0, "rst": 0, "fin": 0},
            "tcp_flags_observed": True,
            "tcp_syn_count": 1,
            "tcp_syn_only_count": 1,
            "packet_evidence_complete": True,
        }


def boundary_record(index: int, *, target: str = "10.0.0.10", packets: int = 1):
    return {
        "sensor_id": "benchmark-sensor",
        "timestamp": (START + timedelta(seconds=index)).isoformat(),
        "source_ip": f"198.51.100.{index % 250 + 1}",
        "destination_ip": target,
        "source_port": 40000 + index % 20000,
        "destination_port": 443,
        "protocol": "UDP",
        "direction": "INBOUND",
        "packet_count": packets,
        "total_bytes": packets * 60,
        "duration_seconds": 1,
        "packet_evidence_complete": packets == 1,
    }


def run_boundary_probes() -> dict[str, bool]:
    input_report = ddos_attack.analyze_ddos_attack(
        (
            boundary_record(index)
            for index in range(ddos_attack.MAX_SCANNED_RECORDS + 1)
        ),
        internal_cidrs=("10.0.0.0/8",),
    )
    target_report = ddos_attack.analyze_ddos_attack(
        (
            boundary_record(
                index,
                target=f"10.10.{index // 256}.{index % 256}",
            )
            for index in range(ddos_attack.MAX_TARGETS + 1)
        ),
        internal_cidrs=("10.0.0.0/8",),
    )
    bucket_report = ddos_attack.analyze_ddos_attack(
        (
            boundary_record(index)
            for index in range(ddos_attack.MAX_BUCKETS_PER_TARGET + 1)
        ),
        internal_cidrs=("10.0.0.0/8",),
    )
    finding_report = ddos_attack.analyze_ddos_attack(
        (
            boundary_record(
                second,
                target=f"10.20.0.{target + 1}",
                packets=10,
            )
            for target in range(ddos_attack.MAX_FINDINGS + 1)
            for second in range(ddos_attack.MIN_TARGET_RECORDS)
        ),
        internal_cidrs=("10.0.0.0/8",),
        parameters={
            "ddos_min_packets_per_second": 1,
            "ddos_min_bits_per_second": 1,
        },
    )
    return {
        "input_limit_plus_one": "INPUT_RECORD_LIMIT_REACHED"
        in input_report["warnings"],
        "target_limit_plus_one": "TARGET_LIMIT_REACHED" in target_report["warnings"],
        "bucket_limit_plus_one": "BUCKET_LIMIT_REACHED" in bucket_report["warnings"],
        "finding_limit_plus_one": (
            "FINDING_LIMIT_REACHED" in finding_report["warnings"]
            and finding_report["summary"]["displayed_finding_count"]
            == ddos_attack.MAX_FINDINGS
        ),
    }


def revision() -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git executable is required for benchmark provenance")
    completed = subprocess.run(  # noqa: S603 -- resolved executable and fixed arguments
        [git, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def source_files_sha256() -> dict[str, str]:
    return {
        name: hashlib.sha256(
            (Path(__file__).parents[2] / name).read_bytes()
        ).hexdigest()
        for name in SOURCE_FILES
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=positive_bounded_records, default=1_000_000)
    parser.add_argument("--iterations", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    elapsed_samples: list[float] = []
    final_report = None
    started_at = datetime.now(UTC)
    for _ in range(args.iterations):
        started = perf_counter()
        report = ddos_attack.analyze_ddos_attack(
            records(args.records), internal_cidrs=("10.0.0.0/8",)
        )
        elapsed_samples.append(round(perf_counter() - started, 6))
        if report["summary"]["evaluated_records"] != args.records:
            raise RuntimeError(
                "benchmark analyzer did not evaluate every requested record"
            )
        if "INPUT_RECORD_LIMIT_REACHED" in report["warnings"]:
            raise RuntimeError("benchmark unexpectedly reached the input limit")
        final_report = report
    if final_report is None:
        raise RuntimeError("benchmark produced no report")
    boundary_probes = run_boundary_probes()
    peak_rss_mib = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 3)
    if max(elapsed_samples) > MAX_RELEASE_SECONDS:
        raise RuntimeError("DDoS benchmark exceeded the 180-second release ceiling")
    if peak_rss_mib > MAX_RELEASE_RSS_MIB:
        raise RuntimeError("DDoS benchmark exceeded the 8-GiB RSS release ceiling")
    if not all(boundary_probes.values()):
        raise RuntimeError("DDoS benchmark boundary probe failed")
    limits = {
        "max_input_records": ddos_attack.MAX_SCANNED_RECORDS,
        "max_targets": ddos_attack.MAX_TARGETS,
        "max_buckets_per_target": ddos_attack.MAX_BUCKETS_PER_TARGET,
        "max_findings": ddos_attack.MAX_FINDINGS,
        "min_target_records": ddos_attack.MIN_TARGET_RECORDS,
    }
    result = {
        "source_revision": revision(),
        "source_files_sha256": source_files_sha256(),
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor() or "unreported",
            "cpu_count": os.cpu_count(),
        },
        "input_records": args.records,
        "iterations": args.iterations,
        "elapsed_seconds": elapsed_samples,
        "mean_elapsed_seconds": round(sum(elapsed_samples) / len(elapsed_samples), 6),
        "peak_rss_mib": peak_rss_mib,
        "effective_parameters": dict(sorted(ddos_attack._DEFAULTS.items())),
        "boundary_probes": boundary_probes,
        "evaluated_records": final_report["summary"]["evaluated_records"],
        "target_count": final_report["summary"]["target_count"],
        "finding_count": final_report["summary"]["finding_count"],
        "verdict": final_report["verdict"],
        "warnings": final_report["warnings"],
        "limits": limits,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    args.markdown.write_text(
        "# DDoS analysis benchmark\n\n"
        f"- Source revision: `{result['source_revision']}`\n"
        f"- Input records: {result['input_records']:,}\n"
        f"- Iterations: {result['iterations']} ({', '.join(map(str, elapsed_samples))} seconds)\n"
        f"- Mean elapsed: {result['mean_elapsed_seconds']} seconds\n"
        f"- Peak RSS: {result['peak_rss_mib']} MiB\n"
        f"- Runtime: Python {result['runtime']['python']} on {result['runtime']['system']} {result['runtime']['machine']}\n"
        f"- Targets/findings: {result['target_count']}/{result['finding_count']}\n"
        f"- Verdict: `{result['verdict']}`\n"
        f"- Warnings: {', '.join(result['warnings']) or 'none'}\n"
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
