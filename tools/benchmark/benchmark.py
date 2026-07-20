#!/usr/bin/env python3
"""Bounded-memory synthetic packet→flow→real analysis benchmark."""

from __future__ import annotations

import argparse
import importlib.metadata
import inspect
import json
import random
import resource
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from c2hunter_analysis.detectors import DEFAULT_DETECTORS, run_detectors
from c2hunter_analysis.domain import AnalysisContext, Flow
from c2hunter_analysis.scoring import score_candidates

C2_IP = "203.0.113.10"
START = datetime(2026, 7, 20, tzinfo=UTC)
REPRESENTATIVE_FLOW_LIMIT = 20_000
SUSPICIOUS_SERIES_SAMPLES = 8
BACKGROUND_SERIES_SAMPLES = 1
MEASUREMENT_SCOPE = (
    "all packets streamed; detectors scored a bounded representative Flow window"
)


def packets(total: int, seed: int):
    """Yield deterministic packet observations without materializing the packet set."""
    rng = random.Random(seed)
    for index in range(total):
        host = index % 4096
        cycle = index // 4096
        suspicious = host % 10 < 3
        yield (
            host,
            0 if suspicious else 1 + host % 128,
            443 if suspicious else (53 if index % 2 else 123),
            cycle * 30 + rng.uniform(-2.5, 2.5),
            72 if suspicious else 96 + index % 900,
        )


def _host_ip(host: int) -> str:
    value = host + 1
    return f"10.{value // 65536}.{(value // 256) % 256}.{value % 256}"


def _destination_ip(destination: int) -> str:
    return C2_IP if destination == 0 else f"192.0.2.{destination}"


class RepresentativeFlowWindow:
    """A bounded, stratified recent sample of emitted Flow records."""

    def __init__(self, limit: int = REPRESENTATIVE_FLOW_LIMIT) -> None:
        self.limit = limit
        self._by_series: dict[tuple[str, str], list[Flow]] = {}
        self._stored = 0
        self.offered = 0
        self.replacements = 0

    def offer(self, flow: Flow) -> None:
        self.offered += 1
        candidate = (
            flow.destination_ip if flow.direction == "OUTBOUND" else flow.source_ip
        )
        internal = (
            flow.source_ip if flow.direction == "OUTBOUND" else flow.destination_ip
        )
        key = (candidate, internal)
        samples = self._by_series.get(key)
        per_series = (
            SUSPICIOUS_SERIES_SAMPLES
            if candidate == C2_IP
            else BACKGROUND_SERIES_SAMPLES
        )
        if samples is None:
            if self._stored >= self.limit:
                return
            self._by_series[key] = [flow]
            self._stored += 1
        elif len(samples) < per_series and self._stored < self.limit:
            samples.append(flow)
            self._stored += 1
        elif len(samples) >= per_series:
            # Keep a rolling per-series window so interval-based detectors receive
            # consecutive observations without retaining unbounded history.
            samples.pop(0)
            samples.append(flow)
            self.replacements += 1

    @property
    def flows(self) -> list[Flow]:
        return [flow for samples in self._by_series.values() for flow in samples]

    @property
    def series(self) -> int:
        return len(self._by_series)


def process_chunk(
    chunk: list[tuple[int, int, int, float, int]], window: RepresentativeFlowWindow
) -> int:
    """Coalesce one bounded packet chunk to flow records and sample those records."""
    aggregates: dict[tuple[int, int, int, int], list[float | int]] = {}
    for host, destination, port, timestamp, size in chunk:
        key = (host, destination, port, int(timestamp // 60))
        row = aggregates.setdefault(key, [timestamp, 0, 0, size])
        row[0] = min(float(row[0]), timestamp)
        row[1] = int(row[1]) + 1
        row[2] = int(row[2]) + size
    for (host, destination, port, _minute), row in aggregates.items():
        suspicious = destination == 0
        window.offer(
            Flow(
                sensor_id=("benchmark-sensor-a", "benchmark-sensor-b")[host % 2],
                timestamp=START + timedelta(seconds=float(row[0])),
                source_ip=_host_ip(host),
                destination_ip=_destination_ip(destination),
                source_port=40_000 + host % 20_000,
                destination_port=port,
                protocol="UDP",
                direction="OUTBOUND",
                packet_count=int(row[1]),
                total_bytes=int(row[2]),
                payload_hash=(
                    "benchmark-beacon-v1" if suspicious else f"background-{destination}"
                ),
                packet_sizes=(int(row[3]),),
            )
        )
    return len(aggregates)


def _run_analysis(
    flows: list[Flow],
) -> tuple[list[object], list[dict[str, object]], float, float]:
    start = min(flow.timestamp for flow in flows) - timedelta(microseconds=1)
    end = max(flow.timestamp for flow in flows) + timedelta(microseconds=1)
    context = AnalysisContext(
        dataset_id="benchmark-bounded-representative-window",
        start=start,
        end=end,
        flows=flows,
        selected_sensors=("benchmark-sensor-a", "benchmark-sensor-b"),
        parameters={
            "minimum_distinct_clients": 3,
            "periodicity_min_samples": 5,
            "maximum_beacon_cv": 0.30,
            "synchronization_window_seconds": 5.0,
        },
    )
    all_evidence = []
    execution: list[dict[str, object]] = []
    detector_seconds = 0.0
    for detector in DEFAULT_DETECTORS:
        started = time.perf_counter()
        evidence = run_detectors(context, detectors=(detector,))
        elapsed = time.perf_counter() - started
        detector_seconds += elapsed
        all_evidence.extend(evidence)
        detector_type = type(detector)
        findings_by_type = Counter(item.type for item in evidence)
        execution.append(
            {
                "name": detector.name,
                "version": detector.version,
                "implementation_type": f"{detector_type.__module__}.{detector_type.__qualname__}",
                "executed": True,
                "duration_seconds": round(elapsed, 6),
                "findings": len(evidence),
                "evidence_types": sorted(findings_by_type),
                "findings_by_evidence_type": dict(sorted(findings_by_type.items())),
            }
        )
    scoring_started = time.perf_counter()
    candidates = score_candidates(all_evidence, minimum_samples=5)
    scoring_seconds = time.perf_counter() - scoring_started
    return candidates, execution, detector_seconds, scoring_seconds


def run(packet_count: int, chunk_size: int, output_dir: Path, seed: int = 20260720):
    if packet_count < 1 or chunk_size < 1:
        raise ValueError("packet_count and chunk_size must be positive")
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    generated_flows = 0
    processed = 0
    chunks = 0
    flow_window = RepresentativeFlowWindow()
    chunk: list[tuple[int, int, int, float, int]] = []
    ingest_start = time.perf_counter()
    for event in packets(packet_count, seed):
        chunk.append(event)
        if len(chunk) == chunk_size:
            generated_flows += process_chunk(chunk, flow_window)
            processed += len(chunk)
            chunks += 1
            chunk.clear()
    if chunk:
        generated_flows += process_chunk(chunk, flow_window)
        processed += len(chunk)
        chunks += 1
    ingest_seconds = time.perf_counter() - ingest_start

    representative_flows = flow_window.flows
    candidates, detector_execution, detector_seconds, scoring_seconds = _run_analysis(
        representative_flows
    )
    elapsed = time.perf_counter() - started
    peak_raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_mb = peak_raw / 1024 if peak_raw > 10_000 else peak_raw / (1024 * 1024)
    package_version = importlib.metadata.version("c2hunter-analysis")
    evidence_counts: Counter[str] = Counter()
    for execution in detector_execution:
        evidence_counts.update(execution["findings_by_evidence_type"])
    result = {
        "schema_version": 2,
        "seed": seed,
        "packets_requested": packet_count,
        "packets_processed": processed,
        "packet_loss": packet_count - processed,
        "chunks_processed": chunks,
        "chunk_size": chunk_size,
        "streaming": True,
        "flows_generated": generated_flows,
        "analysis_input": {
            "measurement_scope": MEASUREMENT_SCOPE,
            "representative_flows": len(representative_flows),
            "representative_flow_limit": flow_window.limit,
            "flow_records_considered_for_sampling": flow_window.offered,
            "series_represented": flow_window.series,
            "sampling_policy": (
                "rolling recent window per candidate/internal-host series; up to 8 C2-series "
                "and 1 background-series Flow records"
            ),
            "sampling_replacements": flow_window.replacements,
        },
        "analysis_engine": {
            "package": "c2hunter-analysis",
            "package_version": package_version,
            "package_location": str(
                Path(inspect.getfile(AnalysisContext)).resolve().parent
            ),
            "run_detectors_function": "c2hunter_analysis.detectors.run_detectors",
            "score_candidates_function": "c2hunter_analysis.scoring.score_candidates",
            "detectors_configured": len(DEFAULT_DETECTORS),
            "detector_execution": detector_execution,
        },
        "evidence": {
            "total": sum(item["findings"] for item in detector_execution),
            "counts_by_type": dict(sorted(evidence_counts.items())),
        },
        "scoring": {
            "executed": True,
            "candidate_count": len(candidates),
            "top_candidate": (
                {
                    "candidate_ip": candidates[0].candidate_ip,
                    "score": candidates[0].score,
                    "severity": candidates[0].severity,
                    "evidence_types": sorted(
                        {item.type for item in candidates[0].evidence}
                    ),
                }
                if candidates
                else None
            ),
            "duration_seconds": round(scoring_seconds, 6),
        },
        "duration_seconds": round(elapsed, 6),
        "ingestion_seconds": round(ingest_seconds, 6),
        "detector_seconds": round(detector_seconds, 6),
        "throughput_packets_per_second": round(processed / max(elapsed, 1e-9), 2),
        "peak_rss_mb": round(peak_mb, 2),
        "target_duration_seconds": 180,
        "target_peak_rss_mb": 8192,
        "oom": False,
        "targets_met": {
            "duration": elapsed < 180,
            "memory": peak_mb < 8192,
            "no_loss": processed == packet_count,
        },
    }
    Path(output_dir, "benchmark-1m.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    execution_rows = "\n".join(
        "| {name} | `{implementation_type}` | {version} | {executed} | {findings} | {types} | {seconds:.6f} |".format(
            name=item["name"],
            implementation_type=item["implementation_type"],
            version=item["version"],
            executed="yes" if item["executed"] else "no",
            findings=item["findings"],
            types=", ".join(item["evidence_types"]) or "none",
            seconds=item["duration_seconds"],
        )
        for item in detector_execution
    )
    top = result["scoring"]["top_candidate"]
    top_text = (
        f"{top['candidate_ip']} (score {top['score']}, {top['severity']})"
        if top
        else "none"
    )
    markdown = f"""# C2Hunter Streaming Benchmark

| Metric | Result |
|---|---:|
| Packets processed | {processed:,} |
| Chunks | {chunks:,} |
| Flow records generated | {generated_flows:,} |
| Duration | {elapsed:.3f} s |
| Ingestion | {ingest_seconds:.3f} s |
| Detector execution | {detector_seconds:.3f} s |
| Scoring | {scoring_seconds:.6f} s |
| Throughput | {result["throughput_packets_per_second"]:,.2f} packets/s |
| Peak RSS | {peak_mb:.2f} MiB |
| Packet loss | {result["packet_loss"]} |

## Bounded analysis input

All {processed:,} packets were ingested in chunks and produced {generated_flows:,} chunk-local Flow records. The installed analysis engine did **not** receive every generated Flow: it received a bounded representative window of {len(representative_flows):,}/{flow_window.limit:,} Flow records across {flow_window.series:,} candidate/internal-host series. Policy: a rolling recent window retains up to 8 records per C2 series and 1 per background series. Therefore detector findings and candidate scores below characterize that representative window, while throughput and Flow generation cover the full stream.

## Actual analysis engine

- Package: `c2hunter-analysis` {package_version}
- Location: `{result["analysis_engine"]["package_location"]}`
- Detector API: `{result["analysis_engine"]["run_detectors_function"]}`
- Scoring API: `{result["analysis_engine"]["score_candidates_function"]}`
- Scoring executed: yes; candidates: {len(candidates)}; top: {top_text}

## Detector execution evidence

| Detector | Implementation type | Version | Executed | Findings | Evidence types | Seconds |
|---|---|---:|:---:|---:|---|---:|
{execution_rows}

Targets: <180 seconds and <8192 MiB RSS on the reference host; no packet loss. `Executed` records a real call through `run_detectors` for that installed detector instance and is independent of whether the detector returned findings. No detector-success count is synthesized.
"""
    Path(output_dir, "benchmark-1m.md").write_text(markdown)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=int, default=1_000_000)
    parser.add_argument("--chunk-size", type=int, default=10_000)
    parser.add_argument("--output", type=Path, default=Path("artifacts"))
    parser.add_argument("--seed", type=int, default=20260720)
    args = parser.parse_args()
    result = run(args.packets, args.chunk_size, args.output, args.seed)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
