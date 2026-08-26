#!/usr/bin/env python3
"""Deterministic spooled PCAP export benchmark and report comparator."""

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
from fractions import Fraction
from io import BytesIO
from pathlib import Path
from typing import Any, TypeVar

from c2hunter_analysis.pcap import bounded_pcap_prefix, parse_pcap
from c2hunter_analysis.pcap_export import open_export_capture
from c2hunter_controller import pcap_indexed_export as indexed_export
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap import (
    ExportPacketRecord,
    build_capture_to_sink,
    compile_packet_predicate,
    filter_records,
)
from c2hunter_controller.pcap_indexed_export import (
    CaptureRangeVersionDrift,
    IndexedFallback,
    RangePlanLimits,
    create_indexed_match_factory,
)
from c2hunter_controller.pcap_offset_index import (
    SourceIndexBinding,
    build_live_segment_index,
    build_offline_upload_index,
)
from c2hunter_controller.pcap_posting_index_worker import (
    create_posting_operation_builder,
)
from c2hunter_controller.pcap_stream import MatchedPacketRecord
from c2hunter_controller.repositories import MemoryRepository

STAGES = ("source_read", "hash", "frame", "decode", "filter", "write", "save", "total")
IMPLEMENTATION = "spooled-boundary-aware-v1"
DEFAULT_SEED = 20260720
STAGE12_SCHEMA_DESCRIPTIONS = {
    "path": "Authoritative final execution path: indexed or fallback.",
    "fallback_reason": "Typed final fallback reason, or none when indexed completed.",
    "indexed_support_reason": (
        "supported when a complete range plan was admitted; otherwise the reason no complete plan exists."
    ),
    "plan_available": "True only when a complete admitted range plan exists.",
    "original_request_count": (
        "Runtime candidate packet payload requests before range coalescing, including a rejected candidate plan."
    ),
    "coalesced_range_count": (
        "Ranges in the complete admitted range plan; null when no complete admitted range plan exists."
    ),
    "selected_bytes": "Runtime sum of candidate packet payload bytes before coalescing.",
    "planned_range_bytes": (
        "Bytes in the complete admitted range plan; null when plan admission did not complete."
    ),
    "attempted_range_count": "range calls actually issued to the repository spy.",
    "attempted_range_bytes": "Bytes requested by range calls actually issued.",
    "received_range_bytes": "bytes actually returned before success or fallback.",
    "fetched_bytes": (
        "All source bytes read by the final execution, including provisional range bytes before fallback."
    ),
    "source_bytes_saved": (
        "final execution bytes avoided versus sequential: zero for fallback/shadow sequential final paths; "
        "indexed uses max(source_bytes - fetched_bytes, 0)."
    ),
    "indexed": "Complete indexed artifact summary, or null when indexed execution did not complete.",
    "final_artifact": "Artifact summary for the authoritative final output on the reported path.",
    "parity": "Sequential-versus-indexed artifact parity, or null without a complete indexed artifact.",
}
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


def pcapng_multi_interface(packet_count: int, seed: int) -> bytes:
    """Build a deterministic two-interface PCAPNG capture."""
    rng = random.Random(seed)  # noqa: S311 -- deterministic benchmark fixture generation

    def block(kind: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

    content = bytearray(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    content.extend(block(1, struct.pack("<HHI", 1, 0, 65_535)))
    content.extend(block(1, struct.pack("<HHI", 1, 0, 65_535)))
    timestamp = 1_700_000_000_000_000
    for index in range(packet_count):
        packet = _udp_packet(index, rng)
        ticks = timestamp + index
        content.extend(
            block(
                6,
                struct.pack(
                    "<IIIII",
                    index % 2,
                    ticks >> 32,
                    ticks & 0xFFFFFFFF,
                    len(packet),
                    len(packet),
                )
                + packet,
            )
        )
    return bytes(content)


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
    input_passes = 0

    def writer_records() -> Any:
        nonlocal input_passes
        input_passes += 1
        for index, record in enumerate(records):
            packet = record["raw_packet_bytes"]
            timestamp = record["timestamp"]
            if not isinstance(packet, bytes) or not isinstance(timestamp, datetime):
                raise RuntimeError("benchmark parser returned an invalid writer record")
            yield ExportPacketRecord(
                timestamp=timestamp,
                source_id="benchmark-source",
                source_order=0,
                packet_index=index,
                section_index=int(record.get("section_index", 0)),
                interface_id=int(record.get("raw_packet_interface_local_id", 0)),
                interface_ordinal=int(record.get("raw_packet_interface_id", 0)),
                link_type=int(record.get("raw_packet_link_type", 1)),
                packet_bytes=packet,
                captured_length=len(packet),
                original_length=int(
                    record.get("raw_packet_original_length", len(packet))
                ),
            )

    capture_artifact = _stage(
        stages,
        "write",
        lambda: build_capture_to_sink(
            writer_records(),
            max_output_bytes=len(content),
            spool_max_memory_bytes=1_024,
        ),
        packets=len(records),
    )
    with capture_artifact:
        capture_content = capture_artifact.read_bytes()
        capture_matched = capture_artifact.matched_packet_count
        capture_exported = capture_artifact.exported_packet_count
        capture_omitted = capture_artifact.omitted_packet_count
        capture_size = capture_artifact.size_bytes
        capture_sha256 = capture_artifact.sha256
        capture_rolled = capture_artifact.rolled
    output_digest = _stage(
        stages,
        "hash",
        lambda: hashlib.sha256(capture_content).hexdigest(),
        bytes_count=len(capture_content),
    )
    artifact = output_dir / "pcap-export-baseline.pcap"
    _stage(
        stages,
        "save",
        lambda: artifact.write_bytes(capture_content),
        packets=capture_exported,
        bytes_count=len(capture_content),
    )
    total_elapsed = time.perf_counter() - total_started
    stages["write"]["bytes"] = len(capture_content)
    stages["total"] = {
        "duration_seconds": total_elapsed,
        "packets": capture_exported,
        "bytes": len(capture_content),
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
                "matched": capture_matched,
                "exported": capture_exported,
                "omitted": capture_omitted,
            },
            "bytes": {"source": len(content), "output": len(capture_content)},
        },
        "writer": {
            "input_passes": input_passes,
            "rolled_over": capture_rolled,
            "artifact_size_bytes": capture_size,
            "artifact_sha256": capture_sha256,
        },
        "peak_rss_bytes": _rss_bytes(),
    }
    Path(output_dir, "pcap-export-baseline.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def _artifact_summary(
    records: tuple[MatchedPacketRecord, ...], source_size: int
) -> dict[str, Any]:
    writer_records = tuple(
        ExportPacketRecord(
            timestamp=item.timestamp,
            source_id=item.source_id,
            source_order=item.source_order,
            packet_index=item.packet_index,
            section_index=item.section_index,
            interface_id=item.interface_id,
            interface_ordinal=item.interface_ordinal,
            link_type=item.link_type,
            packet_bytes=item.raw_packet_bytes,
            captured_length=item.captured_length,
            original_length=item.original_length,
        )
        for item in records
    )
    with build_capture_to_sink(
        writer_records,
        max_output_bytes=max(24, source_size * 2),
        spool_max_memory_bytes=1024,
    ) as artifact:
        return {
            "artifact_sha256": artifact.sha256,
            "artifact_size_bytes": artifact.size_bytes,
            "packet_count": artifact.exported_packet_count,
        }


def _sequential_records(
    sources: tuple[tuple[str, str, bytes], ...], request: dict[str, Any]
) -> tuple[MatchedPacketRecord, ...]:
    predicate = compile_packet_predicate(request, internal_networks=["10.0.0.0/8"])
    records: list[MatchedPacketRecord] = []
    for source_order, (source_id, sensor_id, capture) in enumerate(sources):
        decoder = open_export_capture(
            BytesIO(capture),
            source_id=source_id,
            source_order=source_order,
            internal_networks=["10.0.0.0/8"],
        )
        records.extend(
            MatchedPacketRecord.from_export_packet(packet, sensor_id=sensor_id)
            for packet in decoder.iter_packets()
            if packet.supported and predicate.matches(packet, sensor_id=sensor_id)
        )
    return tuple(records)


def _stage12_case(
    *,
    name: str,
    capture: bytes,
    request: dict[str, Any],
    limits: RangePlanLimits,
    fault: str | None = None,
    live_source_captures: tuple[bytes, ...] = (),
) -> dict[str, Any]:
    repository = MemoryRepository()
    source_captures = live_source_captures or (capture,)
    source_ids = (
        tuple(f"benchmark-segment-{index}" for index in range(len(source_captures)))
        if live_source_captures
        else ("benchmark-source",)
    )
    sensor_ids = (
        tuple(f"benchmark-sensor-{index}" for index in range(len(source_captures)))
        if live_source_captures
        else ("uploaded",)
    )
    source_bytes = sum(map(len, source_captures))
    digest = hashlib.sha256(capture).hexdigest()
    job = {
        "id": "benchmark-source",
        "idempotency_key": f"benchmark-{name}",
        "status": "CAPTURING" if live_source_captures else "COMPLETED",
        "mode": "LIVE" if live_source_captures else "PCAP_UPLOAD",
        "sensor_ids": list(sensor_ids),
        "internal_networks": ["10.0.0.0/8"],
        "capture": {"store_pcap": True},
        "source": None
        if live_source_captures
        else {
            "packet_bytes_retained": True,
            "size_bytes": len(capture),
            "sha256": digest,
            "packet_count": len(
                tuple(
                    open_export_capture(
                        BytesIO(capture),
                        source_id="count",
                        source_order=0,
                        internal_networks=["10.0.0.0/8"],
                    ).iter_packets()
                )
            ),
            "capture_format": "PCAPNG"
            if capture.startswith(b"\x0a\x0d\x0d\x0a")
            else "PCAP",
        },
    }
    repository.create_job(job)
    settings = Settings(environment="test", pcap_posting_index_enabled=True)
    if live_source_captures:
        for index, (source_id, sensor_id, content) in enumerate(
            zip(source_ids, sensor_ids, source_captures, strict=True)
        ):
            stored, status = repository.save_sensor_pcap_limited(
                {
                    "id": source_id,
                    "sensor_id": sensor_id,
                    "analysis_job_id": job["id"],
                    "filename": f"{source_id}.pcap",
                    "size_bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "uploaded_at": f"2026-07-20T00:00:{index:02d}+00:00",
                },
                content,
                None,
                require_open_job=True,
            )
            if status != "OK" or stored is None:
                raise RuntimeError("benchmark LIVE capture admission failed")
            admission = repository.admit_live_segment_index(
                source_id, capacity=4, max_attempts=3
            )
            if admission.value != "QUEUED":
                raise RuntimeError("benchmark LIVE structural index was not queued")
            structural_claim = repository.claim_live_segment_index(
                now=datetime.now(UTC), lease_seconds=30
            )
            if structural_claim is None or structural_claim.lease_token is None:
                raise RuntimeError("benchmark LIVE structural index was not claimed")
            if not build_live_segment_index(
                repository,
                source_id,
                max_packets=100_000,
                max_interfaces=32,
                batch_size=128,
                attempt=structural_claim.attempt,
                lease_token=structural_claim.lease_token,
                request_postings=True,
                posting_queue_capacity=4,
                posting_max_attempts=3,
            ):
                raise RuntimeError("benchmark LIVE structural index build failed")
        repository.save_job({**job, "status": "COMPLETED"})
        job = repository.get_job_summary(job["id"]) or job
    else:
        repository.save_job_capture("benchmark-source", capture)
        if not build_offline_upload_index(
            repository,
            "benchmark-source",
            max_packets=100_000,
            max_interfaces=32,
            batch_size=128,
            request_postings=True,
            posting_queue_capacity=4,
            posting_max_attempts=3,
        ):
            raise RuntimeError("benchmark upload structural index build failed")
    for _source_id in source_ids:
        claimed = repository.claim_posting_index(lease_seconds=30)
        if claimed is None or claimed.lease_token is None:
            raise RuntimeError("benchmark posting index was not claimed")
        operation = create_posting_operation_builder(
            settings, monotonic=time.monotonic
        )(
            repository,
            task=claimed,
            attempt=claimed.attempt,
            lease_token=claimed.lease_token,
            deadline=time.monotonic() + 30,
            should_cancel=lambda: False,
        )
        if not operation().published:
            raise RuntimeError("benchmark posting index publication failed")
    snapshot = repository.snapshot_pcap_export_source("benchmark-source", request, {})
    if snapshot is None:
        raise RuntimeError("benchmark source snapshot is unavailable")
    predicate = compile_packet_predicate(
        request, internal_networks=job["internal_networks"]
    )
    sequential_started = time.perf_counter()
    sequential_records = _sequential_records(
        tuple(zip(source_ids, sensor_ids, source_captures, strict=True)), request
    )
    sequential = _artifact_summary(sequential_records, source_bytes)
    sequential_seconds = time.perf_counter() - sequential_started
    factory = create_indexed_match_factory(
        repository, range_limits=limits, max_sources=4
    )
    original_read = repository.read_capture_range
    original_planner = indexed_export.plan_source_packet_ranges
    observed_range_sources: list[str] = []
    attempted_range_count = 0
    attempted_range_bytes = 0
    received_range_bytes = 0
    candidate_request_count = 0
    candidate_selected_bytes = 0
    candidate_plans: list[indexed_export.RangePlan] = []
    plan_available = False

    def observed_plan(
        locators: tuple[indexed_export.SelectedPacketLocator, ...],
        *,
        limits: indexed_export.SourceRangePlanLimits,
    ) -> indexed_export.RangePlan:
        nonlocal candidate_request_count, candidate_selected_bytes
        candidate_request_count += len(locators)
        candidate_selected_bytes += sum(item.captured_length for item in locators)
        plan = original_planner(locators, limits=limits)
        candidate_plans.append(plan)
        return plan

    def observed_read(source: Any, byte_range: Any) -> bytes:
        nonlocal attempted_range_count, attempted_range_bytes, received_range_bytes
        nonlocal plan_available
        plan_available = True
        observed_range_sources.append(source.source_id)
        attempted_range_count += 1
        attempted_range_bytes += byte_range.length
        if fault == "drift":
            raise CaptureRangeVersionDrift("injected")
        content = original_read(source, byte_range)
        if fault == "short":
            content = content[:-1]
        received_range_bytes += len(content)
        return content

    repository.read_capture_range = observed_read  # type: ignore[method-assign]
    indexed_started = time.perf_counter()
    path = "indexed"
    fallback_reason = "none"
    indexed: dict[str, Any] | None = None
    batch = None
    indexed_export.plan_source_packet_ranges = observed_plan
    try:
        try:
            batch = factory(
                repository=repository,
                settings=settings,
                requested_job=job,
                source_snapshot=snapshot,
                canonical_request=request,
                candidate_id=None,
                predicate=predicate,
                internal_networks=job["internal_networks"],
                scan_max_bytes=source_bytes,
                scan_max_packets=100_000,
                checkpoint=lambda **_progress: None,
            )
            plan_available = True
            indexed = _artifact_summary(batch.records, source_bytes)
        except IndexedFallback as exc:
            path = "fallback"
            fallback_reason = exc.reason.value
    finally:
        indexed_export.plan_source_packet_ranges = original_planner
    indexed_seconds = time.perf_counter() - indexed_started
    if batch is not None:
        candidate_request_count = batch.requested_range_count
        candidate_selected_bytes = batch.selected_payload_bytes
        coalesced_range_count: int | None = batch.range_count
        planned_range_bytes: int | None = batch.fetched_bytes
    elif plan_available:
        coalesced_range_count = sum(len(plan.ranges) for plan in candidate_plans)
        planned_range_bytes = sum(plan.fetched_bytes for plan in candidate_plans)
    else:
        coalesced_range_count = None
        planned_range_bytes = None
    final_artifact = indexed if indexed is not None else sequential
    fetched = (
        received_range_bytes
        if path == "indexed"
        else source_bytes + received_range_bytes
    )
    interface_count = 0
    for source_id in source_ids:
        source = (
            repository.get_live_capture_source_version(source_id)
            if live_source_captures
            else repository.get_capture_source_version(source_id)
        )
        if source is None:
            raise RuntimeError("benchmark source version is unavailable")
        for capture_format in ("PCAP", "PCAPNG"):
            lookup = repository.get_structural_index(
                SourceIndexBinding(
                    source.source_kind,
                    source.source_id,
                    source.source_version_id,
                    source.source_size_bytes,
                    source.source_sha256,
                    capture_format,
                )
            )
            if lookup.snapshot is not None:
                interface_count += len(lookup.snapshot.interfaces)
    repository.close()
    amplification = (
        {
            "numerator": planned_range_bytes,
            "denominator": max(1, candidate_selected_bytes),
            "value": float(
                Fraction(planned_range_bytes, max(1, candidate_selected_bytes))
            ),
        }
        if planned_range_bytes is not None
        else None
    )
    parity = (
        {
            "sha256": sequential["artifact_sha256"] == indexed["artifact_sha256"],
            "size": sequential["artifact_size_bytes"] == indexed["artifact_size_bytes"],
            "packet_count": sequential["packet_count"] == indexed["packet_count"],
        }
        if indexed is not None
        else None
    )
    return {
        "workload": name,
        "path": path,
        "fallback_reason": fallback_reason,
        "indexed_support_reason": "supported" if plan_available else fallback_reason,
        "plan_available": plan_available,
        "selected_packet_count": final_artifact["packet_count"],
        "original_request_count": candidate_request_count,
        "coalesced_range_count": coalesced_range_count,
        "selected_bytes": candidate_selected_bytes,
        "planned_range_bytes": planned_range_bytes,
        "attempted_range_count": attempted_range_count,
        "attempted_range_bytes": attempted_range_bytes,
        "received_range_bytes": received_range_bytes,
        "fetched_bytes": fetched,
        "source_bytes": source_bytes,
        "source_bytes_saved": (
            max(0, source_bytes - fetched) if path == "indexed" else 0
        ),
        "amplification": amplification,
        "source_fraction": fetched / max(1, source_bytes),
        "source_count": len(source_ids),
        "source_ids": list(source_ids),
        "range_source_ids": list(dict.fromkeys(observed_range_sources)),
        "interface_count": interface_count,
        "sequential": sequential,
        "indexed": indexed,
        "final_artifact": final_artifact,
        "parity": parity,
        "peak_rss_bytes": _rss_bytes(),
        "stages": {
            "sequential_seconds": sequential_seconds,
            "indexed_seconds": indexed_seconds,
        },
    }


def run_stage12(
    output_dir: Path, packet_count: int = 128, seed: int = DEFAULT_SEED
) -> dict[str, Any]:
    """Measure Stage 12 through the production builder, factory, and range repository."""
    output_dir.mkdir(parents=True, exist_ok=True)
    capture = classic_pcap(packet_count, seed)
    middle = 40_000 + packet_count // 2
    sparse = {
        "include_filters": [
            {"source_port": 40_000},
            {"source_port": middle},
            {"source_port": 40_000 + packet_count - 1},
        ]
    }
    clustered = {
        "include_filters": [
            {"source_port": 40_000 + index} for index in range(min(8, packet_count))
        ]
    }
    generous = RangePlanLimits(256, 1 << 20, 128, 1 << 24, 8, 1, 9, 10)
    cases = [
        ("sparse", sparse, generous, None),
        ("clustered", clustered, generous, None),
        (
            "dense_fallback",
            {},
            RangePlanLimits(256, 1 << 20, 128, 1 << 24, 8, 1, 1, 10),
            None,
        ),
        ("multi_source_live", sparse, generous, None),
        ("pcapng_multi_interface", sparse, generous, None),
        (
            "range_limit_plus_one",
            sparse,
            RangePlanLimits(0, 1 << 20, 2, 1 << 24, 8, 1, 9, 10),
            None,
        ),
        ("short_read", sparse, generous, "short"),
        ("version_drift", sparse, generous, "drift"),
    ]
    workloads = [
        _stage12_case(
            name=name,
            capture=(
                pcapng_multi_interface(packet_count, seed)
                if name == "pcapng_multi_interface"
                else capture
            ),
            request=request,
            limits=limits,
            fault=fault,
            live_source_captures=(
                (capture, classic_pcap(packet_count, seed + 1))
                if name == "multi_source_live"
                else ()
            ),
        )
        for name, request, limits, fault in cases
    ]
    report = {
        "schema_version": 3,
        "implementation": "stage12-production-indexed-factory-v1",
        "seed": seed,
        "packet_count": packet_count,
        "schema_descriptions": STAGE12_SCHEMA_DESCRIPTIONS,
        "workloads": workloads,
    }
    (output_dir / "pcap-export-stage12.json").write_text(
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
    parser.add_argument(
        "--stage12", action="store_true", help="run the Stage 12 indexed matrix"
    )
    args = parser.parse_args()
    report = (
        run_stage12(args.output, args.packets, args.seed)
        if args.stage12
        else run(args.packets, args.output, args.seed)
    )
    payload: dict[str, Any] = report
    if args.compare is not None:
        baseline = json.loads(args.compare.read_text(encoding="utf-8"))
        payload = {"report": report, "comparison": compare_reports(report, baseline)}
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
