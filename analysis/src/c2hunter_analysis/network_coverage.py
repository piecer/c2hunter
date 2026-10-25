"""Bounded source qualifiers, separate from packet-local measurement quality.

These booleans describe the immutable dataset, not cumulative packet counters.
The pure report analyzer intentionally remains independent of job provenance.
"""

from __future__ import annotations

from typing import Any, TypeGuard

from .network_report import Report, analyze_network_report

SOURCE_WARNINGS = (
    "CAPTURE_PACKET_LIMIT_REACHED",
    "PARSER_SKIPPED_PACKETS",
    "SENSOR_DROPS_REPORTED",
    "SENSOR_CLOCK_SKEW",
    "PARTIAL_CAPTURE",
    "SENSOR_CAPTURE_QUALITY_UNAVAILABLE",
)
OMISSION_WARNINGS = frozenset(SOURCE_WARNINGS) - {
    "SENSOR_CLOCK_SKEW",
    "SENSOR_CAPTURE_QUALITY_UNAVAILABLE",
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _observed_count(value: Any) -> TypeGuard[int]:
    return type(value) is int and value >= 0


def network_coverage_context(job: dict[str, Any]) -> dict[str, bool]:
    previous = _mapping(job.get("network_coverage_context"))
    limit = _mapping(job.get("capture_limit"))
    source = _mapping(job.get("source"))
    quality = _mapping(job.get("capture_quality"))
    drops = quality.get("dropped_packet_count")
    skipped = source.get("skipped_packet_count")
    discarded = limit.get("discarded_packets")
    is_uploaded_pcap = _observed_count(source.get("captured_packet_count"))
    context = {
        "CAPTURE_PACKET_LIMIT_REACHED": _observed_count(discarded) and discarded > 0,
        "PARSER_SKIPPED_PACKETS": _observed_count(skipped) and skipped > 0,
        "SENSOR_DROPS_REPORTED": _observed_count(drops) and drops > 0,
        "SENSOR_CLOCK_SKEW": quality.get("clock_skew_detected") is True,
        "PARTIAL_CAPTURE": job.get("capture_incomplete") is True
        or job.get("error_code") == "LIVE_CAPTURE_RESTART_INCOMPLETE",
        "SENSOR_CAPTURE_QUALITY_UNAVAILABLE": not is_uploaded_pcap
        and not (_observed_count(drops) and type(quality.get("clock_skew_detected")) is bool),
    }
    return {code: context[code] or previous.get(code) is True for code in SOURCE_WARNINGS}


def attach_network_coverage_context(job: dict[str, Any]) -> None:
    if job.get("analysis", {}).get("module") == "network_anomaly":
        job["network_coverage_context"] = network_coverage_context(job)


def analyze_network_job(job: dict[str, Any]) -> Report:
    """Analyze the supplied view once, retaining valid positive/local evidence."""
    report = analyze_network_report(job.get("flow_records", []))
    qualifiers = {code for code, present in network_coverage_context(job).items() if present}
    if not qualifiers:
        return report
    report["warnings"] = sorted(set(report["warnings"]) | qualifiers)
    summary = report["summary"]
    summary["coverage_complete"] = False
    if qualifiers & OMISSION_WARNINGS:
        summary["counts_are_lower_bounds"] = True
        summary["truncated"] = True
    if summary["issue_count"]:
        summary["narrative"] = (
            "Supported observable patterns identified; inspect grouped evidence. "
            "Coverage is incomplete; additional patterns may be unobservable."
        )
    else:
        summary["verdict"] = "insufficient_evidence"
        summary["narrative"] = "Evidence is insufficient to exclude anomaly patterns."
    return report
