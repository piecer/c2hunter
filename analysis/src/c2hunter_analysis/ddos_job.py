"""One traversal for legacy DDoS classification and offline packet review."""

from __future__ import annotations

from typing import Any

from . import ddos_attack
from .ddos_signatures import load_reference
from .pcap_attack_guidance import GuidanceCollector


def analyze_ddos_job(job: dict[str, Any]) -> dict[str, Any]:
    if job.get("analysis", {}).get("module") != "ddos_attack":
        raise ValueError("shared DDoS helper requires ddos_attack module")
    collector = GuidanceCollector() if job.get("source_type") == "PCAP_UPLOAD" else None
    report = ddos_attack.analyze_ddos_attack(
        job.get("flow_records", []),
        internal_cidrs=job.get("internal_networks", ()),
        parameters=job.get("analysis", {}),
        coverage_context=job.get("ddos_coverage_context", {}),
        normal_reference=load_reference(job),
        _observe_packet=collector.add if collector is not None else None,
    )
    result = {"candidates": [], "ddos_attack": report}
    if collector is not None:
        result["pcap_attack_guidance"] = collector.finish(job, report)
    return result
