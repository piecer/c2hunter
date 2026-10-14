"""Closed v3 evidence contract; confidence describes support, not attack probability."""

from __future__ import annotations

from typing import Any

MAX_SAMPLES_GLOBAL = 32768
MAX_SAMPLES_TARGET = 2048
MAX_SAMPLES_SOURCE = 32
MAX_SAMPLES_FLOW = 16
WINDOW_SECONDS = 10
MIN_SOURCES = 3
MIN_SHARED_BUCKETS = 3

COUNTERS = frozenset(
    {
        "observed_sources",
        "sample_count",
        "omitted_samples",
        "unobserved_packets",
        "eligible_sources",
        "coordinated_sources",
        "shared_buckets",
        "response_samples",
        "request_samples",
        "matched_response_samples",
        "direct_samples",
        "invalid_source_records",
        "identity_variation_records",
        "component_count",
    }
)
EVIDENCE_KEYS = COUNTERS | {"coverage_limited", "window_seconds", "amplification_ratio"}


def assess(evidence: dict[str, Any]) -> dict[str, Any]:
    """Derive all labels/reasons from bounded facts; reject invented measurements."""
    if set(evidence) != EVIDENCE_KEYS:
        raise ValueError("invalid DDoS axis evidence keys")
    if any(type(evidence[k]) is not int or not 0 <= evidence[k] <= 2**53 - 1 for k in COUNTERS):
        raise ValueError("invalid DDoS axis counter")
    if (
        type(evidence["coverage_limited"]) is not bool
        or evidence["amplification_ratio"] is not None
    ):
        raise ValueError("invalid DDoS observation presence")
    if type(evidence["window_seconds"]) is not int or evidence["window_seconds"] != WINDOW_SECONDS:
        raise ValueError("invalid coordination window")
    e = evidence
    if (
        e["matched_response_samples"] > e["response_samples"]
        or e["response_samples"] + e["request_samples"] + e["direct_samples"] > e["sample_count"]
        or e["coordinated_sources"] > e["eligible_sources"] > e["observed_sources"]
        or e["coordinated_sources"] > e["eligible_sources"]
        or e["eligible_sources"] > e["observed_sources"]
        or e["shared_buckets"] > WINDOW_SECONDS
        or e["sample_count"] > MAX_SAMPLES_GLOBAL
        or (not e["component_count"] and e["sample_count"] > MAX_SAMPLES_TARGET)
        or e["coordinated_sources"] * e["shared_buckets"]
        > e["sample_count"] - e["response_samples"]
        or e["eligible_sources"] * MIN_SHARED_BUCKETS > e["sample_count"]
    ):
        raise ValueError("inconsistent DDoS axis evidence")
    limited = e["coverage_limited"] or e["omitted_samples"] > 0 or e["unobserved_packets"] > 0
    reflection = e["response_samples"] > e["matched_response_samples"]
    direct = e["direct_samples"] + e["request_samples"] > 0
    delivery = (
        "MIXED"
        if reflection and direct
        else "REFLECTION_AMPLIFICATION"
        if reflection
        else "DIRECT_DISTRIBUTED"
        if direct
        else "UNKNOWN"
    )
    coordinated = (
        e["coordinated_sources"] >= MIN_SOURCES
        and e["shared_buckets"] >= MIN_SHARED_BUCKETS
        and not limited
    )
    population = (
        "MIXED"
        if e["component_count"]
        else "BOTNET_LIKE_COORDINATION"
        if coordinated
        else "REFLECTOR_SET"
        if reflection and not direct
        else "DISTRIBUTED_UNATTRIBUTED"
    )
    authenticity = "SPOOFING_SUSPECTED" if e["invalid_source_records"] else "SPOOFING_UNCONFIRMED"
    axes: dict[str, dict[str, Any]] = {
        "delivery_mechanism": {
            "confidence": "medium" if reflection and not limited else "low",
            "supporting_codes": ["PARSED_RESPONSE_OBSERVED"]
            if reflection
            else ["DIRECT_PACKET_PROFILE_OBSERVED"]
            if direct
            else [],
            "counter_codes": ["MATCHING_REQUEST_OBSERVED"] if e["matched_response_samples"] else [],
            "unknown_codes": [
                "AMPLIFICATION_UNMEASURED",
                "REQUEST_VISIBILITY_NOT_PROOF",
                "UPSTREAM_SPOOFING_UNCONFIRMED",
            ]
            if e["response_samples"]
            else ["RESPONSE_SEMANTICS_UNAVAILABLE"]
            if not direct
            else [],
        },
        "source_population": {
            "confidence": "medium" if coordinated and not e["component_count"] else "low",
            "supporting_codes": ["SHARED_PROFILE_AND_PACKET_TIMING"]
            if coordinated and not e["component_count"]
            else [],
            "counter_codes": ["NO_SHARED_TEMPORAL_PROFILE"]
            if e["eligible_sources"] >= MIN_SOURCES and not coordinated
            else [],
            "unknown_codes": (
                ["COMPONENT_ASSESSMENTS"]
                if e["component_count"]
                else ["LEGITIMATE_COORDINATION_POSSIBLE", "COMPROMISE_UNCONFIRMED"]
                if coordinated
                else ["PACKET_TIMING_OR_PROFILE_UNAVAILABLE"]
            ),
        },
        "source_authenticity": {
            "confidence": "medium" if e["invalid_source_records"] and not limited else "low",
            "supporting_codes": ["INVALID_SOURCE_ADDRESS_OBSERVED"]
            if e["invalid_source_records"]
            else [],
            "counter_codes": [],
            "unknown_codes": ["SOURCE_VALIDATION_UNAVAILABLE"]
            + (["TTL_IPID_VARIATION_NOT_PROOF"] if e["identity_variation_records"] else []),
        },
    }
    if limited:
        for axis in axes.values():
            axis["unknown_codes"].append("EVIDENCE_COVERAGE_LIMITED")
    return {
        "delivery_mechanism": delivery,
        "source_population": population,
        "source_authenticity": authenticity,
        "confidence": "low"
        if limited
        else "medium"
        if coordinated or reflection or e["invalid_source_records"]
        else "low",
        "evidence": dict(e),
        "axes": axes,
    }


def empty_evidence() -> dict[str, Any]:
    return {
        **dict.fromkeys(COUNTERS, 0),
        "coverage_limited": False,
        "window_seconds": WINDOW_SECONDS,
        "amplification_ratio": None,
    }
