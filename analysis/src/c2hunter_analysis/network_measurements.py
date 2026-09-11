"""Fixed-size, capture-local supporting measurements, never anomaly classifiers."""

from __future__ import annotations

from dataclasses import dataclass, field
from math import sqrt
from typing import Literal, TypedDict


class Stats(TypedDict):
    count: int
    min: float | None
    max: float | None
    mean: float | None
    stddev: float | None


class TTL(TypedDict):
    count: int
    min: int | None
    max: int | None
    changes: int
    missing: int


class Measurements(TypedDict):
    observed_rtt_ms: Stats
    rtt_sources: dict[str, int]
    rtt_excluded: dict[str, int]
    interarrival_variation_ms: dict[str, Stats]
    ttl_observed: dict[str, TTL]
    coverage_complete: bool
    status: Literal["observed", "insufficient_evidence", "unsupported"]
    reasons: list[str]


class Hypothesis(TypedDict):
    code: str
    confidence: Literal["low"]
    summary: str


@dataclass(slots=True)
class OnlineStats:
    count: int = 0
    mean: float = 0
    m2: float = 0
    minimum: float = float("inf")
    maximum: float = float("-inf")

    def add(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)

    def publish(self) -> Stats:
        return {
            "count": self.count,
            "min": self.minimum if self.count else None,
            "max": self.maximum if self.count else None,
            "mean": round(self.mean, 6) if self.count else None,
            "stddev": round(sqrt(max(0, self.m2) / self.count), 6) if self.count >= 2 else None,
        }


@dataclass(slots=True)
class DirectionMeasurement:
    spacing: OnlineStats = field(default_factory=OnlineStats)
    last_time: float | None = None
    packets: int = 0
    ttl_count: int = 0
    ttl_min: int | None = None
    ttl_max: int | None = None
    ttl_last: int | None = None
    ttl_changes: int = 0
    ttl_missing: int = 0

    def add(self, time: float, ttl: object) -> None:
        self.packets += 1
        if self.last_time is not None:
            self.spacing.add(round((time - self.last_time) * 1000, 6))
        self.last_time = time
        if type(ttl) is int and 0 <= ttl <= 255:
            self.ttl_count += 1
            self.ttl_min = min(self.ttl_min, ttl) if self.ttl_min is not None else ttl
            self.ttl_max = max(self.ttl_max, ttl) if self.ttl_max is not None else ttl
            self.ttl_changes += int(self.ttl_last is not None and self.ttl_last != ttl)
            self.ttl_last = ttl
        else:
            self.ttl_missing += 1
            self.ttl_last = None

    def ttl(self) -> TTL:
        return {
            "count": self.ttl_count,
            "min": self.ttl_min,
            "max": self.ttl_max,
            "changes": self.ttl_changes,
            "missing": self.ttl_missing,
        }


@dataclass(slots=True)
class SupportingMeasurements:
    rtt: OnlineStats = field(default_factory=OnlineStats)
    directions: tuple[DirectionMeasurement, DirectionMeasurement] = field(
        default_factory=lambda: (DirectionMeasurement(), DirectionMeasurement())
    )
    sources: dict[str, int] = field(default_factory=lambda: {"syn_ack": 0, "data_ack": 0})
    excluded: dict[str, int] = field(
        default_factory=lambda: {"ambiguous": 0, "nonpositive_time": 0, "nonexact_ack": 0}
    )
    reasons: set[str] = field(default_factory=set)

    def sample(self, start: float, end: float, source: str, ambiguous: bool) -> None:
        if ambiguous:
            self.excluded["ambiguous"] += 1
        elif end <= start:
            self.excluded["nonpositive_time"] += 1
        else:
            self.rtt.add(round((end - start) * 1000, 6))
            self.sources[source] += 1

    def gap(self, reason: str) -> None:
        self.reasons.add(reason)
        for direction in self.directions:
            direction.last_time = None
            direction.ttl_last = None

    def publish(self, protocol: str) -> Measurements:
        reasons = self.reasons.copy()
        if any(d.ttl_missing for d in self.directions):
            reasons.add("MISSING_TTL")
        if any(not d.packets for d in self.directions):
            reasons.add("ONE_DIRECTION_OBSERVED")
        if protocol != "TCP":
            reasons.add("NOT_TCP")
        elif not self.rtt.count:
            reasons.add("NO_UNAMBIGUOUS_RTT")
        names = ("a_to_b", "b_to_a")
        observed = self.rtt.count or any(d.ttl_count or d.spacing.count for d in self.directions)
        return {
            "observed_rtt_ms": self.rtt.publish(),
            "rtt_sources": self.sources.copy(),
            "rtt_excluded": self.excluded.copy(),
            "interarrival_variation_ms": {
                n: d.spacing.publish() for n, d in zip(names, self.directions, strict=True)
            },
            "ttl_observed": {n: d.ttl() for n, d in zip(names, self.directions, strict=True)},
            "coverage_complete": not reasons,
            "status": "observed"
            if observed
            else "insufficient_evidence"
            if protocol == "TCP"
            else "unsupported",
            "reasons": sorted(reasons),
        }


_CAUSES = {
    "syn_retransmissions": (
        "response_visibility_or_filtering",
        "Missing response visibility, filtering or duplicate capture may explain "
        "repeated attempts.",
    ),
    "matched_resets": (
        "service_refusal_or_policy",
        "Service refusal or policy rejection may explain matched resets.",
    ),
    "data_retransmissions": (
        "loss_reordering_or_capture_duplication",
        "Loss, reordering or capture duplication may explain exact data repeats.",
    ),
    "duplicate_acks": (
        "loss_reordering_or_capture_duplication",
        "Missing data, reordering or capture duplication may explain repeated ACKs.",
    ),
    "udp_duplicate_candidates": (
        "application_repeat_or_capture_duplication",
        "Application retries, intentional repeats or capture duplication may explain UDP repeats.",
    ),
    "icmp_errors": (
        "reported_network_or_policy_error",
        "A reporting device indicates a network or policy error; inspect type/code.",
    ),
}


def hypothesis(pattern: str) -> Hypothesis:
    code, summary = _CAUSES[pattern]
    return {"code": code, "confidence": "low", "summary": summary}


def describe(m: Measurements) -> list[str]:
    return [
        f"Representative flow capture-local RTT (ms): {m['observed_rtt_ms']}; "
        f"sources {m['rtt_sources']}; excluded matches {m['rtt_excluded']}. "
        "Not one-way latency; includes peer ACK delay.",
        f"Same-direction interarrival dispersion (ms): {m['interarrival_variation_ms']}. "
        "Application pacing and capture effects can explain variation; "
        "this is not network jitter proof.",
        f"Outer IPv4 TTL / IPv6 hop-limit: {m['ttl_observed']}. "
        "Variation can motivate checking path changes or sender defaults, "
        "but proves neither a route change nor exact hops or asymmetry.",
        f"Measurement coverage complete: {m['coverage_complete']}; reasons: {m['reasons']}. "
        "No baseline is configured: RTT/spacing alone cannot establish congestion or queueing; "
        "compare baseline and peer captures before attributing the pattern.",
    ]
