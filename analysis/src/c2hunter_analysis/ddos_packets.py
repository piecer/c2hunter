"""Bounded packet-derived metadata shared by PCAP and the LIVE wire contract."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime
from decimal import ROUND_CEILING, Decimal
from itertools import combinations
from typing import Any

from .ddos_evidence import (
    MAX_SAMPLES_FLOW,
    MAX_SAMPLES_GLOBAL,
    MAX_SAMPLES_SOURCE,
    MAX_SAMPLES_TARGET,
    MIN_SHARED_BUCKETS,
    WINDOW_SECONDS,
)

# One analysis-wide cap, not a per-target map of unbounded reverse keys.
MAX_REVERSE_LOSS_SCOPES = 4096

SEMANTICS = frozenset(
    {"DNS_REQUEST", "DNS_RESPONSE", "NTP_REQUEST", "NTP_RESPONSE", "OTHER", "UNKNOWN"}
)


def protocol_semantics(
    payload: bytes, source_port: int | None, destination_port: int | None
) -> tuple[str, str | None]:
    """Parse bounded DNS standard-query headers/question or NTP v3/v4 modes.

    Not a full DNS answer validator or NTP authenticator. Compression and other
    opcodes/modes abstain. Tokens are passive request correlation, not identity.
    """
    if 53 in (source_port, destination_port):
        if len(payload) < 17 or payload[2] & 0x7A or payload[4:6] != b"\0\1":
            return "UNKNOWN", None
        offset = 12
        for _ in range(128):
            if offset >= min(len(payload), 268):
                return "UNKNOWN", None
            size = payload[offset]
            offset += 1
            if size == 0:
                break
            if size > 63:
                return "UNKNOWN", None
            offset += size
        else:
            return "UNKNOWN", None
        if offset + 4 > len(payload):
            return "UNKNOWN", None
        response = bool(payload[2] & 0x80)
        if (response and source_port != 53) or (not response and destination_port != 53):
            return "UNKNOWN", None
        token = hashlib.sha256(payload[:2] + payload[12 : offset + 4]).hexdigest()
        return ("DNS_RESPONSE" if response else "DNS_REQUEST"), token
    if 123 in (source_port, destination_port):
        if len(payload) < 48 or (payload[0] >> 3) & 7 not in {3, 4}:
            return "UNKNOWN", None
        mode = payload[0] & 7
        if mode == 4 and source_port == 123 and 1 <= payload[1] <= 15:
            timestamp_token = payload[24:32]
            return "NTP_RESPONSE", hashlib.sha256(timestamp_token).hexdigest() if any(
                timestamp_token
            ) else None
        if mode == 3 and destination_port == 123:
            timestamp_token = payload[40:48]
            return "NTP_REQUEST", hashlib.sha256(timestamp_token).hexdigest() if any(
                timestamp_token
            ) else None
        return "UNKNOWN", None
    # Service ports are not affirmative response evidence. Until a bounded
    # parser supports these reflection services, their replies must abstain.
    if source_port in {17, 19, 389, 1900, 11211}:
        return "UNKNOWN", None
    return "OTHER", None


def timestamp_us(timestamp: datetime) -> int:
    """Signed epoch microseconds without float conversion (naive means UTC)."""
    delta = (
        timestamp.replace(tzinfo=UTC) - datetime(1970, 1, 1, tzinfo=UTC)
        if timestamp.tzinfo is None
        else timestamp - datetime(1970, 1, 1, tzinfo=UTC)
    )
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def packet_interval_us(timestamp: datetime, duration: float) -> tuple[int, int]:
    """Bound floored packet times after datetime discards the start's nanoseconds.

    For start S+r microseconds, 0 <= r < 1, and duration D, every sample is
    in [S, S+ceil(D)]. The upper allowance is strictly less than one microsecond
    relative to S+D; integral-microsecond durations gain no allowance. Decimal
    conversion avoids binary multiplication/truncation at historical epochs.
    Legacy timestamp/duration fields are never rewritten.
    """
    start = timestamp_us(timestamp)
    span = int((Decimal(str(duration)) * 1_000_000).to_integral_value(rounding=ROUND_CEILING))
    return start, start + span


def packet_sample(
    timestamp: datetime,
    protocol: str,
    ip_length: int,
    flags: int,
    payload: bytes,
    source_port: int | None,
    destination_port: int | None,
) -> dict[str, Any] | None:
    stamp = timestamp_us(timestamp)
    if not -(2**53 - 1) <= stamp <= 2**53 - 1:
        return None
    semantic, token = (
        protocol_semantics(payload, source_port, destination_port)
        if protocol == "UDP"
        else ("OTHER", None)
    )
    # IP length, not captured Ethernet length; bounded prefix, never raw payload.
    profile = hashlib.sha256(f"{protocol}|{ip_length}|{flags}|".encode() + payload[:64]).hexdigest()
    return {
        "timestamp_us": stamp,
        "profile": profile,
        "semantic": semantic,
        "transaction": token,
    }


def validate_packet_evidence(
    value: object,
    packets: int,
    start_us: int,
    end_us: int,
    protocol: str,
    source_port: int | None,
    destination_port: int | None,
) -> dict[str, Any] | None:
    if value is None:
        return None  # model_dump of absent optional legacy metadata
    if not isinstance(value, dict) or set(value) != {"version", "samples", "omitted_samples"}:
        raise ValueError("invalid DDoS packet evidence shape")
    if type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("unsupported DDoS packet evidence")
    samples, omitted = value["samples"], value["omitted_samples"]
    if (
        not isinstance(samples, list)
        or len(samples) > MAX_SAMPLES_FLOW
        or type(omitted) is not int
        or omitted < 0
        or omitted > packets
        or len(samples) + omitted > packets
    ):
        raise ValueError("invalid DDoS sample count")
    for sample in samples:
        if not isinstance(sample, dict) or set(sample) != {
            "timestamp_us",
            "profile",
            "semantic",
            "transaction",
        }:
            raise ValueError("invalid DDoS packet sample")
        if (
            type(sample["timestamp_us"]) is not int
            or not -(2**53 - 1) <= sample["timestamp_us"] <= 2**53 - 1
            or not start_us <= sample["timestamp_us"] <= end_us
        ):
            raise ValueError("DDoS sample outside flow interval")
        for name in ("profile", "transaction"):
            value_hash = sample[name]
            if name == "transaction" and value_hash is None:
                continue
            if (
                not isinstance(value_hash, str)
                or len(value_hash) != 64
                or any(c not in "0123456789abcdef" for c in value_hash)
            ):
                raise ValueError("invalid DDoS sample hash")
        if not isinstance(sample["semantic"], str) or sample["semantic"] not in SEMANTICS:
            raise ValueError("unknown DDoS packet semantic")
        if sample["semantic"] in {"OTHER", "UNKNOWN"} and sample["transaction"] is not None:
            raise ValueError("unexpected DDoS transaction")
        semantic = sample["semantic"]
        if semantic not in {"OTHER", "UNKNOWN"}:
            port = 53 if semantic.startswith("DNS_") else 123
            observed_port = source_port if semantic.endswith("RESPONSE") else destination_port
            if (
                protocol != "UDP"
                or observed_port != port
                or (port == 53 and sample["transaction"] is None)
            ):
                raise ValueError("DDoS semantic disagrees with transport")
    return value


class PacketEvidenceCollector:
    """Independent caps; overflow never upgrades partial coordination evidence."""

    def __init__(self) -> None:
        self.samples: dict[tuple[Any, ...], list[tuple[Any, dict[str, Any]]]] = defaultdict(list)
        self.source_counts: dict[tuple[Any, ...], int] = {}
        self.total = 0
        self.global_limited = False
        self.reverse_loss_scopes: set[tuple[Any, ...]] = set()
        self.reverse_loss_overflow = False

    def _request_loss(self, row: Any) -> None:
        # Only transports whose parsed responses consult our request index.
        if row.protocol != "UDP" or row.target_port not in {53, 123}:
            return
        scope = (row.sensor, row.source, row.source_port, row.target, row.target_port)
        if scope in self.reverse_loss_scopes:
            return
        if len(self.reverse_loss_scopes) >= MAX_REVERSE_LOSS_SCOPES:
            self.reverse_loss_overflow = True
        else:
            self.reverse_loss_scopes.add(scope)

    def add(self, key: tuple[Any, ...], row: Any, evidence: dict[str, Any]) -> None:
        bundle = row.ddos_packet_evidence
        if bundle is None:
            evidence["unobserved_packets"] += row.packets
            self._request_loss(row)
            return
        evidence["unobserved_packets"] += (
            row.packets - len(bundle["samples"]) - bundle["omitted_samples"]
        )
        evidence["omitted_samples"] += bundle["omitted_samples"]
        if len(bundle["samples"]) < row.packets:
            self._request_loss(row)
        for sample in bundle["samples"]:
            source_key = (*key, row.source)
            if (
                self.total >= MAX_SAMPLES_GLOBAL
                or len(self.samples.get(key, ())) >= MAX_SAMPLES_TARGET
                or self.source_counts.get(source_key, 0) >= MAX_SAMPLES_SOURCE
            ):
                evidence["omitted_samples"] += 1
                self.global_limited |= self.total >= MAX_SAMPLES_GLOBAL
                self._request_loss(row)
                continue
            self.samples[key].append((row, sample))
            self.source_counts[source_key] = self.source_counts.get(source_key, 0) + 1
            self.total += 1

    def finish(self, targets: dict[tuple[Any, ...], Any], limited: bool) -> None:
        requests: dict[tuple[Any, ...], list[int]] = defaultdict(list)
        for items in self.samples.values():
            for row, sample in items:
                if sample["semantic"].endswith("REQUEST") and sample["transaction"] is not None:
                    requests[
                        (
                            row.sensor,
                            row.source,
                            row.source_port,
                            row.target,
                            row.target_port,
                            sample["transaction"],
                        )
                    ].append(sample["timestamp_us"])
        for key, target in targets.items():
            e = target.axis_evidence
            e["coverage_limited"] = (
                limited or self.global_limited or target.bucket_limited or len(target.sensors) > 1
            )
            groups: dict[tuple[str, int], dict[int, set[str]]] = defaultdict(
                lambda: defaultdict(set)
            )
            eligible: dict[str, set[int]] = defaultdict(set)
            for row, sample in self.samples.get(key, ()):
                e["sample_count"] += 1
                semantic = sample["semantic"]
                stamp = sample["timestamp_us"]
                if semantic.endswith("RESPONSE"):
                    e["response_samples"] += 1
                    request_key = (
                        row.sensor,
                        row.target,
                        row.target_port,
                        row.source,
                        row.source_port,
                        sample["transaction"],
                    )
                    if self.reverse_loss_overflow or request_key[:-1] in self.reverse_loss_scopes:
                        e["coverage_limited"] = True
                    if sample["transaction"] is not None and any(
                        0 <= stamp - t <= WINDOW_SECONDS * 1_000_000
                        for t in requests.get(request_key, ())
                    ):
                        e["matched_response_samples"] += 1
                elif semantic.endswith("REQUEST"):
                    e["request_samples"] += 1
                elif semantic == "OTHER":
                    e["direct_samples"] += 1
                # Reflector response synchrony is not evidence of compromised clients.
                if semantic in {"OTHER", "DNS_REQUEST", "NTP_REQUEST"}:
                    bucket = stamp // 1_000_000
                    groups[(sample["profile"], bucket // WINDOW_SECONDS)][bucket].add(row.source)
                    eligible[row.source].add(bucket)
            e["eligible_sources"] = sum(
                len(buckets) >= MIN_SHARED_BUCKETS for buckets in eligible.values()
            )
            for buckets in groups.values():
                for selected in combinations(sorted(buckets), MIN_SHARED_BUCKETS):
                    sources = set.intersection(*(buckets[b] for b in selected))
                    if len(sources) > e["coordinated_sources"]:
                        e["coordinated_sources"] = len(sources)
                        e["shared_buckets"] = MIN_SHARED_BUCKETS
