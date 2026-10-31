"""Bounded packet-window review hypotheses, never DDoS verdicts."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .ddos_attack import Observation

VERSION = "pcap-attack-guidance-v1"
WINDOW_SECONDS = 5
RESPONSE_HORIZON = timedelta(seconds=5)
MIN_PACKETS = 32
MAX_TARGETS = 256
MAX_WINDOWS = 8192
MAX_TARGET_WINDOWS = 512
MAX_SOURCES = 32
MAX_CANDIDATES = 32
MAX_BYTES = 128 * 1024
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
TargetKey = tuple[str, str, int | None, str]
ResponseKey = tuple[str, str, int | None, str, int | None]
ResponseEvent = tuple[datetime, bool, ResponseKey, TargetKey, int]


def stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass
class Window:
    first: datetime
    last: datetime
    packets: int = 0
    size: int = 0
    syn: int = 0
    ack: int = 0
    rst: int = 0
    payload: int = 0
    payload_visible: bool = True
    sources: set[str] = field(default_factory=set)
    sources_limited: bool = False


class GuidanceCollector:
    def __init__(self) -> None:
        self.targets: dict[TargetKey, dict[int, Window]] = {}
        self.windows = 0
        self.eligible = 0
        self.excluded = 0
        self.omitted = 0
        # Retained SYN/SYN-ACK observations, not tuple/bucket counters. The
        # global cap also bounds every pending FIFO and match map at finish.
        self.responses: list[ResponseEvent] = []
        self.response_omitted = 0

    def add(self, row: Observation) -> None:
        if (
            row.precision != "PACKET"
            or row.duration != 0
            or row.timestamp >= datetime(9999, 12, 31, 23, 59, 55, tzinfo=UTC)
        ):
            self.excluded += 1
            return
        self.eligible += 1
        key = row.role, row.target, row.target_port, row.protocol
        seconds = (row.timestamp - EPOCH) // timedelta(seconds=1)
        bucket = seconds // WINDOW_SECONDS * WINDOW_SECONDS
        if row.protocol == "TCP" and (row.syn_only or row.syn_ack):
            response_key = (
                row.sensor,
                row.source,
                row.source_port,
                row.target,
                row.target_port,
            )
            if row.syn_ack:
                response_key = (
                    row.sensor,
                    row.target,
                    row.target_port,
                    row.source,
                    row.source_port,
                )
            if len(self.responses) >= MAX_WINDOWS:
                self.response_omitted += 1
            else:
                self.responses.append((row.timestamp, bool(row.syn_ack), response_key, key, bucket))
        if key not in self.targets:
            if len(self.targets) >= MAX_TARGETS:
                self.omitted += 1
                return
            self.targets[key] = {}
        windows = self.targets[key]
        if bucket not in windows:
            if len(windows) >= MAX_TARGET_WINDOWS or self.windows >= MAX_WINDOWS:
                self.omitted += 1
                return
            windows[bucket] = Window(row.timestamp, row.timestamp)
            self.windows += 1
        window = windows[bucket]
        window.first = min(window.first, row.timestamp)
        window.last = max(window.last, row.timestamp)
        window.packets += 1
        window.size += row.size_bytes
        window.syn += row.syn_only
        window.ack += row.ack_only
        window.rst += row.rst
        window.payload += row.payload_packets
        window.payload_visible &= row.payload_visible
        if row.source not in window.sources:
            if len(window.sources) < MAX_SOURCES:
                window.sources.add(row.source)
            else:
                window.sources_limited = True

    def finish(self, job: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
        if report["summary"]["evaluated_records"] == 0:
            # Legacy traversal discards all measurements on input/numeric overflow.
            self.targets.clear()
            self.responses.clear()
            self.windows = self.eligible = self.excluded = self.omitted = self.response_omitted = 0
        candidates: list[dict[str, Any]] = []
        suppressed = 0
        matches: dict[tuple[TargetKey, int], int] = {}
        pending: dict[ResponseKey, deque[tuple[datetime, TargetKey, int]]] = {}
        # Timestamp order is independent of file order; requests precede
        # replies at equal timestamps. Sequence/ACK proof is unavailable:
        # this is temporal reverse-tuple counterevidence, not a handshake.
        for timestamp, reply, response_key, target_key, bucket in sorted(
            self.responses, key=lambda event: (event[0], event[1])
        ):
            requests = pending.setdefault(response_key, deque())
            while requests and timestamp - requests[0][0] > RESPONSE_HORIZON:
                requests.popleft()
            if not reply:
                requests.append((timestamp, target_key, bucket))
            elif requests:
                _, original_target, original_bucket = requests.popleft()
                match_key = original_target, original_bucket
                matches[match_key] = matches.get(match_key, 0) + 1
        for key, windows in self.targets.items():
            baseline_count = baseline_packets = 0
            for bucket, window in sorted(windows.items()):
                prior_count, prior_packets = baseline_count, baseline_packets
                # Quiet occupied windows are observations too. The sample floor
                # admits candidate windows, not their within-capture reference.
                baseline_count += 1
                baseline_packets += window.packets
                if window.packets < MIN_PACKETS:
                    continue
                relative = prior_count >= 3 and window.packets * prior_count >= 5 * prior_packets
                family = "SYN_CONCENTRATION"
                reason = "SYN_SHARE_HIGH"
                alternative = "LEGITIMATE_CONNECTION_SURGE"
                check = "CHECK_SYN_BACKLOG"
                volume = window.packets >= 1000 and (
                    window.packets / WINDOW_SECONDS >= 100
                    or window.size * 8 / WINDOW_SECONDS >= 1_000_000
                )
                if key[3] == "TCP" and window.syn * 5 >= window.packets * 4:
                    if matches.get((key, bucket), 0) * 5 >= window.syn * 4:
                        suppressed += 1
                        continue
                elif volume or relative:
                    reason = "ABSOLUTE_VOLUME" if volume else "RELATIVE_RATE_INCREASE"
                    alternative, check = "EXPECTED_SERVICE_BURST", "CHECK_SERVICE_REQUEST_RESPONSE"
                    if key[3] == "UDP":
                        family = "UDP_BURST"
                    elif key[3] in {"ICMP", "ICMPV6"}:
                        family, check = "ICMP_BURST", "CHECK_ICMP_OPERATIONS"
                    elif window.rst * 5 >= window.packets * 4:
                        family = "RST_BURST"
                        alternative, check = "MIDDLEBOX_OR_SERVER_RESETS", "CHECK_TCP_STATE"
                    elif (
                        window.ack * 5 >= window.packets * 4
                        and window.payload == 0
                        and window.payload_visible
                    ):
                        family = "PAYLOAD_FREE_ACK_BURST"
                        alternative, check = "ASYMMETRIC_TCP_CAPTURE", "CHECK_TCP_STATE"
                    else:
                        continue
                else:
                    continue
                uncertainty = [
                    "INTENT_AND_IMPACT_UNCONFIRMED",
                    "REVERSE_VISIBILITY_UNKNOWN",
                    "WITHIN_CAPTURE_NOT_KNOWN_NORMAL"
                    if prior_count >= 3
                    else "WITHIN_CAPTURE_BASELINE_UNAVAILABLE",
                ]
                if len(window.sources) < 20:
                    uncertainty.append("LOW_SOURCE_DIVERSITY")
                if (window.last - window.first).total_seconds() < 3:
                    uncertainty.append("SHORT_OBSERVATION")
                candidates.append(
                    {
                        "family": family,
                        "role": key[0],
                        "target": {"ip": key[1], "port": key[2], "protocol": key[3]},
                        "window_start": stamp(EPOCH + timedelta(seconds=bucket)),
                        "window_end": stamp(EPOCH + timedelta(seconds=bucket + WINDOW_SECONDS)),
                        "first_seen": stamp(window.first),
                        "last_seen": stamp(window.last),
                        "packet_count": window.packets,
                        "byte_count": window.size,
                        "source_count": len(window.sources),
                        "source_count_is_lower_bound": window.sources_limited,
                        "source_examples": sorted(window.sources)[:8],
                        "syn_only_count": window.syn,
                        "ack_only_count": window.ack,
                        "rst_count": window.rst,
                        "payload_packet_count": window.payload,
                        "payload_visibility_complete": window.payload_visible,
                        "baseline_window_count": prior_count if prior_count >= 3 else 0,
                        "baseline_packet_count": prior_packets if prior_count >= 3 else 0,
                        "reason_codes": [reason],
                        "uncertainty_codes": sorted(uncertainty),
                        "alternative_codes": [alternative],
                        "next_check_codes": ["CHECK_BIDIRECTIONAL_CAPTURE", check],
                    }
                )
        qualifying = len(candidates)
        strongest: dict[tuple[str, str, int | None, str], dict[str, Any]] = {}
        for candidate in candidates:
            target = candidate["target"]
            identity = candidate["role"], target["ip"], target["port"], target["protocol"]
            previous = strongest.get(identity)
            if previous is None or candidate["packet_count"] > previous["packet_count"]:
                strongest[identity] = candidate
        candidates = sorted(
            strongest.values(),
            key=lambda item: (
                -item["packet_count"],
                item["target"]["ip"],
                -1 if item["target"]["port"] is None else item["target"]["port"],
                item["target"]["protocol"],
                item["role"],
                item["window_start"],
            ),
        )[:MAX_CANDIDATES]
        source_summary = report["summary"]
        coverage = set()
        warning_map = {
            "INPUT_RECORD_LIMIT_REACHED": "INPUT_LIMIT",
            "PARSER_SKIPPED_PACKETS": "PARSER_GAPS",
            "SENSOR_DROPS_REPORTED": "SENSOR_DROPS",
            "SENSOR_CLOCK_SKEW": "CLOCK_SKEW",
            "PARTIAL_CAPTURE": "CAPTURE_PARTIAL",
            "SENSOR_CAPTURE_QUALITY_UNAVAILABLE": "CAPTURE_QUALITY_UNKNOWN",
            "DUPLICATE_CAPTURE_NOT_EXCLUDED": "DUPLICATE_CAPTURE_POSSIBLE",
        }
        for warning in report["warnings"]:
            if warning in warning_map:
                coverage.add(warning_map[warning])
        if not source_summary["coverage_complete"]:
            coverage.add("DDOS_COVERAGE_LIMITED")
        if self.excluded:
            coverage.add("INELIGIBLE_RECORDS")
        if source_summary["skipped_records"]:
            coverage.add("RECORDS_REJECTED")
        if self.omitted:
            coverage.add("WINDOW_STATE_LIMIT")
        if self.response_omitted:
            coverage.add("RESPONSE_STATE_LIMIT")
        summary = {
            name: source_summary[name]
            for name in ("scanned_records", "evaluated_records", "packet_count", "byte_count")
        }
        summary.update(
            {
                "eligible_packet_count": self.eligible,
                "excluded_record_count": self.excluded,
                "rejected_record_count": source_summary["skipped_records"],
                "retained_target_count": len(self.targets),
                "retained_window_count": self.windows,
                "omitted_observation_count": self.omitted,
                "response_state_count": len(self.responses),
                "response_omitted_count": self.response_omitted,
                "suppressed_handshake_window_count": suppressed,
                "qualifying_window_count": qualifying,
                "candidate_count": len(candidates),
                "omitted_candidate_count": len(strongest) - len(candidates),
                "coverage_complete": not coverage,
                "first_seen": stamp(datetime.fromisoformat(source_summary["first_seen"]))
                if source_summary["first_seen"]
                else None,
                "last_seen": stamp(datetime.fromisoformat(source_summary["last_seen"]))
                if source_summary["last_seen"]
                else None,
            }
        )
        result = {
            "version": VERSION,
            "job_id": job["id"],
            "dataset_id": job["dataset_id"],
            "status": "REVIEW_CANDIDATES"
            if candidates
            else ("NO_CANDIDATE" if self.eligible >= MIN_PACKETS else "INSUFFICIENT_OBSERVATION"),
            "summary": summary,
            "coverage_codes": sorted(coverage),
            "limitations": [
                "REVIEW_NOT_ATTACK_CLASSIFICATION",
                "NO_CANDIDATE_NOT_CLEAN",
                "L7_NOT_ASSESSED",
                "OBSERVED_SOURCES_NOT_ACTORS",
            ],
            "candidates": candidates,
        }
        while len(canonical_bytes(result)) > MAX_BYTES and candidates:
            candidates.pop()
            summary["candidate_count"] -= 1
            summary["omitted_candidate_count"] += 1
        if len(canonical_bytes(result)) > MAX_BYTES:
            raise ValueError("guidance metadata exceeds byte budget")
        if not candidates:
            result["status"] = (
                "NO_CANDIDATE" if self.eligible >= MIN_PACKETS else "INSUFFICIENT_OBSERVATION"
            )
        return result


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        + "\n"
    ).encode("utf-8")
