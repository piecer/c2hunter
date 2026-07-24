from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime

from .domain import AllowlistEntry, Candidate, Evidence, ScoreAdjustment

CAPS = {
    "COMMON_DESTINATION": 20,
    "PERIODIC_BEACON": 15,
    "SYNCHRONIZED_COMMUNICATION": 15,
    "COMMAND_ATTACK_CORRELATION": 25,
    "MULTI_SENSOR_CONTEXT": 10,
    "PROTOCOL_PAYLOAD_SIMILARITY": 10,
    "LOW_VOLUME_PERSISTENCE_RARITY": 5,
    "SINGLE_HOST_BEACON": 35,
    "ANALYST_PAYLOAD_SIGNATURE": 80,
    "NON_WELL_KNOWN_PORT": 25,
}


def severity_for(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def score_candidates(
    evidence: Iterable[Evidence],
    *,
    allowlist: Sequence[AllowlistEntry] = (),
    minimum_samples: int = 1,
    traffic_profiles: Mapping[str, Mapping[str, int | float]] | None = None,
    high_volume_bytes_threshold: int = 50 * 1024 * 1024,
    high_volume_packet_threshold: int = 100_000,
    high_volume_penalty: int = 30,
    now: datetime | None = None,
) -> list[Candidate]:
    grouped: dict[str, list[Evidence]] = defaultdict(list)
    for item in evidence:
        grouped[item.candidate_ip].append(item)
    instant = now or datetime.now(UTC)
    candidates: list[Candidate] = []
    for candidate_ip, items in grouped.items():
        if any(entry.matches(candidate_ip, items, instant) for entry in allowlist):
            continue
        by_type: dict[str, float] = defaultdict(float)
        for item in items:
            by_type[item.type] += max(0, item.contribution)
        score = sum(min(CAPS.get(kind, 0), value) for kind, value in by_type.items())
        hosts = sorted({host for item in items for host in item.hosts})
        sensors = sorted({sensor for item in items for sensor in item.sensors})
        adjustments: list[ScoreAdjustment] = []
        exact_analyst_match = any(
            item.type == "ANALYST_PAYLOAD_SIGNATURE" and item.metrics.get("match_mode") == "EXACT"
            for item in items
        )
        if len(hosts) == 1 and not exact_analyst_match:
            points = -10 if any(item.type == "SINGLE_HOST_BEACON" for item in items) else -20
            adjustments.append(ScoreAdjustment("SINGLE_HOST", points, "단일 내부 호스트 관찰"))
        sample_count = max(
            (int(item.metrics.get("sample_count", minimum_samples)) for item in items), default=0
        )
        if sample_count < minimum_samples and not exact_analyst_match:
            adjustments.append(ScoreAdjustment("LOW_SAMPLE", -20, "분석 표본 부족"))
        if any(item.metrics.get("public_dns_ntp") for item in items):
            adjustments.append(ScoreAdjustment("PUBLIC_DNS_NTP", -30, "공용 DNS/NTP 정책 일치"))
        if any(item.metrics.get("cdn_cloud") for item in items):
            adjustments.append(ScoreAdjustment("CDN_CLOUD", -20, "CDN/cloud 정책 일치"))
        profile = (traffic_profiles or {}).get(candidate_ip, {})
        total_bytes = max(0, int(profile.get("total_bytes", 0) or 0))
        total_packets = max(0, int(profile.get("total_packets", 0) or 0))
        volume_reasons = []
        if high_volume_bytes_threshold > 0 and total_bytes >= high_volume_bytes_threshold:
            volume_reasons.append(
                f"bytes {total_bytes:,} >= {high_volume_bytes_threshold:,}"
            )
        if high_volume_packet_threshold > 0 and total_packets >= high_volume_packet_threshold:
            volume_reasons.append(
                f"packets {total_packets:,} >= {high_volume_packet_threshold:,}"
            )
        if volume_reasons and high_volume_penalty > 0 and not exact_analyst_match:
            adjustments.append(
                ScoreAdjustment(
                    "HIGH_VOLUME",
                    -abs(int(high_volume_penalty)),
                    "대용량 endpoint 통신: " + ", ".join(volume_reasons),
                )
            )
        final = max(0, min(100, round(score + sum(item.points for item in adjustments))))
        times = [time for item in items for time in (item.first_seen, item.last_seen) if time]
        candidates.append(
            Candidate(
                candidate_ip,
                final,
                severity_for(final),
                tuple(items),
                tuple(adjustments),
                tuple(hosts),
                tuple(sensors),
                min(times) if times else None,
                max(times) if times else None,
            )
        )
    return sorted(candidates, key=lambda item: (-item.score, item.candidate_ip))
