from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
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
        if len(hosts) == 1:
            adjustments.append(ScoreAdjustment("SINGLE_HOST", -20, "단일 내부 호스트 관찰"))
        sample_count = max(
            (int(item.metrics.get("sample_count", minimum_samples)) for item in items), default=0
        )
        if sample_count < minimum_samples:
            adjustments.append(ScoreAdjustment("LOW_SAMPLE", -20, "분석 표본 부족"))
        if any(item.metrics.get("public_dns_ntp") for item in items):
            adjustments.append(ScoreAdjustment("PUBLIC_DNS_NTP", -30, "공용 DNS/NTP 정책 일치"))
        if any(item.metrics.get("cdn_cloud") for item in items):
            adjustments.append(ScoreAdjustment("CDN_CLOUD", -20, "CDN/cloud 정책 일치"))
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
