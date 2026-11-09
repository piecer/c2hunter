"""Finite both-endpoint inventory; no legacy candidate hydration or identity."""

from typing import Any

from .ai_investigation_contract import InvestigationError, SourceSnapshot, canonical_bytes, digest
from .ai_job_investigation_schema import (
    POLICY_VERSION,
    POOL_BYTES,
    POOL_LIMITATIONS,
    POOL_PEERS,
    DiscoveryCoverage,
    JobPool,
    PeerSummary,
    endpoint_counts,
    finite_score,
    pool_digest,
)


def build_pool(
    snapshot: SourceSnapshot, scores: dict[str, float], coverage: DiscoveryCoverage
) -> JobPool:
    counts = endpoint_counts(snapshot)
    if not scores.keys() <= counts.keys():
        raise InvestigationError("SOURCE_INVALID")
    scores = {ip: finite_score(score) for ip, score in scores.items()}
    ordered = sorted(counts, key=lambda ip: (0 if ip in scores else 1, -scores.get(ip, 0), ip))
    # Never instantiate a DTO for an entry that cannot survive the count bound.
    entries = tuple(
        PeerSummary(
            peer_id=digest([snapshot.binding.source_sha256, ip]),
            ip=ip,
            matched_rows=sum(counts[ip]),
            eligible_rows=counts[ip][0],
            suppressed_control_rows=counts[ip][1],
            eligibility_unavailable_rows=counts[ip][2],
            behavior_state=(
                "PRIORITIZED"
                if ip in scores
                else "UNAVAILABLE"
                if coverage.state == "UNAVAILABLE"
                else "NOT_PRIORITIZED"
            ),
            behavior_score=scores.get(ip),
        ).model_dump()
        for ip in ordered[:POOL_PEERS]
    )

    def envelope(retained: int) -> dict[str, Any]:
        omitted = len(counts) - retained
        return dict(
            version="job-investigation-pool-v1",
            source_sha256=snapshot.binding.source_sha256,
            policy_version=POLICY_VERSION,
            entries=entries[:retained],
            observed_peers=len(counts),
            omitted_peers=omitted,
            omitted_identities="NOT_RETAINED" if omitted else "NONE",
            legacy_membership="NOT_READ",
            discovery=coverage.model_dump(),
            limitations=POOL_LIMITATIONS,
            pool_sha256="0" * 64,
        )

    # Complete prefix rollback: <= 8 encodes for the fixed 32-entry policy.
    if len(canonical_bytes(envelope(0))) > POOL_BYTES:
        raise InvestigationError("SOURCE_LIMIT")
    low, high = 0, len(entries)
    while low < high:
        middle = (low + high + 1) // 2
        if len(canonical_bytes(envelope(middle))) <= POOL_BYTES:
            low = middle
        else:
            high = middle - 1
    data = envelope(low)
    data["pool_sha256"] = pool_digest(data)
    return JobPool.model_validate(data)
