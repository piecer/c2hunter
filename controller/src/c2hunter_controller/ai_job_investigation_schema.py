"""Closed JOB source/pool contracts; no run, dispatch or model authority."""

from __future__ import annotations

import json
from math import isfinite
from struct import pack
from typing import Annotated, Any, ClassVar, Literal, Self, cast, get_args

from pydantic import BeforeValidator, Field, field_validator, model_validator

from .ai_investigation_contract import (
    Digest,
    Frozen,
    InvestigationError,
    InvestigationScope,
    SourceSnapshot,
    canonical_bytes,
    digest,
    literal_ip,
)
from .ai_investigation_schema import Key

POOL_PEERS = 32
POOL_BYTES = 16384
PREPARATION_BYTES = 131072
POLICY_VERSION = "job-investigation-policy-v1"
POOL_LIMITATIONS = (
    "CAPTURE_COMPLETENESS_UNKNOWN",
    "CURRENT_JOB_ONLY_NOT_VALIDATED",
    "HISTORICAL_COMPARISON_UNSUPPORTED",
)


Reason = Literal[
    "INVALID_SOURCE_ARGUMENTS",
    "SOURCE_NOT_FOUND",
    "SOURCE_INVALID",
    "SOURCE_UNAVAILABLE",
    "SOURCE_STATE",
    "SOURCE_CHANGED",
    "SOURCE_LIMIT",
    "SOURCE_BUSY",
    "SOURCE_STORAGE_UNAVAILABLE",
    "PEER_OUT_OF_POOL",
    "INVALID_REQUEST",
    "JOB_DISABLED",
    "JOB_DISPATCH_UNSUPPORTED",
    "UNAVAILABLE",
    "REMOTE_NOT_ALLOWED",
    "POOL_EMPTY",
    "POOL_REFERENCE_MISMATCH",
    "PEER_NOT_SELECTED",
    "INVALID_SELECTION_STATE",
    "MODEL_INVALID",
    "MODEL_UNAVAILABLE",
    "MODEL_LIMIT",
    "MODEL_BUDGET",
    "TOOL_BUDGET",
    "PLANNING_BUDGET",
    "EVIDENCE_BUDGET",
    "REFERENCE_MISMATCH",
    "COUNTEREVIDENCE_REQUIRED",
    "POSITIVE_UNSUPPORTED",
    "FINAL_LIMIT",
    "DEADLINE_EXCEEDED",
    "EXECUTION_IDENTITY_CHANGED",
    "INCOMPLETE_ASSESSMENT",
    "USER_CANCELLED",
    "WORKER_EXITED",
    "CLOCK_ROLLBACK",
    "QUEUE_EXPIRED",
    "OWNER_LOST",
    "JOB_RESPONSE_LIMIT",
]
REASON_CODES = frozenset(get_args(Reason))


class JobFrozen(Frozen):
    wire_limit: ClassVar[int] = PREPARATION_BYTES

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        if type(json_data) not in (str, bytes, bytearray):
            raise ValueError("JSON bytes required")
        if len(json_data) > cls.wire_limit:
            raise ValueError("SOURCE_LIMIT")
        raw = json_data.encode("utf-8") if isinstance(json_data, str) else bytes(json_data)
        if len(raw) > cls.wire_limit:
            raise ValueError("SOURCE_LIMIT")

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate JSON member")
                result[key] = value
            return result

        def constant(value: str) -> None:
            raise ValueError("nonfinite JSON number")

        try:
            json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
            return super().model_validate_json(raw, **kwargs)
        except RecursionError:
            raise ValueError("JSON nesting limit") from None


class JobRequest(JobFrozen):
    wire_limit: ClassVar[int] = 16384
    version: Literal["job-investigation-v1"]
    mode: Literal["JOB"]
    experimental: Literal[True]
    question: Annotated[str, Field(min_length=1, max_length=2000)]
    language: Literal["ko", "en"]
    idempotency_key: Key
    expected_source_sha256: Digest | None
    allow_remote: bool
    baseline_mode: Literal["off"]

    @field_validator("experimental", mode="before")
    @classmethod
    def _opt_in(cls, value: object) -> object:
        if value is not True:
            raise ValueError("explicit experimental opt-in required")
        return value

    @field_validator("question")
    @classmethod
    def _question(cls, value: str) -> str:
        if not value.strip() or "\x00" in value or len(value.encode("utf-8")) > 8000:
            raise ValueError("invalid question")
        return value


class Selection(JobFrozen):
    wire_limit: ClassVar[int] = 1024
    state: Literal["PENDING", "COMMITTED"]
    peer_ids: Annotated[tuple[Digest, ...], Field(max_length=3)]

    @model_validator(mode="after")
    def _semantics(self) -> Self:
        if len(set(self.peer_ids)) != len(self.peer_ids):
            raise ValueError("duplicate peer reference")
        if (self.state == "PENDING") != (len(self.peer_ids) == 0):
            raise ValueError("selection state mismatch")
        return self


def integral(value: object) -> int:
    if type(value) not in (int, float):
        raise ValueError("finite integral primitive required")
    number = cast("int | float", value)
    if not -(2**53 - 1) <= number <= 2**53 - 1:
        raise ValueError("safe integer required")
    if not isfinite(number) or number != int(number):
        raise ValueError("finite integral primitive required")
    return int(number)


def finite_score(value: object) -> float:
    if type(value) not in (int, float):
        raise ValueError("finite nonnegative primitive required")
    try:
        number = float(cast("int | float", value))
    except OverflowError:
        raise ValueError("finite binary64 required") from None
    if not isfinite(number) or number < 0:
        raise ValueError("finite nonnegative primitive required")
    return number if number else 0.0


Integral = Annotated[int, BeforeValidator(integral)]
Score = Annotated[float, BeforeValidator(finite_score)]


def pool_digest(data: dict[str, Any]) -> str:
    """Portable preimage; scores use normalized binary64, counters integral."""
    value = {k: v for k, v in data.items() if k != "pool_sha256"}
    value["entries"] = [dict(entry) for entry in value["entries"]]
    for entry in value["entries"]:
        if entry["behavior_score"] is not None:
            entry["behavior_score"] = pack(">d", finite_score(entry["behavior_score"])).hex()
        for name in (
            "matched_rows",
            "eligible_rows",
            "suppressed_control_rows",
            "eligibility_unavailable_rows",
        ):
            entry[name] = integral(entry[name])
    for name in ("observed_peers", "omitted_peers"):
        value[name] = integral(value[name])
    value["discovery"] = dict(value["discovery"])
    for name in ("examined_peers", "excluded_peers"):
        if value["discovery"][name] is not None:
            value["discovery"][name] = integral(value["discovery"][name])
    return digest(value)


class PeerSummary(JobFrozen):
    peer_id: Digest
    ip: str
    matched_rows: Annotated[Integral, Field(ge=1, le=8192)]
    eligible_rows: Annotated[Integral, Field(ge=0, le=8192)]
    suppressed_control_rows: Annotated[Integral, Field(ge=0, le=8192)]
    eligibility_unavailable_rows: Annotated[Integral, Field(ge=0, le=8192)]
    behavior_state: Literal["PRIORITIZED", "NOT_PRIORITIZED", "UNAVAILABLE"]
    behavior_score: Score | None

    @field_validator("ip")
    @classmethod
    def _ip(cls, value: str) -> str:
        if value != literal_ip(value):
            raise ValueError("canonical IP required")
        return value

    @model_validator(mode="after")
    def _semantics(self) -> Self:
        if self.matched_rows != (
            self.eligible_rows + self.suppressed_control_rows + self.eligibility_unavailable_rows
        ):
            raise ValueError("peer count equation")
        if (self.behavior_state == "PRIORITIZED") != (self.behavior_score is not None):
            raise ValueError("behavior score/state mismatch")
        return self


def peer_order(peer: PeerSummary) -> tuple[int, float, str]:
    return (0 if peer.behavior_state == "PRIORITIZED" else 1, -(peer.behavior_score or 0), peer.ip)


class DiscoveryCoverage(JobFrozen):
    state: Literal["AVAILABLE", "PARTIAL", "UNAVAILABLE"]
    examined_peers: Annotated[Integral, Field(ge=0, le=16384)] | None
    excluded_peers: Annotated[Integral, Field(ge=0, le=16384)] | None
    warnings: Annotated[tuple[Annotated[str, Field(max_length=1000)], ...], Field(max_length=32)]

    @model_validator(mode="after")
    def _semantics(self) -> Self:
        unknown = self.examined_peers is None and self.excluded_peers is None
        known = self.examined_peers is not None and self.excluded_peers is not None
        if not (unknown if self.state == "UNAVAILABLE" else known):
            raise ValueError("discovery count availability")
        if self.state == "AVAILABLE" and (self.warnings or self.excluded_peers):
            raise ValueError("incomplete discovery mislabeled available")
        return self


class JobPool(JobFrozen):
    wire_limit: ClassVar[int] = POOL_BYTES
    version: Literal["job-investigation-pool-v1"]
    source_sha256: Digest
    policy_version: Literal["job-investigation-policy-v1"]
    pool_sha256: Digest
    entries: Annotated[tuple[PeerSummary, ...], Field(max_length=32)]
    observed_peers: Annotated[Integral, Field(ge=0, le=16384)]
    omitted_peers: Annotated[Integral, Field(ge=0, le=16384)]
    omitted_identities: Literal["NOT_RETAINED", "NONE"]
    legacy_membership: Literal["NOT_READ"]
    discovery: DiscoveryCoverage
    limitations: Annotated[tuple[Annotated[str, Field(max_length=128)], ...], Field(max_length=32)]

    @model_validator(mode="after")
    def _semantics(self) -> Self:
        if (
            self.observed_peers != len(self.entries) + self.omitted_peers
            or self.omitted_identities != ("NOT_RETAINED" if self.omitted_peers else "NONE")
            or len({p.ip for p in self.entries}) != len(self.entries)
            or len({p.peer_id for p in self.entries}) != len(self.entries)
            or tuple(sorted(self.entries, key=peer_order)) != self.entries
            or self.limitations != POOL_LIMITATIONS
        ):
            raise ValueError("invalid pool semantics")
        for peer in self.entries:
            if peer.peer_id != digest([self.source_sha256, peer.ip]):
                raise ValueError("peer source identity mismatch")
            if (self.discovery.state == "UNAVAILABLE") != (peer.behavior_state == "UNAVAILABLE"):
                raise ValueError("peer discovery mismatch")
        if self.discovery.examined_peers is not None:
            if (
                self.discovery.examined_peers + (self.discovery.excluded_peers or 0)
                > self.observed_peers
            ):
                raise ValueError("discovery exceeds observations")
            if (
                sum(p.behavior_state == "PRIORITIZED" for p in self.entries)
                > self.discovery.examined_peers
            ):
                raise ValueError("priority exceeds examined peers")
        if len(canonical_bytes(self.model_dump())) > POOL_BYTES:
            raise InvestigationError("SOURCE_LIMIT")
        if pool_digest(self.model_dump()) != self.pool_sha256:
            raise ValueError("pool commitment mismatch")
        return self


def endpoint_counts(snapshot: SourceSnapshot) -> dict[str, list[int]]:
    counts: dict[str, list[int]] = {}
    for row in snapshot.rows:
        slot = {"ELIGIBLE": 0, "SUPPRESSED_OUTBOUND_CONTROL": 1, "UNAVAILABLE": 2}[
            row.c2_eligibility
        ]
        for ip in {row.source_ip, row.destination_ip}:
            counts.setdefault(ip, [0, 0, 0])[slot] += 1
    return counts


class JobPreparation(JobFrozen):
    snapshot: SourceSnapshot
    pool: JobPool

    def scope_for_peer(self, peer_id: str) -> InvestigationScope:
        # Also recheck model_copy updates before exposing an evidence scope.
        checked = JobPreparation.model_validate(self)
        for peer in checked.pool.entries:
            if peer.peer_id == peer_id:
                return InvestigationScope(target_ip=peer.ip, endpoint_side="either")
        raise InvestigationError("PEER_OUT_OF_POOL")

    @model_validator(mode="after")
    def _agreement(self) -> Self:
        if self.snapshot.binding.source_sha256 != self.pool.source_sha256:
            raise ValueError("preparation source mismatch")
        if len(canonical_bytes(self.model_dump())) > PREPARATION_BYTES:
            raise InvestigationError("SOURCE_LIMIT")
        counts = endpoint_counts(self.snapshot)
        if len(counts) != self.pool.observed_peers:
            raise ValueError("preparation observed count mismatch")
        for peer in self.pool.entries:
            if counts.get(peer.ip) != [
                peer.eligible_rows,
                peer.suppressed_control_rows,
                peer.eligibility_unavailable_rows,
            ]:
                raise ValueError("preparation peer counts mismatch")
        return self
