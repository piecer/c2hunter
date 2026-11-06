"""Closed wire contracts for bounded IP investigations (no execution authority)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, field_validator

from .ai_investigation_contract import (
    Counts,
    Digest,
    Frozen,
    InvestigationScope,
    Metric,
    SourceBinding,
    ToolName,
)

VERSION: Literal["ip-investigation-v1"] = "ip-investigation-v1"
SNAPSHOT_LIMIT = 128 * 1024
RETAINED_EVIDENCE_LIMIT = 128 * 1024
FINAL_LIMIT = 16 * 1024
SOURCE_RESERVATION_BYTES = 8 * 1024 * 1024 + 256 * 1024
Text = Annotated[str, Field(min_length=1, max_length=600)]
Key = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[!-~]+$")]
Verdict = Literal["SUSPICIOUS_C2", "BENIGN_HYPOTHESIS", "NEEDS_REVIEW", "INCONCLUSIVE"]
Status = Literal[
    "QUEUED",
    "PREPARING",
    "INVESTIGATING",
    "VALIDATING",
    "COMPLETED",
    "PARTIAL",
    "FAILED",
    "CANCELLED",
]


class ModelSettings(Frozen):
    temperature: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    context_tokens: Annotated[int, Field(ge=8192, le=262144)]
    max_output_tokens: Annotated[int, Field(ge=1, le=16384)]
    timeout_seconds: Annotated[float, Field(gt=0, le=600, allow_inf_nan=False)]


class ExecutionIdentity(Frozen):
    """Declared configuration, not proof of immutable provider model weights."""

    version: Literal["ip-investigation-execution-v1"] = "ip-investigation-execution-v1"
    provider: Literal["ollama", "openai-compatible"]
    model: Annotated[str, Field(min_length=1, max_length=512)]
    model_settings: ModelSettings
    model_config_sha256: Digest
    prompt_version: Literal["ip-investigation-prompt-v1"] = "ip-investigation-prompt-v1"
    prompt_sha256: Digest
    action_schema_sha256: Digest
    final_schema_sha256: Digest
    policy_version: Literal["ip-investigation-policy-v1"] = "ip-investigation-policy-v1"
    policy_sha256: Digest
    evidence_version: Literal["ip-evidence-v1"] = "ip-evidence-v1"

    @field_validator("model")
    @classmethod
    def _model_identifier(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid model identifier")
        return value


class ExecutionBinding(Frozen):
    version: Literal["ip-investigation-binding-v1"] = "ip-investigation-binding-v1"
    source: SourceBinding
    execution: ExecutionIdentity


class InvestigationRequest(InvestigationScope):
    version: Literal["ip-investigation-v1"] = VERSION
    mode: Literal["IP"] = "IP"
    question: Annotated[str, Field(min_length=1, max_length=2000)]
    language: Literal["ko", "en"] = "ko"
    idempotency_key: Key
    expected_source_sha256: Digest
    allow_remote: bool = False

    @field_validator("question")
    @classmethod
    def _question(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 8000 or "\x00" in value or not value.strip():
            raise ValueError("invalid question")
        return value

    def scope(self) -> InvestigationScope:
        return InvestigationScope.model_validate(
            {name: getattr(self, name) for name in InvestigationScope.model_fields}
        )


class EmptyArgs(Frozen):
    pass


class SampleArgs(Frozen):
    limit: Annotated[int, Field(ge=1, le=50)] = 50


class TimelineArgs(Frozen):
    limit: Annotated[int, Field(ge=1, le=120)] = 120


class CohortArgs(Frozen):
    limit: Annotated[int, Field(ge=1, le=20)] = 20


class OverviewCall(Frozen):
    tool: Literal["peer_overview"]
    arguments: EmptyArgs


class SampleCall(Frozen):
    tool: Literal["peer_flow_samples"]
    arguments: SampleArgs


class TimelineCall(Frozen):
    tool: Literal["peer_timeline"]
    arguments: TimelineArgs


class ProtocolCall(Frozen):
    tool: Literal["peer_protocol_observations"]
    arguments: SampleArgs


class CohortCall(Frozen):
    tool: Literal["compare_peer_cohort"]
    arguments: CohortArgs


ToolCall = Annotated[
    OverviewCall | SampleCall | TimelineCall | ProtocolCall | CohortCall,
    Field(discriminator="tool"),
]


class RequestTools(Frozen):
    action: Literal["request_tools"]
    tools: Annotated[tuple[ToolCall, ...], Field(min_length=1, max_length=3)]


class Interpretation(Frozen):
    text: Text
    evidence_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=3)]
    metric_refs: Annotated[tuple[Annotated[str, Field(max_length=128)], ...], Field(max_length=3)]


class Finish(Frozen):
    action: Literal["finish"]
    verdict: Verdict
    support: Annotated[tuple[Interpretation, ...], Field(max_length=4)]
    counterevidence: Annotated[tuple[Interpretation, ...], Field(max_length=4)]
    uncertainty: Annotated[tuple[Text, ...], Field(min_length=1, max_length=4)]
    next_checks: Annotated[tuple[Text, ...], Field(max_length=4)]


ACTION: TypeAdapter[RequestTools | Finish] = TypeAdapter(
    Annotated[RequestTools | Finish, Field(discriminator="action")]
)


class Progress(Frozen):
    source_bytes_accounting: Literal["RESERVED_READER_UPPER_BOUND_NOT_MEASURED"] = (
        "RESERVED_READER_UPPER_BOUND_NOT_MEASURED"
    )
    model_calls: Annotated[int, Field(ge=0, le=6)] = 0
    tool_calls: Annotated[int, Field(ge=0, le=12)] = 0
    transport_attempts: Annotated[int, Field(ge=0, le=12)] = 0
    source_bytes: Annotated[int, Field(ge=0)] = 0
    source_records: Annotated[int, Field(ge=0)] = 0


class InvestigationStep(Frozen):
    version: Literal["ip-investigation-v1"] = VERSION
    sequence: Annotated[int, Field(ge=1, le=24)]
    kind: Literal["SOURCE", "MODEL", "TOOL", "FINAL"]
    progress: Progress
    tool: ToolName | None = None
    evidence_id: Digest | None = None
    code: Annotated[str, Field(max_length=64)] | None = None


class EvidenceQuality(Frozen):
    evidence_id: Digest
    tool: ToolName
    status: Literal["OBSERVED", "NOT_OBSERVED", "UNAVAILABLE", "NOT_FOUND_IN_INSPECTED_SCOPE"]
    counts: Counts


class InvestigationResult(Frozen):
    version: Literal["ip-investigation-v1"] = VERSION
    verdict: Verdict
    mode: Literal["MODEL_ASSISTED", "FACTS_ONLY"]
    language: Literal["ko", "en"]
    source: SourceBinding
    scope: InvestigationScope
    counts: Counts
    facts: Annotated[tuple[Metric, ...], Field(max_length=24)]
    evidence_quality: Annotated[tuple[EvidenceQuality, ...], Field(min_length=1, max_length=12)]
    support: tuple[Interpretation, ...]
    counterevidence: tuple[Interpretation, ...]
    uncertainty: tuple[Text, ...]
    next_checks: tuple[Text, ...]
    limitations: tuple[str, ...]
    partial_scope: Literal[True] = True
    reason: Annotated[str, Field(max_length=64)] | None = None
    execution: ExecutionIdentity
    progress: Progress


class InvestigationFailure(Frozen):
    version: Literal["ip-investigation-v1"] = VERSION
    kind: Literal["FAILURE"] = "FAILURE"
    reason: Annotated[str, Field(max_length=64)]
    execution: ExecutionIdentity
    progress: Progress


RESULT: TypeAdapter[InvestigationResult | InvestigationFailure] = TypeAdapter(
    InvestigationResult | InvestigationFailure
)


class InvestigationRun(Frozen):
    version: Literal["ip-investigation-v1"] = VERSION
    id: Digest
    owner_id: Key
    job_id: Key
    status: Status
    revision: Annotated[int, Field(ge=0)]
    created_at: float
    request: InvestigationRequest
    target_ip: str
    language: Literal["ko", "en"]
    scope: InvestigationScope
    execution: ExecutionIdentity
    progress: Progress
    result: InvestigationResult | InvestigationFailure | None = None
    reason: str | None = None


class InvestigationCapabilities(Frozen):
    version: Literal["ip-investigation-v1"] = VERSION
    availability: Literal["CONFIGURED_NOT_PROBED", "UNAVAILABLE"]
    modes: tuple[Literal["IP"], ...] = ("IP",)
    snapshot_bytes: int = SNAPSHOT_LIMIT
    retained_evidence_bytes: int = RETAINED_EVIDENCE_LIMIT
    source_reservation_bytes: int = SOURCE_RESERVATION_BYTES
    source_bytes_accounting: Literal["RESERVED_READER_UPPER_BOUND_NOT_MEASURED"] = (
        "RESERVED_READER_UPPER_BOUND_NOT_MEASURED"
    )
    preparation_concurrency: Literal[2] = 2
    preparation_concurrency_scope: Literal["PROCESS_ONLY"] = "PROCESS_ONLY"
    max_model_calls: Literal[6] = 6
    max_tool_calls: Literal[12] = 12
    max_planning_responses: Literal[4] = 4
    max_transport_attempts: Literal[12] = 12
    deadline_seconds: Literal[300] = 300
    remote_server_allowed: bool


class SourcePreview(Frozen):
    version: Literal["ip-investigation-v1"] = VERSION
    source: SourceBinding
    scope: InvestigationScope
    status: Literal["OBSERVED", "NOT_OBSERVED", "UNAVAILABLE", "NOT_FOUND_IN_INSPECTED_SCOPE"]
    counts: Counts
    snapshot_bytes: int
    limitations: tuple[str, ...]
