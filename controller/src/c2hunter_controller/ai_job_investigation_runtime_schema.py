"""Closed JOB actions and saved projections, independent of legacy IP wire."""

from __future__ import annotations

import json
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import (
    Field,
    GetJsonSchemaHandler,
    TypeAdapter,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema

from .ai_investigation_contract import (
    Counts,
    Digest,
    Evidence,
    Metric,
    SourceBinding,
    ToolName,
    canonical_bytes,
)
from .ai_investigation_schema import EvidenceQuality, Key, Status, Verdict
from .ai_job_investigation_schema import (
    POOL_LIMITATIONS,
    Integral,
    JobFrozen,
    JobPool,
    JobRequest,
    Reason,
    Selection,
    integral,
)

Text = Annotated[str, Field(min_length=1, max_length=300)]
Count = Annotated[Integral, Field(ge=0, le=8192)]


def parse_job_evidence(raw: bytes) -> Evidence:
    """JOB wire-only integral normalization; source and IP parsers stay strict."""
    if type(raw) is not bytes or len(raw) > 32768:
        raise ValueError("evidence byte limit")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate member")
            value[key] = item
        return value

    schema = Evidence.model_json_schema()

    def normalize(value: Any, shape: dict[str, Any]) -> Any:
        if "$ref" in shape:
            return normalize(value, schema["$defs"][shape["$ref"].rsplit("/", 1)[-1]])
        if "anyOf" in shape:
            if value is None:
                return value
            options = [s for s in shape["anyOf"] if s.get("type") != "null"]
            return normalize(value, options[0]) if len(options) == 1 else value
        if shape.get("type") == "integer":
            return integral(value)
        if shape.get("type") == "object" and type(value) is dict:
            return {
                k: normalize(v, shape.get("properties", {}).get(k, {})) for k, v in value.items()
            }
        if shape.get("type") == "array" and type(value) is list:
            return [normalize(v, shape["items"]) for v in value]
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        return Evidence.model_validate_json(canonical_bytes(normalize(value, schema)))
    except (RecursionError, UnicodeError):
        raise ValueError("invalid evidence JSON") from None


class PublicFrozen(JobFrozen):
    @classmethod
    def __get_pydantic_json_schema__(
        cls, schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        value = handler.resolve_ref_schema(handler(schema))
        if "properties" in value:
            value["required"] = list(value["properties"])
        return value

    @model_validator(mode="after")
    def closed_wire(self, info: ValidationInfo) -> Self:
        if info.mode == "json" and not type(self).model_fields.keys() <= self.model_fields_set:
            raise ValueError("missing public wire member")
        return self

    @field_validator("partial_scope", "experimental", mode="before", check_fields=False)
    @classmethod
    def true_boolean(cls, value: object) -> object:
        if value is not True:
            raise ValueError("literal boolean required")
        return value


class JobModelSettings(PublicFrozen):
    temperature: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    context_tokens: Annotated[Integral, Field(ge=8192, le=262144)]
    max_output_tokens: Annotated[Integral, Field(ge=1, le=16384)]
    timeout_seconds: Annotated[float, Field(gt=0, le=600, allow_inf_nan=False)]


class JobExecutionIdentity(PublicFrozen):
    version: Literal["job-investigation-execution-v1"] = "job-investigation-execution-v1"
    provider: Literal["ollama", "openai-compatible"]
    model: Annotated[str, Field(min_length=1, max_length=512)]
    model_settings: JobModelSettings
    model_config_sha256: Digest
    prompt_version: Literal["job-investigation-prompt-v1"] = "job-investigation-prompt-v1"
    prompt_sha256: Digest
    action_schema_sha256: Digest
    final_schema_sha256: Digest
    policy_version: Literal["job-investigation-policy-v1"] = "job-investigation-policy-v1"
    policy_sha256: Digest
    evidence_version: Literal["ip-evidence-v1"] = "ip-evidence-v1"

    @field_validator("model")
    @classmethod
    def identifier(cls, value: str) -> str:
        if len(value.encode()) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid model identifier")
        return value


class JobBinding(PublicFrozen):
    version: Literal["job-investigation-binding-v1"] = "job-investigation-binding-v1"
    source: SourceBinding
    execution: JobExecutionIdentity
    pool_sha256: Digest


class JobProgress(PublicFrozen):
    source_bytes_accounting: Literal["RESERVED_READER_UPPER_BOUND_NOT_MEASURED"] = (
        "RESERVED_READER_UPPER_BOUND_NOT_MEASURED"
    )
    model_calls: Annotated[Integral, Field(ge=0, le=6)] = 0
    tool_calls: Annotated[Integral, Field(ge=0, le=12)] = 0
    transport_attempts: Annotated[Integral, Field(ge=0, le=12)] = 0
    source_bytes: Annotated[Integral, Field(ge=0, le=8650752)] = 0
    source_records: Count = 0
    planning_responses: Annotated[Integral, Field(ge=0, le=4)] = 0


class JobCoverage(PublicFrozen):
    source_status: Literal["COMPLETED", "PARTIALLY_COMPLETED"]
    source_rows: Count
    observed_peers: Annotated[Integral, Field(ge=0, le=16384)]
    pool_peers: Annotated[Integral, Field(ge=0, le=32)]
    pool_omitted_peers: Annotated[Integral, Field(ge=0, le=16384)]
    awaiting_selection_peers: Annotated[Integral, Field(ge=0, le=32)]
    not_selected_peers: Annotated[Integral, Field(ge=0, le=32)]
    selected_peers: Annotated[Integral, Field(ge=0, le=3)]
    investigated_peers: Annotated[Integral, Field(ge=0, le=3)]
    not_investigated_peers: Annotated[Integral, Field(ge=0, le=3)]
    unobserved_peer_count: None = None
    capture_completeness: Literal["UNKNOWN"] = "UNKNOWN"
    lineage: Literal["CURRENT_JOB_ONLY_NOT_VALIDATED"] = "CURRENT_JOB_ONLY_NOT_VALIDATED"
    whole_job_conclusion: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"

    @model_validator(mode="after")
    def equations(self) -> Self:
        if (
            self.observed_peers != self.pool_peers + self.pool_omitted_peers
            or self.pool_peers
            != self.awaiting_selection_peers + self.not_selected_peers + self.selected_peers
            or self.selected_peers != self.investigated_peers + self.not_investigated_peers
        ):
            raise ValueError("coverage equation")
        return self


class JobInterpretation(JobFrozen):
    text: Text
    evidence_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=3)]
    metric_refs: Annotated[tuple[Annotated[str, Field(max_length=128)], ...], Field(max_length=3)]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len(set(self.evidence_ids)) != len(self.evidence_ids) or len(
            set(self.metric_refs)
        ) != len(self.metric_refs):
            raise ValueError("duplicate reference")
        return self


class AssessmentAction(JobFrozen):
    peer_id: Digest
    verdict: Verdict
    support: Annotated[tuple[JobInterpretation, ...], Field(max_length=2)]
    counterevidence: Annotated[tuple[JobInterpretation, ...], Field(max_length=2)]
    uncertainty: Annotated[tuple[Text, ...], Field(min_length=1, max_length=2)]
    next_checks: Annotated[tuple[Text, ...], Field(max_length=2)]


class SelectPeers(JobFrozen):
    wire_limit: ClassVar[int] = 1024
    action: Literal["select_peers"]
    pool_sha256: Digest
    peer_ids: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=3)]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len(set(self.peer_ids)) != len(self.peer_ids):
            raise ValueError("duplicate peer")
        return self


class EmptyArgs(JobFrozen):
    pass


class SampleArgs(JobFrozen):
    limit: Annotated[Integral, Field(ge=1, le=50)] = 50


class TimelineArgs(JobFrozen):
    limit: Annotated[Integral, Field(ge=1, le=120)] = 120


class CohortArgs(JobFrozen):
    limit: Annotated[Integral, Field(ge=1, le=20)] = 20


class OverviewCall(JobFrozen):
    peer_id: Digest
    tool: Literal["peer_overview"]
    arguments: EmptyArgs


class SampleCall(JobFrozen):
    peer_id: Digest
    tool: Literal["peer_flow_samples", "peer_protocol_observations"]
    arguments: SampleArgs


class TimelineCall(JobFrozen):
    peer_id: Digest
    tool: Literal["peer_timeline"]
    arguments: TimelineArgs


class CohortCall(JobFrozen):
    peer_id: Digest
    tool: Literal["compare_peer_cohort"]
    arguments: CohortArgs


class RequestTools(JobFrozen):
    action: Literal["request_tools"]
    tools: Annotated[
        tuple[
            Annotated[
                OverviewCall | SampleCall | TimelineCall | CohortCall, Field(discriminator="tool")
            ],
            ...,
        ],
        Field(min_length=1, max_length=3),
    ]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len({canonical_bytes(c.model_dump(mode="json")) for c in self.tools}) != len(self.tools):
            raise ValueError("duplicate tool attempt")
        return self


class Finish(JobFrozen):
    action: Literal["finish"]
    assessments: Annotated[tuple[AssessmentAction, ...], Field(min_length=1, max_length=3)]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len({a.peer_id for a in self.assessments}) != len(self.assessments):
            raise ValueError("duplicate peer")
        return self


ACTION: TypeAdapter[SelectPeers | RequestTools | Finish] = TypeAdapter(
    Annotated[SelectPeers | RequestTools | Finish, Field(discriminator="action")]
)


def parse_action(raw: str) -> SelectPeers | RequestTools | Finish:
    # TypeAdapter.validate_json bypasses JobFrozen.model_validate_json. Explicit
    # dispatch retains its duplicate/UTF8/byte checks at the real action parser.
    if len(raw.encode("utf-8")) > 16384:
        raise ValueError("model text limit")
    value = json.loads(raw)
    if type(value) is not dict:
        raise ValueError("object required")
    if value.get("action") == "select_peers":
        return SelectPeers.model_validate_json(raw)
    if value.get("action") == "request_tools":
        return RequestTools.model_validate_json(raw)
    if value.get("action") == "finish":
        return Finish.model_validate_json(raw)
    raise ValueError("unknown action")


# JOB-specific adapters: do not loosen raw Observation or IP leaf admission.


class JobCounts(Counts):
    inspected: Count
    matched: Count
    retained: Count
    omitted: Count
    not_observed: Count
    unavailable: Count = 0
    scope_unavailable: Count = 0

    @model_validator(mode="after")
    def equations(self) -> Self:
        if (
            self.inspected != self.matched + self.not_observed + self.scope_unavailable
            or self.matched != self.retained + self.omitted + self.unavailable
        ):
            raise ValueError("evidence count equation")
        return self


class JobMetric(Metric):
    value: Annotated[Integral, Field(ge=0)] | None
    observed_rows: Count
    unavailable_rows: Count

    @model_validator(mode="after")
    def measurement(self) -> Self:
        expected_unit = (
            "bytes"
            if self.name == "total_bytes" or self.name.endswith("_bytes")
            else "packets"
            if self.name == "packet_count"
            else "sensors"
            if self.name == "sensor_count"
            else "rows"
        )
        prefix, separator, suffix = self.ref.partition(":")
        if (
            len(prefix) != 64
            or any(c not in "0123456789abcdef" for c in prefix)
            or separator != ":"
            or suffix != self.name
            or self.unit != expected_unit
            or (self.value is None) != (self.unavailable_rows > 0)
        ):
            raise ValueError("metric semantics")
        return self


class JobEvidenceQuality(EvidenceQuality):
    counts: JobCounts

    @model_validator(mode="after")
    def availability(self) -> Self:
        c = self.counts
        if self.tool != "compare_peer_cohort" and c.matched:
            expected = "UNAVAILABLE" if c.unavailable == c.matched else "OBSERVED"
            if self.status != expected:
                raise ValueError("evidence availability mismatch")
        return self


class PeerAssessment(AssessmentAction):
    mode: Literal["MODEL_ASSISTED", "FACTS_ONLY"]
    facts: Annotated[tuple[JobMetric, ...], Field(max_length=8)]
    evidence_quality: Annotated[tuple[JobEvidenceQuality, ...], Field(min_length=1, max_length=12)]
    reason: Reason | None

    @model_validator(mode="after")
    def consistency(self) -> Self:
        ids = {e.evidence_id for e in self.evidence_quality}
        if len(ids) != len(self.evidence_quality):
            raise ValueError("duplicate evidence")
        if len({m.ref for m in self.facts}) != len(self.facts) or any(
            m.ref.split(":", 1)[0] not in ids for m in self.facts
        ):
            raise ValueError("fact reference mismatch")
        qualities = {e.evidence_id: e for e in self.evidence_quality}
        for metric in self.facts:
            counts = qualities[metric.ref.split(":", 1)[0]].counts
            measured = metric.observed_rows + metric.unavailable_rows
            if measured > counts.matched + counts.scope_unavailable:
                raise ValueError("metric observation count")
            if (
                metric.name
                in {
                    "matched_rows",
                    "total_bytes",
                    "packet_count",
                    "sensor_count",
                    "c2_eligible_rows",
                    "suppressed_control_rows",
                    "eligibility_unavailable_rows",
                }
                and measured != counts.matched + counts.scope_unavailable
            ):
                raise ValueError("metric observation coverage")
        refs = {m.ref for m in self.facts}
        for item in (*self.support, *self.counterevidence):
            if not set(item.metric_refs) <= refs:
                raise ValueError("metric not in saved facts")
            if not set(item.evidence_ids) <= ids:
                raise ValueError("unknown evidence")
            if any(ref.split(":", 1)[0] not in item.evidence_ids for ref in item.metric_refs):
                raise ValueError("metric reference mismatch")
        if self.mode == "FACTS_ONLY" and (
            self.verdict != "INCONCLUSIVE"
            or self.support
            or self.counterevidence
            or self.reason is None
        ):
            raise ValueError("facts-only is not an assessment")
        if self.verdict in {"SUSPICIOUS_C2", "BENIGN_HYPOTHESIS"} and (
            not self.support or not self.counterevidence
        ):
            raise ValueError("support and counterevidence required")
        return self


class JobResult(PublicFrozen):
    wire_limit: ClassVar[int] = 16384
    version: Literal["job-investigation-v1"] = "job-investigation-v1"
    kind: Literal["RESULT"] = "RESULT"
    source: SourceBinding
    pool_sha256: Digest
    execution: JobExecutionIdentity
    language: Literal["ko", "en"]
    progress: JobProgress
    coverage: JobCoverage
    assessments: Annotated[tuple[PeerAssessment, ...], Field(max_length=3)]
    limitations: Annotated[tuple[Annotated[str, Field(max_length=128)], ...], Field(max_length=32)]
    partial_scope: Literal[True] = True
    reason: Reason | None

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.limitations != POOL_LIMITATIONS:
            raise ValueError("unknown or missing result limitation")
        if len({a.peer_id for a in self.assessments}) != len(self.assessments):
            raise ValueError("duplicate peer")
        evidence_ids = [e.evidence_id for a in self.assessments for e in a.evidence_quality]
        if len(evidence_ids) > 12 or len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("cross-peer or excessive evidence")
        if self.coverage.investigated_peers != sum(
            a.mode == "MODEL_ASSISTED" for a in self.assessments
        ):
            raise ValueError("assessed coverage mismatch")
        if len(canonical_bytes(self.model_dump(mode="json"))) > self.wire_limit:
            raise ValueError("final byte limit")
        return self


class JobFailure(PublicFrozen):
    version: Literal["job-investigation-v1"] = "job-investigation-v1"
    kind: Literal["FAILURE"] = "FAILURE"
    reason: Reason
    execution: JobExecutionIdentity
    progress: JobProgress


class JobRun(PublicFrozen):
    wire_limit: ClassVar[int] = 65536
    version: Literal["job-investigation-v1"] = "job-investigation-v1"
    id: Digest
    owner_id: Key
    job_id: Key
    status: Status
    revision: Annotated[Integral, Field(ge=0)]
    created_at: Annotated[float, Field(allow_inf_nan=False)]
    request: JobRequest
    source: SourceBinding
    execution: JobExecutionIdentity
    pool: JobPool
    selection: Selection
    coverage: JobCoverage
    progress: JobProgress
    result: JobResult | JobFailure | None
    reason: Reason | None

    @model_validator(mode="after")
    def consistency(self) -> Self:
        selected = set(self.selection.peer_ids)
        entries = {p.peer_id: p for p in self.pool.entries}
        cov = self.coverage
        progress = self.progress
        # Counters are charged attempts, not successful HTTP responses. A model
        # debit may precede transport; a planning response cannot precede it.
        if (
            progress.transport_attempts > progress.model_calls
            or progress.planning_responses > progress.transport_attempts
            or cov.observed_peers > 2 * cov.source_rows
            or any(p.matched_rows > cov.source_rows for p in entries.values())
            or progress.source_bytes not in {0, 8650752}
            or progress.source_records not in {0, cov.source_rows}
        ):
            raise ValueError("unreachable source or attempt counters")
        active = self.status in {"INVESTIGATING", "VALIDATING", "COMPLETED", "PARTIAL"}
        if (active or progress.model_calls or progress.tool_calls) and (
            progress.source_bytes != 8650752 or progress.source_records != cov.source_rows
        ):
            raise ValueError("source reservation missing")
        if selected and (not progress.planning_responses or not progress.tool_calls):
            raise ValueError("selection without charged planning")
        if self.status == "QUEUED" and (
            selected
            or any(
                (
                    progress.source_bytes,
                    progress.source_records,
                    progress.model_calls,
                    progress.tool_calls,
                    progress.transport_attempts,
                    progress.planning_responses,
                )
            )
        ):
            raise ValueError("queued work already executed")
        if (
            self.job_id != self.source.job_id
            or self.source.source_sha256 != self.pool.source_sha256
            or self.request.expected_source_sha256 not in {None, self.source.source_sha256}
            or not selected <= entries.keys()
            or cov.selected_peers != len(selected)
            or cov.pool_peers != len(entries)
            or cov.observed_peers != self.pool.observed_peers
            or cov.pool_omitted_peers != self.pool.omitted_peers
            or cov.awaiting_selection_peers
            != (len(entries) if self.selection.state == "PENDING" else 0)
        ):
            raise ValueError("run binding/coverage mismatch")
        if self.result is not None and (
            self.result.execution != self.execution
            or self.result.progress != self.progress
            or (self.reason is not None and self.result.reason != self.reason)
        ):
            raise ValueError("result identity/progress mismatch")
        if isinstance(self.result, JobResult):
            result = self.result
            if (
                result.source != self.source
                or result.pool_sha256 != self.pool.pool_sha256
                or result.language != self.request.language
                or result.coverage != cov
                or not {a.peer_id for a in result.assessments} <= selected
            ):
                raise ValueError("result binding mismatch")
            for assessment in result.assessments:
                for quality in assessment.evidence_quality:
                    if (
                        quality.counts.inspected != cov.source_rows
                        or quality.counts.matched != entries[assessment.peer_id].matched_rows
                        or quality.counts.scope_unavailable != 0
                    ):
                        raise ValueError("quality source/peer coverage mismatch")
            if any(
                a.verdict == "SUSPICIOUS_C2" and entries[a.peer_id].eligible_rows == 0
                for a in result.assessments
            ):
                raise ValueError("control-only positive")
        if self.status == "COMPLETED" and (
            not isinstance(self.result, JobResult)
            or not selected
            or cov.investigated_peers != len(selected)
            or self.result.reason is not None
            or progress.model_calls < 2
            or progress.transport_attempts < 2
        ):
            raise ValueError("incomplete completion")
        if self.status == "PARTIAL" and not isinstance(self.result, JobResult):
            raise ValueError("partial result missing")
        if (
            self.status in {"QUEUED", "PREPARING", "INVESTIGATING", "VALIDATING", "CANCELLED"}
            and self.result is not None
        ):
            raise ValueError("unexpected result")
        if self.status == "FAILED" and isinstance(self.result, JobResult):
            raise ValueError("failed assessment")
        if len(canonical_bytes(self.model_dump(mode="json"))) > self.wire_limit:
            raise ValueError("run byte limit")
        return self


class JobLimits(PublicFrozen):
    pool_peers: Literal[32] = 32
    pool_encoded_bytes: Literal[16384] = 16384
    selected_peers: Literal[3] = 3
    model_calls: Literal[6] = 6
    tool_calls: Literal[12] = 12
    planning_responses: Literal[4] = 4
    transport_attempts: Literal[12] = 12
    execution_deadline_seconds: Literal[300] = 300
    persisted_preparation_bytes: Literal[131072] = 131072
    retained_evidence_run_bytes: Literal[131072] = 131072


class JobCapabilities(PublicFrozen):
    version: Literal["job-investigation-v1"] = "job-investigation-v1"
    availability: Literal["CONFIGURED_NOT_PROBED", "UNAVAILABLE"]
    experimental: Literal[True] = True
    mode: Literal["JOB"] = "JOB"
    dispatch_scope: Literal["OWNED_CAPABLE_RUNTIME", "UNAVAILABLE"]
    historical_comparison: Literal["UNSUPPORTED"] = "UNSUPPORTED"
    remote_server_allowed: bool
    limits: JobLimits = Field(default_factory=JobLimits)
    reason: Reason | None


class JobStep(PublicFrozen):
    version: Literal["job-investigation-v1"] = "job-investigation-v1"
    sequence: Annotated[Integral, Field(ge=1, le=24)]
    kind: Literal["SOURCE", "MODEL", "TOOL", "FINAL"]
    progress: JobProgress
    peer_id: Digest | None
    tool: ToolName | Literal["select_peers"] | None
    evidence_id: Digest | None
    code: Reason | None
    origin: Literal["AUTOMATIC_SEED", "MODEL_REQUEST"] | None

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.kind != "TOOL":
            if any(x is not None for x in (self.peer_id, self.tool, self.evidence_id, self.origin)):
                raise ValueError("non-tool receipt")
        elif self.tool is None or self.origin is None:
            raise ValueError("tool origin missing")
        elif self.origin == "AUTOMATIC_SEED" and self.tool != "peer_overview":
            raise ValueError("invalid automatic seed")
        elif self.tool == "select_peers" and (
            self.peer_id is not None
            or self.evidence_id is not None
            or self.origin != "MODEL_REQUEST"
        ):
            raise ValueError("invalid selection receipt")
        return self
