"""Versioned reference admission and independently derived numeric publication.

The provider selects sources, never values. This module owns no storage or retries.
"""

from __future__ import annotations

import hashlib
import math
import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, ValidationError

from .network_ai import (
    MAX_NETWORK_INPUT_BYTES,
    NETWORK_PROMPT,
    NUMERIC_FACT_MAXIMA,
    PATTERNS,
    SUMMARY_COUNTS,
    SUMMARY_FLAGS,
    ClosedModel,
    IssueID,
    NetworkSemanticError,
    PatternCorrelation,
    PossibleCause,
    PrioritizedCheck,
    ReportSuspectedCause,
    SupportingMeasurements,
    Text,
    canonical_network_input,
)

PROMPT = (
    NETWORK_PROMPT
    + "\n"
    + (
        "Use network-interpretation-v2. Include summary_numeric_refs and numeric_refs on every "
        "cause/check/correlation, even when empty. Select only retained typed references, never "
        "supply values or units. Example indices are original ordinals, not array positions. "
        "Observation integers are exact decimal strings. Maximum 3 references per list, 24 total. "
        "Prose is unverified; references do not validate prose. Select fewer references if the "
        "derived numeric envelope exceeds its byte budget."
    )
)
PROMPT_HASH = hashlib.sha256(PROMPT.encode()).hexdigest()
MAX_EVIDENCE_BYTES = 32768
MAX_COUNT = 2**63 - 1
SAFE_INTEGER = 2**53 - 1
ISSUE_COUNTS = ("event_count", "affected_flow_count", "affected_host_count")
DIRECTIONS = ("a_to_b", "b_to_a")
SUMMARY_UNITS = (
    {k: "records" for k in SUMMARY_COUNTS[:5]}
    | {k: "flows" for k in SUMMARY_COUNTS[5:8]}
    | {k: "issues" for k in SUMMARY_COUNTS[8:]}
)
ISSUE_UNITS = dict(zip(ISSUE_COUNTS, ("events", "flows", "hosts"), strict=True))
FACT_UNITS = {k: "bytes" if k == "transport_payload_length" else "raw" for k in NUMERIC_FACT_MAXIMA}


def scalar(value: Any, maximum: int, minimum: int = 0) -> str:
    if (
        type(value) is not str
        or not minimum <= len(value) <= maximum
        or any(0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        raise ValueError("invalid scalar text")
    return value


def bounded_json(value: Any, budget: int) -> None:
    """Bound work before encoding; never invoke custom conversion hooks."""
    remaining = budget

    def visit(v: Any, depth: int, numeric: bool = False) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 16:
            raise ValueError("resource limit")
        if type(v) is str:
            scalar(v, budget)
            remaining -= len(v)
        elif type(v) is dict:
            if len(v) > 64:
                raise ValueError("object limit")
            for k, child in v.items():
                scalar(k, 100)
                visit(child, depth + 1, numeric or k in {"numeric_refs", "summary_numeric_refs"})
        elif type(v) is list:
            if len(v) > 100:
                raise ValueError("list limit")
            for child in v:
                visit(child, depth + 1, numeric)
        elif type(v) is float:
            if not math.isfinite(v):
                if numeric:
                    raise NetworkSemanticError("INVALID_NUMERIC_REFERENCE")
                raise ValueError("nonfinite")
        elif v is not None and type(v) not in (bool, int):
            raise ValueError("not JSON data")
        if remaining < 0:
            raise ValueError("resource limit")

    visit(value, 0)


def closed(v: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if type(v) is not dict or not required <= v.keys() or v.keys() - required - (optional or set()):
        raise ValueError("closed shape required")
    return v


def decimal(value: Any, maximum: int = MAX_COUNT) -> int:
    if type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        raise ValueError("canonical observation string required")
    number = int(value)
    if number > maximum:
        raise ValueError("observation bound")
    return number


def selector(value: Any) -> int:
    if type(value) not in (int, float) or value not in (0, 1):
        raise ValueError("invalid example selector")
    return int(value)


Selector = Annotated[int, BeforeValidator(selector)]
SummaryField = Literal[
    "scanned_records",
    "skipped_records",
    "evaluated_records",
    "incomplete_records",
    "tracking_limited_records",
    "flow_count",
    "suspect_flow_count",
    "detailed_flow_count",
    "issue_count",
    "displayed_issue_count",
    "omitted_issue_count",
]


class SummaryRef(ClosedModel):
    kind: Literal["summary_count"]
    field: SummaryField


class IssueRef(ClosedModel):
    kind: Literal["issue_count"]
    issue_id: IssueID
    field: Literal["event_count", "affected_flow_count", "affected_host_count"]


class FactRef(ClosedModel):
    kind: Literal["example_fact"]
    issue_id: IssueID
    example_index: Selector
    field: Literal[
        "tcp_sequence",
        "tcp_acknowledgment",
        "tcp_window",
        "transport_payload_length",
        "icmp_type",
        "icmp_code",
    ]


class MeasurementRef(ClosedModel):
    kind: Literal["measurement"]
    issue_id: IssueID
    example_index: Selector
    metric: Literal[
        "observed_rtt_ms",
        "interarrival_variation_ms",
        "ttl_observed",
        "rtt_sources",
        "rtt_excluded",
    ]
    direction: Literal["a_to_b", "b_to_a"] | None
    statistic: Literal[
        "count",
        "min",
        "max",
        "mean",
        "stddev",
        "changes",
        "missing",
        "syn_ack",
        "data_ack",
        "ambiguous",
        "nonpositive_time",
        "nonexact_ack",
    ]


NumericRef = Annotated[
    SummaryRef | IssueRef | FactRef | MeasurementRef, Field(discriminator="kind")
]
References = Annotated[list[NumericRef], Field(max_length=3)]


class CauseV2(PossibleCause):
    numeric_refs: References


class CheckV2(PrioritizedCheck):
    numeric_refs: References


class CorrelationV2(PatternCorrelation):
    numeric_refs: References


class NetworkInterpretationV2(ClosedModel):
    schema_version: Literal["network-interpretation-v2"]
    kind: Literal["MODEL_INTERPRETATION"]
    language: Literal["ko", "en"]
    summary: Text
    summary_numeric_refs: References
    possible_causes: list[CauseV2] = Field(max_length=10)
    prioritized_checks: list[CheckV2] = Field(max_length=10)
    correlations: list[CorrelationV2] = Field(max_length=10)
    limitations: list[Text] = Field(min_length=1, max_length=12)


def measurement_integers(m: dict[str, Any]) -> list[tuple[dict[str, Any], str, int]]:
    paths = [(m["observed_rtt_ms"], "count", MAX_COUNT)]
    for metric in ("rtt_sources", "rtt_excluded"):
        paths.extend((m[metric], k, MAX_COUNT) for k in m[metric])
    for d in DIRECTIONS:
        paths.append((m["interarrival_variation_ms"][d], "count", MAX_COUNT))
        paths.extend(
            (m["ttl_observed"][d], k, 255 if k in ("min", "max") else MAX_COUNT)
            for k in ("count", "min", "max", "changes", "missing")
        )
    return paths


def encode_measurements(measurements: dict[str, Any]) -> dict[str, Any]:
    m = deepcopy(measurements)
    for obj, k, _ in measurement_integers(m):
        if obj[k] is not None:
            obj[k] = str(obj[k])
    return m


def decode_measurements(value: Any) -> dict[str, Any]:
    m = deepcopy(
        closed(
            value,
            {
                "observed_rtt_ms",
                "rtt_sources",
                "rtt_excluded",
                "interarrival_variation_ms",
                "ttl_observed",
                "coverage_complete",
                "status",
                "reasons",
            },
            {"metric_quality"},
        )
    )
    closed(m["observed_rtt_ms"], {"count", "min", "max", "mean", "stddev"})
    closed(m["rtt_sources"], {"syn_ack", "data_ack"})
    closed(m["rtt_excluded"], {"ambiguous", "nonpositive_time", "nonexact_ack"})
    for metric in ("interarrival_variation_ms", "ttl_observed"):
        closed(m[metric], set(DIRECTIONS))
        for d in DIRECTIONS:
            closed(
                m[metric][d],
                {"count", "min", "max", "mean", "stddev"}
                if metric == "interarrival_variation_ms"
                else {"count", "min", "max", "changes", "missing"},
            )
    for obj, k, maximum in measurement_integers(m):
        if obj[k] is None and k in ("min", "max"):
            continue
        obj[k] = decimal(obj[k], maximum)
    return SupportingMeasurements.model_validate(m).model_dump(exclude_unset=True)


def validate_input(bundle: Any) -> dict[str, Any]:
    bounded_json(bundle, MAX_NETWORK_INPUT_BYTES)
    if len(canonical_network_input(bundle).encode()) > MAX_NETWORK_INPUT_BYTES:
        raise ValueError("input byte budget")
    b = closed(
        bundle,
        {
            "schema_version",
            "language",
            "summary",
            "issues",
            "warnings",
            "limitations",
            "omitted_input_issues",
            "input_detail_counts",
            "projection_notice",
        },
    )
    if b["schema_version"] != "network-ai-input-v2" or b["language"] not in ("ko", "en"):
        raise ValueError("unsupported input")
    s = closed(
        b["summary"], set(SUMMARY_COUNTS) | set(SUMMARY_FLAGS) | {"verdict"}, {"suspected_cause"}
    )
    counts = {k: decimal(s[k]) for k in SUMMARY_COUNTS}
    if any(type(s[k]) is not bool for k in SUMMARY_FLAGS) or s["verdict"] not in (
        "anomaly_observed",
        "no_clear_anomaly",
        "insufficient_evidence",
    ):
        raise ValueError("invalid coverage")
    if (
        counts["scanned_records"]
        != counts["skipped_records"] + counts["evaluated_records"] + counts["incomplete_records"]
        or counts["issue_count"] != counts["displayed_issue_count"] + counts["omitted_issue_count"]
        or not counts["detailed_flow_count"]
        <= counts["suspect_flow_count"]
        <= counts["flow_count"]
        <= counts["scanned_records"]
        or counts["tracking_limited_records"] > counts["incomplete_records"]
    ):
        raise ValueError("inconsistent summary")
    if counts["tracking_limited_records"] and not (s["counts_are_lower_bounds"] and s["truncated"]):
        raise ValueError("tracking qualifiers required")

    def cause(v: Any) -> None:
        ReportSuspectedCause.model_validate(v)
        scalar(v["summary"], 400)

    if s.get("suspected_cause") is not None:
        cause(s["suspected_cause"])

    def texts(v: Any, limit: int) -> None:
        if type(v) is not list or len(v) > limit:
            raise ValueError("text list bound")
        for text in v:
            scalar(text, 400)

    texts(b["warnings"], 20)
    texts(b["limitations"], 4)
    scalar(b["projection_notice"], 2000)
    if type(b["issues"]) is not list or len(b["issues"]) > 20:
        raise ValueError("issue bound")
    detail = closed(
        b["input_detail_counts"],
        {
            "available",
            "retained",
            "omitted",
            "capped_example_entries",
            "capped_diagnostic_entries",
            "clipped_text_characters",
        },
    )
    for n in [b["omitted_input_issues"], *detail.values()]:
        if type(n) is not int or not 0 <= n <= SAFE_INTEGER:
            raise ValueError("bookkeeping bound")
    if (
        counts["displayed_issue_count"] != len(b["issues"]) + b["omitted_input_issues"]
        or detail["available"] != detail["retained"] + detail["omitted"]
        or detail["available"] > 420
    ):
        raise ValueError("projection conservation")
    seen: set[str] = set()
    retained = 0
    for i in b["issues"]:
        closed(
            i,
            {
                "id",
                "pattern",
                *ISSUE_COUNTS,
                "first_seen",
                "last_seen",
                "observed_facts",
                "evidence",
                "uncertainty",
                "next_checks",
            },
            {"observed_measurements", "suspected_cause", "detailed_analysis"},
        )
        scalar(i["id"], 100, 1)
        if i["id"] in seen or i["pattern"] not in PATTERNS:
            raise ValueError("invalid issue")
        seen.add(i["id"])
        for k in ISSUE_COUNTS:
            decimal(i[k])
        for k in ("first_seen", "last_seen"):
            scalar(i[k], 64)
        for k in ("evidence", "uncertainty", "next_checks", "detailed_analysis"):
            texts(i.get(k, []), 4)
            retained += len(i.get(k, []))
        if "suspected_cause" in i:
            cause(i["suspected_cause"])
            retained += 1
        for k, payload in (("observed_facts", "facts"), ("observed_measurements", "measurements")):
            values = i.get(k, [])
            if type(values) is not list or len(values) > 2:
                raise ValueError("wrapper limit")
            ordinals = set()
            for wrapper in values:
                closed(wrapper, {"example_index", payload})
                ordinal = selector(wrapper["example_index"])
                if ordinal in ordinals:
                    raise ValueError("duplicate ordinal")
                ordinals.add(ordinal)
                if payload == "measurements":
                    decode_measurements(wrapper[payload])
                else:
                    facts = closed(wrapper[payload], set(), set(NUMERIC_FACT_MAXIMA))
                    for field, value in facts.items():
                        decimal(value, NUMERIC_FACT_MAXIMA[field])
            retained += len(values)
    if retained != detail["retained"]:
        raise ValueError("retained units mismatch")
    return b


def observation_string(value: Any) -> str:
    decimal(value)
    return value


ObservationString = Annotated[str, BeforeValidator(observation_string)]


class SourceCounts(ClosedModel):
    syn_ack: ObservationString
    data_ack: ObservationString


class ExcludedCounts(ClosedModel):
    ambiguous: ObservationString
    nonpositive_time: ObservationString
    nonexact_ack: ObservationString


class Qualifiers(ClosedModel):
    scope: Literal["report", "issue", "representative_flow"]
    report_coverage_complete: bool
    counts_are_lower_bounds: bool
    measurement_coverage_complete: bool | None
    measurement_status: Literal["observed", "insufficient_evidence", "unsupported"] | None
    sample_count: ObservationString | None
    quality_status: (
        Literal["unavailable", "limited_samples", "observed_samples", "not_provided"] | None
    )
    quality_reasons: list[
        Literal[
            "NO_SAMPLES",
            "SINGLE_SAMPLE",
            "HANDSHAKE_ONLY",
            "BIDIRECTIONAL_RTT_NOT_ESTABLISHED",
            "SELECTION_BIAS_POSSIBLE",
        ]
    ] = Field(max_length=5)
    measurement_reasons: list[
        Literal[
            "INCOMPLETE_PACKET_EVIDENCE",
            "NON_MONOTONIC_TIMESTAMPS",
            "CORRELATION_LIMIT_REACHED",
            "MISSING_TTL",
            "NO_UNAMBIGUOUS_RTT",
            "NOT_TCP",
            "ONE_DIRECTION_OBSERVED",
        ]
    ] = Field(max_length=7)
    rtt_sources: SourceCounts | None
    rtt_excluded: ExcludedCounts | None


class EvidenceItem(ClosedModel):
    section: Literal["summary", "possible_causes", "prioritized_checks", "correlations"]
    item_index: int | None = Field(ge=0, le=9)
    reference_index: int = Field(ge=0, le=2)
    reference: NumericRef
    value: str = Field(max_length=32)
    unit: Literal[
        "records",
        "flows",
        "hosts",
        "issues",
        "events",
        "samples",
        "observations",
        "changes",
        "count",
        "ms",
        "ttl",
        "bytes",
        "raw",
    ]
    qualifiers: Qualifiers


class NumericEvidence(ClosedModel):
    schema_version: Literal["network-numeric-evidence-v1"]
    run_id: str
    analysis_job_id: str
    dataset_id: str | None
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    items: list[EvidenceItem] = Field(max_length=24)


@dataclass(frozen=True)
class EvidenceIdentity:
    run_id: str
    analysis_job_id: str
    dataset_id: str | None

    @classmethod
    def from_run(cls, run: dict[str, Any]) -> EvidenceIdentity:
        return cls(run["id"], run["analysis_job_id"], run.get("dataset_id"))


def resolve(reference: dict[str, Any], bundle: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    kind = reference["kind"]
    q: dict[str, Any] = dict(
        scope="report"
        if kind == "summary_count"
        else "issue"
        if kind == "issue_count"
        else "representative_flow",
        report_coverage_complete=bundle["summary"]["coverage_complete"],
        counts_are_lower_bounds=bundle["summary"]["counts_are_lower_bounds"],
        measurement_coverage_complete=None,
        measurement_status=None,
        sample_count=None,
        quality_status=None,
        quality_reasons=[],
        measurement_reasons=[],
        rtt_sources=None,
        rtt_excluded=None,
    )
    if kind == "summary_count":
        return bundle["summary"][reference["field"]], SUMMARY_UNITS[reference["field"]], q
    issue = next((i for i in bundle["issues"] if i["id"] == reference["issue_id"]), None)
    if issue is None:
        raise ValueError("unknown issue")
    if kind == "issue_count":
        return issue[reference["field"]], ISSUE_UNITS[reference["field"]], q
    key, payload = (
        ("observed_facts", "facts")
        if kind == "example_fact"
        else ("observed_measurements", "measurements")
    )
    wrapper = next(
        (w for w in issue.get(key, []) if w["example_index"] == reference["example_index"]), None
    )
    if wrapper is None:
        raise ValueError("unretained source")
    if kind == "example_fact":
        return wrapper[payload][reference["field"]], FACT_UNITS[reference["field"]], q
    m = wrapper[payload]
    metric, direction, stat = reference["metric"], reference["direction"], reference["statistic"]
    directional = metric in ("interarrival_variation_ms", "ttl_observed")
    if direction not in DIRECTIONS if directional else direction is not None:
        raise ValueError("invalid direction")
    allowed = {
        "observed_rtt_ms": {"count", "min", "max", "mean", "stddev"},
        "interarrival_variation_ms": {"count", "min", "max", "mean", "stddev"},
        "ttl_observed": {"count", "min", "max", "changes", "missing"},
        "rtt_sources": {"syn_ack", "data_ack"},
        "rtt_excluded": {"ambiguous", "nonpositive_time", "nonexact_ack"},
    }
    if stat not in allowed[metric]:
        raise ValueError("invalid statistic")
    stats = m[metric][direction] if directional else m[metric]
    quality_metric = metric if directional else "observed_rtt_ms"
    count = stats["count"] if directional else m["observed_rtt_ms"]["count"]
    value = stats[stat]
    if value is None or (stat == "stddev" and decimal(count) < 2):
        raise ValueError("unobserved value")
    quality = m.get("metric_quality", {}).get(quality_metric)
    if quality is not None and directional:
        quality = quality[direction]
    q.update(
        measurement_coverage_complete=m["coverage_complete"],
        measurement_status=m["status"],
        sample_count=count,
        quality_status=quality["status"] if quality else "not_provided",
        quality_reasons=quality["reasons"] if quality else [],
        measurement_reasons=m["reasons"],
        rtt_sources=None if directional else m["rtt_sources"],
        rtt_excluded=None if directional else m["rtt_excluded"],
    )
    if metric in ("rtt_sources", "rtt_excluded"):
        unit = "count"
    elif metric == "ttl_observed":
        unit = {
            "count": "observations",
            "min": "ttl",
            "max": "ttl",
            "changes": "changes",
            "missing": "count",
        }[stat]
    else:
        unit = "samples" if stat == "count" else "ms"
    return value if type(value) is str else repr(float(value)), unit, q


def envelope(
    bundle: dict[str, Any], identity: EvidenceIdentity, items: list[dict[str, Any]]
) -> dict[str, Any]:
    scalar(identity.run_id, MAX_EVIDENCE_BYTES, 1)
    scalar(identity.analysis_job_id, MAX_EVIDENCE_BYTES, 1)
    if identity.dataset_id is not None:
        scalar(identity.dataset_id, MAX_EVIDENCE_BYTES)
    value = {
        "schema_version": "network-numeric-evidence-v1",
        "run_id": identity.run_id,
        "analysis_job_id": identity.analysis_job_id,
        "dataset_id": identity.dataset_id,
        "input_sha256": hashlib.sha256(canonical_network_input(bundle).encode()).hexdigest(),
        "items": items,
    }
    if len(canonical_network_input(value).encode()) > MAX_EVIDENCE_BYTES:
        raise ValueError("numeric envelope exceeds byte budget; select fewer references")
    return NumericEvidence.model_validate(value).model_dump(mode="json")


def validate_output(
    response: Any, bundle: dict[str, Any], identity: EvidenceIdentity
) -> tuple[NetworkInterpretationV2, dict[str, Any]]:
    validate_input(bundle)
    bounded_json(response, 200000)
    try:
        output = NetworkInterpretationV2.model_validate(response)
    except ValidationError as error:
        if all(set(e["loc"]) & {"summary_numeric_refs", "numeric_refs"} for e in error.errors()):
            raise NetworkSemanticError("INVALID_NUMERIC_REFERENCE") from None
        raise
    if output.language != bundle["language"]:
        raise NetworkSemanticError("LANGUAGE")
    groups: list[tuple[str, int | None, list[Any], list[str] | None]] = [
        ("summary", None, output.summary_numeric_refs, None)
    ]
    supplied = {i["id"] for i in bundle["issues"]}
    for section in ("possible_causes", "prioritized_checks", "correlations"):
        for index, item in enumerate(getattr(output, section)):
            if len(set(item.issue_ids)) != len(item.issue_ids) or set(item.issue_ids) - supplied:
                raise NetworkSemanticError("INVALID_CITATION")
            groups.append((section, index, item.numeric_refs, item.issue_ids))
    if sum(len(g[2]) for g in groups) > 24:
        raise NetworkSemanticError("INVALID_NUMERIC_REFERENCE")
    rows = []
    for section, item_index, refs, owner in groups:
        seen = set()
        for ri, ref_model in enumerate(refs):
            ref = ref_model.model_dump()
            try:
                key = canonical_network_input(ref)
                if key in seen or (
                    "issue_id" in ref and owner is not None and ref["issue_id"] not in owner
                ):
                    raise ValueError("duplicate or foreign reference")
                seen.add(key)
                value, unit, qualifiers = resolve(ref, bundle)
            except (KeyError, ValueError, TypeError):
                raise NetworkSemanticError("INVALID_NUMERIC_REFERENCE") from None
            rows.append(
                dict(
                    section=section,
                    item_index=item_index,
                    reference_index=ri,
                    reference=ref,
                    value=value,
                    unit=unit,
                    qualifiers=qualifiers,
                )
            )
    return output, envelope(bundle, identity, rows)


def validate_binding(run: dict[str, Any]) -> EvidenceIdentity:
    if any(
        run.get(k) != v
        for k, v in {
            "analysis_kind": "NETWORK_ANOMALY",
            "prompt_name": "network_pattern_system",
            "prompt_version": "2.0",
            "prompt_hash": PROMPT_HASH,
            "input_schema_version": "network-ai-input-v2",
            "output_schema_version": "network-interpretation-v2",
        }.items()
    ):
        raise ValueError("unsupported network binding")
    bundle = validate_input(run.get("network_input"))
    if run.get("language") != bundle["language"]:
        raise ValueError("language binding")
    identity = EvidenceIdentity.from_run(run)
    envelope(bundle, identity, [])
    return identity


def public_network_run(run: dict[str, Any]) -> dict[str, Any]:
    from .api_errors import ApiError
    from .network_ai import NETWORK_PROMPT_HASH

    view = {k: v for k, v in run.items() if k != "network_numeric_evidence"}
    if run.get("status") != "COMPLETED":
        return view
    legacy = (
        all(
            run.get(k) == v
            for k, v in {
                "input_schema_version": "network-ai-input-v1",
                "output_schema_version": "network-interpretation-v1",
                "prompt_version": "1.0",
                "prompt_name": "network_pattern_system",
                "prompt_hash": NETWORK_PROMPT_HASH,
            }.items()
        )
        and isinstance(run.get("network_input"), dict)
        and run["network_input"].get("schema_version") == "network-ai-input-v1"
        and isinstance(run.get("network_interpretation"), dict)
        and run["network_interpretation"].get("schema_version") == "network-interpretation-v1"
    )
    if legacy:
        return view
    try:
        identity = validate_binding(run)
        _, value = validate_output(
            run.get("network_interpretation"), run["network_input"], identity
        )
    except (ValueError, TypeError, KeyError, OverflowError):
        raise ApiError(
            503,
            "NETWORK_EVIDENCE_INVALID",
            "Saved network evidence could not be validated.",
            details=None,
        ) from None
    view["network_numeric_evidence"] = value
    return view
