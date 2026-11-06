"""Bounded, uncertainty-preserving synthetic comparison reporting."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .ai_analysis import CandidateAssessment
from .ai_gateway import StructuredLocalGateway
from .ai_investigation_schema import ACTION, Finish

REPORT_LIMIT = 2 * 1024 * 1024


class EvaluationRow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    case_id: str
    scenario: str
    expected: Literal["POSITIVE", "NEGATIVE", "ABSTAIN"]
    arm: Literal["legacy", "investigation"]
    target_ip: str
    data_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stored_source_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal[
        "COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "NOT_SELECTED", "EXECUTION_UNRESOLVED"
    ]
    stored_status: str | None = None
    verdict: str | None
    reason: str | None = Field(max_length=128)
    selected_ips: list[str] = Field(max_length=5)
    source_unchanged: Literal[True]
    facts: list[dict[str, Any]] = Field(max_length=24)
    interpretation: dict[str, Any] | None
    evidence: list[dict[str, Any]] = Field(max_length=12)
    steps: list[dict[str, Any]] = Field(max_length=24)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    calls: list[dict[str, Any]] | None = Field(default=None, max_length=12)
    output_audits: list[dict[str, Any]] = Field(default_factory=list, max_length=12)
    trace_range: list[int] | None = Field(default=None, min_length=2, max_length=2)
    provenance: dict[str, Any] | None = None
    model_observations: dict[str, Any] | None = None
    typed_facts_verified: bool | None = None
    typed_fact_mismatches: int | None = Field(default=None, ge=0)


def serialize_report(report: dict[str, Any]) -> str:
    """Pre-admit depth, nodes and strings, then cap the complete encoded report."""
    nodes = size = 0

    def visit(value: Any, depth: int = 0) -> None:
        nonlocal nodes, size
        nodes += 1
        if nodes > 100000 or depth > 32:
            raise ValueError("report limit")
        if isinstance(value, str):
            size += len(value.encode("utf-8"))
        elif isinstance(value, dict):
            for key, child in value.items():
                if type(key) is not str:
                    raise ValueError("report key")
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(value, list | tuple):
            for child in value:
                visit(child, depth + 1)
        if size > REPORT_LIMIT:
            raise ValueError("report limit")

    visit(report)
    text = json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if len(text.encode()) > REPORT_LIMIT:
        raise ValueError("report limit")
    return text


def audit_output(arm: str, content: str | None, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Reference membership is mechanical; cited prose truth is deliberately unknown."""
    result: dict[str, Any] = dict(
        json_valid=None,
        schema_valid=None,
        citation_count=None,
        invalid_citations=None,
        typed_ref_count=None,
        invalid_typed_refs=None,
        semantic_prose_verified=None,
    )
    if content is None:
        return result
    if len(content.encode()) > 65536:
        raise ValueError("output audit limit")
    try:
        parsed = (
            StructuredLocalGateway._parse_content(content)
            if arm == "legacy"
            else json.loads(content)
        )
    except (ValueError, RecursionError):
        result.update(json_valid=False, schema_valid=False)
        return result
    result["json_valid"] = True
    try:
        if arm == "legacy":
            assessment = CandidateAssessment.model_validate(parsed)
            refs = [ref for f in assessment.supporting_factors for ref in f.evidence_ids]
            refs += [ref for f in assessment.counter_factors for ref in f.evidence_ids]
            refs += [
                ref for f in assessment.stable_detection_features for ref in f.source_evidence_ids
            ]
            known = {item["id"] for bundle in evidence for item in bundle.get("evidence", [])}
            typed: list[str] = []
            metrics: set[str] = set()
        else:
            action = ACTION.validate_json(content)
            interpretations = (
                (*action.support, *action.counterevidence) if isinstance(action, Finish) else ()
            )
            refs = [ref for f in interpretations for ref in f.evidence_ids]
            typed = [ref for f in interpretations for ref in f.metric_refs]
            known = {item["evidence_id"] for item in evidence}
            metrics = {m["ref"] for e in evidence for m in e.get("metrics", [])}
            # Cross-citation membership is required in addition to global metric existence.
            invalid_typed = sum(
                ref not in metrics or ref.split(":", 1)[0] not in f.evidence_ids
                for f in interpretations
                for ref in f.metric_refs
            )
        result.update(
            schema_valid=True,
            citation_count=len(refs),
            invalid_citations=sum(ref not in known for ref in refs),
            typed_ref_count=len(typed) if arm != "legacy" else None,
            invalid_typed_refs=invalid_typed if arm != "legacy" else None,
        )
    except (ValidationError, ValueError, TypeError):
        result["schema_valid"] = False
    return result


def _prediction(verdict: str | None) -> str:
    if verdict in {"LIKELY_C2", "SUSPICIOUS", "SUSPICIOUS_C2"}:
        return "POSITIVE"
    if verdict in {"LIKELY_BENIGN", "BENIGN_HYPOTHESIS"}:
        return "NEGATIVE"
    return "ABSTAIN"


def _sum_known(values: list[int | None]) -> int | None:
    return (
        sum(v for v in values if v is not None)
        if values and all(v is not None for v in values)
        else None
    )


def _comparison(parsed: list[EvaluationRow], metadata: dict[str, Any]) -> dict[str, Any]:
    from copy import deepcopy

    from .ai_investigation_evaluation import digest

    identities = []
    observed_digests = set()
    verified = True
    for case_id in dict.fromkeys(r.case_id for r in parsed):
        pair = [r for r in parsed if r.case_id == case_id]
        if pair[0].stored_source_sha256 != pair[1].stored_source_sha256:
            raise ValueError("pair stored source mismatch")
        if pair[0].provenance != pair[1].provenance:
            raise ValueError("pair execution identity mismatch")
        identity = pair[0].provenance
        if identity is None:
            verified = False
            continue
        identities.append(identity)
        observations = pair[0].model_observations
        if observations != pair[1].model_observations:
            raise ValueError("pair model observation mismatch")
        if not observations:
            verified = False
            continue
        before, after = observations.get("before"), observations.get("after")
        if not before or not after:
            verified = False
            continue
        name = identity["common"]["model"]
        if before["tag"]["name"] != name or after["tag"]["name"] != name:
            raise ValueError("observed model binding mismatch")
        observed_digests.add(before["tag"]["digest"])
        if before["tag"]["digest"] != after["tag"]["digest"]:
            verified = False
    if identities and any(i != identities[0] for i in identities):
        raise ValueError("mixed execution identities")
    if len(observed_digests) > 1:
        raise ValueError("mixed model identities")
    result = deepcopy(metadata)
    if identities:
        identity = identities[0]
        if "source_sha256" in result and result["source_sha256"] != identity["source_sha256"]:
            raise ValueError("runtime source binding mismatch")
        if "config" in result:
            config = result["config"]
            if result.get("config_sha256") != digest(config):
                raise ValueError("config hash mismatch")
            for key, value in identity["common"].items():
                config_key = "endpoint" if key == "base_url" else key
                if config_key in config and config[config_key] != value:
                    raise ValueError("report configuration mismatch")
    result["comparison_valid"] = verified and len(identities) == len(parsed) // 2
    result["provenance_status"] = (
        "VERIFIED_OBSERVED_IDENTITY" if result["comparison_valid"] else "UNVERIFIED_OR_UNAVAILABLE"
    )
    return result


def build_report(
    cases: tuple[Any, ...], rows: list[dict[str, Any]], *, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    # Bound allocation before pydantic's nested validation/serialization.
    serialize_report({"rows": rows})
    if not 1 <= len(cases) <= 9 or len({c.case_id for c in cases}) != len(cases):
        raise ValueError("invalid case set")
    expected = {(c.case_id, arm): c for c in cases for arm in ("legacy", "investigation")}
    parsed = [EvaluationRow.model_validate(row) for row in rows]
    keys = [(r.case_id, r.arm) for r in parsed]
    if len(keys) != len(expected) or len(set(keys)) != len(keys) or set(keys) != set(expected):
        raise ValueError("incomplete or duplicate case-arm matrix")
    for row in parsed:
        case = expected[row.case_id, row.arm]
        if (row.scenario, row.expected, row.target_ip, row.data_sha256) != (
            case.scenario,
            case.expected,
            case.target_ip,
            case.data_sha256,
        ):
            raise ValueError("case binding mismatch")
        verdicts = (
            {"LIKELY_C2", "SUSPICIOUS", "INCONCLUSIVE", "LIKELY_BENIGN"}
            if row.arm == "legacy"
            else {"SUSPICIOUS_C2", "BENIGN_HYPOTHESIS", "INCONCLUSIVE", "NEEDS_REVIEW"}
        )
        if row.status == "COMPLETED" and row.verdict not in verdicts:
            raise ValueError("completed result requires an arm-specific verdict")
        if (
            row.status in {"FAILED", "NOT_SELECTED", "CANCELLED", "EXECUTION_UNRESOLVED"}
            and row.verdict is not None
        ):
            raise ValueError("failed or omitted result is not an assessment")
        if row.status == "NOT_SELECTED" and row.arm != "legacy":
            raise ValueError("investigation has no shortlist")
        if row.status == "PARTIAL" and (
            row.arm != "investigation" or row.verdict != "INCONCLUSIVE"
        ):
            raise ValueError("partial result must abstain")
    metadata = _comparison(parsed, metadata or {})
    metrics = {}
    for arm in ("legacy", "investigation"):
        subset = [r for r in parsed if r.arm == arm]
        assessed = [r for r in subset if r.status == "COMPLETED"]
        binary = [
            r for r in assessed if r.expected != "ABSTAIN" and _prediction(r.verdict) != "ABSTAIN"
        ]
        calls = [call for r in subset for call in r.calls or []]
        observed_calls = all(r.calls is not None for r in subset)
        audits = [a for r in subset for a in r.output_audits]
        metrics[arm] = dict(
            cases=len(subset),
            selected=sum(r.status != "NOT_SELECTED" for r in subset),
            selection_coverage=sum(r.status != "NOT_SELECTED" for r in subset) / len(subset),
            omissions=sum(r.status == "NOT_SELECTED" for r in subset),
            positive_label_omissions=sum(
                r.status == "NOT_SELECTED" and r.expected == "POSITIVE" for r in subset
            ),
            failures=sum(
                r.status in {"FAILED", "CANCELLED", "EXECUTION_UNRESOLVED"} for r in subset
            ),
            partial=sum(r.status == "PARTIAL" for r in subset),
            assessed=len(assessed),
            model_abstentions=sum(_prediction(r.verdict) == "ABSTAIN" for r in assessed),
            false_positives=sum(
                r.expected == "NEGATIVE" and _prediction(r.verdict) == "POSITIVE" for r in assessed
            ),
            false_negatives=sum(
                r.expected == "POSITIVE" and _prediction(r.verdict) == "NEGATIVE" for r in assessed
            ),
            binary_proxy_denominator=len(binary),
            on_assessed_binary_proxy_accuracy=(
                sum(r.expected == _prediction(r.verdict) for r in binary) / len(binary)
                if binary
                else None
            ),
            elapsed_seconds=sum(r.elapsed_seconds for r in subset),
            http_attempts=sum(c["http_attempts"] for c in calls) if observed_calls else None,
            input_tokens=_sum_known([c["input_tokens"] for c in calls]) if observed_calls else None,
            output_tokens=_sum_known([c["output_tokens"] for c in calls])
            if observed_calls
            else None,
            cost_usd=None,
            semantic_prose_verified=None,
            invalid_output_count=sum(a["schema_valid"] is False for a in audits)
            if audits
            else None,
            invalid_citations=_sum_known([a["invalid_citations"] for a in audits]),
            citation_count=_sum_known([a["citation_count"] for a in audits]),
            tool_calls=sum(s["kind"] == "TOOL" for r in subset for s in r.steps),
            counterevidence_items=sum(
                len(
                    (r.interpretation or {}).get(
                        "counter_factors" if arm == "legacy" else "counterevidence", []
                    )
                )
                for r in assessed
            ),
        )
    report = dict(
        version="generated-investigation-evaluation-v1",
        complete=True,
        expected_rows=len(expected),
        metadata=metadata or {},
        metrics=metrics,
        cases=[
            dict(
                case_id=c.case_id,
                scenario=c.scenario,
                expected=c.expected,
                data_sha256=c.data_sha256,
            )
            for c in cases
        ],
        rows=[r.model_dump(mode="json") for r in parsed],
        limitations=[
            "Synthetic behavioral proxy labels, not real-traffic ground truth.",
            "Single run; no statistical superiority or best-model conclusion.",
            "NOT_SELECTED is an omission, never a benign model assessment.",
            "Accuracy denominator excludes omissions, failures, partials and abstentions.",
            "Citation existence and typed fact equality do not verify prose meaning.",
            "Unknown tokens and monetary/physical compute costs are null, not zero.",
        ],
    )
    serialize_report(report)
    return report
