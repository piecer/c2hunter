from __future__ import annotations

import argparse
import json
import math
import time
import tracemalloc
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class EvaluationCase:
    """One deterministic evaluation result without raw packet or payload data."""

    scenario_id: str
    expected_malicious: bool
    predicted_verdict: str
    confidence: float
    evidence_valid: bool = True
    unsafe_recommendation: bool = False
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.predicted_verdict not in {
            "LIKELY_C2",
            "SUSPICIOUS",
            "LIKELY_BENIGN",
            "INCONCLUSIVE",
        }:
            raise ValueError("unsupported predicted verdict")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if self.latency_ms < 0 or self.input_tokens < 0 or self.output_tokens < 0:
            raise ValueError("performance measurements cannot be negative")
        if self.estimated_cost_usd < 0:
            raise ValueError("estimated cost cannot be negative")


def _safe_ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 2)
    interpolated = ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
    return round(interpolated, 2)


def _positive_probability(case: EvaluationCase) -> float:
    if case.predicted_verdict in {"LIKELY_C2", "SUSPICIOUS"}:
        return case.confidence
    if case.predicted_verdict == "LIKELY_BENIGN":
        return 1 - case.confidence
    return case.confidence


def evaluate_cases(
    cases: list[EvaluationCase],
    *,
    model_profile: str,
) -> dict[str, Any]:
    """Build a stable evaluation report suitable for JSON or Markdown serialization."""

    if not model_profile.strip():
        raise ValueError("model_profile is required")
    if not cases:
        raise ValueError("at least one evaluation case is required")

    predicted_positive = [case.predicted_verdict in {"LIKELY_C2", "SUSPICIOUS"} for case in cases]
    true_positive = sum(
        case.expected_malicious and positive
        for case, positive in zip(cases, predicted_positive, strict=True)
    )
    false_positive = sum(
        not case.expected_malicious and positive
        for case, positive in zip(cases, predicted_positive, strict=True)
    )
    true_negative = sum(
        not case.expected_malicious and not positive
        for case, positive in zip(cases, predicted_positive, strict=True)
    )
    false_negative = sum(
        case.expected_malicious and not positive
        for case, positive in zip(cases, predicted_positive, strict=True)
    )
    precision = _safe_ratio(true_positive, true_positive + false_positive)
    recall = _safe_ratio(true_positive, true_positive + false_negative)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0
    brier_score = round(
        sum((_positive_probability(case) - float(case.expected_malicious)) ** 2 for case in cases)
        / len(cases),
        4,
    )

    return {
        "schema_version": "ai-evaluation-v1",
        "model_profile": model_profile,
        "case_count": len(cases),
        "quality": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        "calibration": {"brier_score": brier_score},
        "safety": {
            "evidence_valid_rate": _safe_ratio(
                sum(case.evidence_valid for case in cases), len(cases)
            ),
            "unsafe_recommendation_rate": _safe_ratio(
                sum(case.unsafe_recommendation for case in cases), len(cases)
            ),
        },
        "performance": {
            "latency_ms_p50": _percentile([case.latency_ms for case in cases], 0.5),
            "latency_ms_p95": _percentile([case.latency_ms for case in cases], 0.95),
            "input_tokens_total": sum(case.input_tokens for case in cases),
            "output_tokens_total": sum(case.output_tokens for case in cases),
            "estimated_cost_usd": round(sum(case.estimated_cost_usd for case in cases), 6),
        },
    }


def compare_model_profiles(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Rank profiles for recall, safe output, F1 quality, then lower latency."""

    if not reports:
        raise ValueError("at least one model profile report is required")
    ranked = sorted(
        deepcopy(reports),
        key=lambda report: (
            -float(report["quality"]["recall"]),
            float(report["safety"]["unsafe_recommendation_rate"]),
            -float(report["safety"]["evidence_valid_rate"]),
            -float(report["quality"]["f1"]),
            float(report["performance"]["latency_ms_p95"]),
            str(report["model_profile"]),
        ),
    )
    return {
        "schema_version": "ai-model-comparison-v1",
        "recommended_profile": ranked[0]["model_profile"],
        "profiles": ranked,
    }


@dataclass(frozen=True)
class AssessmentCacheIdentity:
    provider: str
    model: str
    model_config_hash: str
    prompt_hash: str
    output_schema_hash: str


class BoundedAssessmentCache:
    """Process-local LRU keyed by full model contract and canonical bundle hash."""

    def __init__(self, *, max_entries: int = 128) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._values: OrderedDict[tuple[AssessmentCacheIdentity, str], dict[str, Any]] = (
            OrderedDict()
        )
        self._lock = Lock()

    def get(self, identity: AssessmentCacheIdentity, bundle_hash: str) -> dict[str, Any] | None:
        key = (identity, bundle_hash)
        with self._lock:
            value = self._values.get(key)
            if value is None:
                return None
            self._values.move_to_end(key)
            return deepcopy(value)

    def put(
        self,
        identity: AssessmentCacheIdentity,
        bundle_hash: str,
        assessment: dict[str, Any],
    ) -> None:
        key = (identity, bundle_hash)
        with self._lock:
            self._values[key] = deepcopy(assessment)
            self._values.move_to_end(key)
            while len(self._values) > self.max_entries:
                self._values.popitem(last=False)


def evaluate_fixture_profiles() -> dict[str, Any]:
    from .ai_evaluation_pipeline import run_fixture_profile

    reports = [
        run_fixture_profile("fake-gateway"),
        run_fixture_profile("fake-gateway-conservative"),
    ]
    comparison = compare_model_profiles(reports)
    return {
        "fixture_version": "ai-evaluation-v1",
        "case_count": 10,
        "recommended_profile": comparison["recommended_profile"],
        "comparison": comparison["profiles"],
    }


def write_evaluation_report(
    report: dict[str, Any], *, json_path: Path, markdown_path: Path
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = [
        "# C2Hunter AI evaluation",
        "",
        f"Fixture: `{report['fixture_version']}` ({report['case_count']} cases)",
        f"Recommended profile: `{report['recommended_profile']}`",
        "",
        "| profile | precision | recall | F1 | evidence valid | unsafe | p95 ms | input tokens |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for profile in report["comparison"]:
        quality = profile["quality"]
        safety = profile["safety"]
        performance = profile["performance"]
        rows.append(
            f"| {profile['model_profile']} | {quality['precision']} | {quality['recall']} | "
            f"{quality['f1']} | {safety['evidence_valid_rate']} | "
            f"{safety['unsafe_recommendation_rate']} | "
            f"{performance['latency_ms_p95']} | {performance['input_tokens_total']} |"
        )
    primary = report["comparison"][0]
    candidate = primary["candidate_generation"]
    validation = primary["llm_validation"]
    artifacts = primary["artifact_generation"]
    rows.extend(
        [
            "",
            "## Pipeline metrics",
            "",
            f"- Recall@20: {candidate['recall_at_20']}",
            f"- Precision@20: {candidate['precision_at_20']}",
            f"- Candidate reduction ratio: {candidate['candidate_reduction_ratio']}",
            f"- JSON valid rate: {validation['json_valid_rate']}",
            f"- Evidence citation coverage: {validation['evidence_citation_coverage']}",
            f"- Validated artifacts: {artifacts['validated_artifact_count']}",
        ]
    )
    markdown_path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def benchmark_evaluation(*, iterations: int = 100) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    from .ai_evaluation_pipeline import run_fixture_profile

    latencies: list[float] = []
    stage_totals: dict[str, float] = {}
    last_report: dict[str, Any] = {}
    tracemalloc.start()
    started = time.perf_counter()
    cpu_started = time.process_time()
    for _ in range(iterations):
        iteration_started = time.perf_counter()
        last_report = run_fixture_profile("fake-gateway")
        for stage, duration in last_report["stage_duration_ms"].items():
            stage_totals[stage] = stage_totals.get(stage, 0.0) + float(duration)
        latencies.append((time.perf_counter() - iteration_started) * 1000)
    duration_ms = (time.perf_counter() - started) * 1000
    cpu_seconds = time.process_time() - cpu_started
    _current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    performance = last_report["performance"]
    return {
        "benchmark_version": "ai-benchmark-v1",
        "iterations": iterations,
        "case_evaluations": iterations * 10,
        "duration_ms": round(duration_ms, 4),
        "cpu_seconds": round(cpu_seconds, 4),
        "peak_memory_bytes": peak_memory,
        "latency_ms": {
            "p50": round(_percentile(latencies, 0.5), 4),
            "p95": round(_percentile(latencies, 0.95), 4),
        },
        "stage_duration_ms_total": {
            stage: round(duration, 4) for stage, duration in sorted(stage_totals.items())
        },
        "candidate_generation": last_report["candidate_generation"],
        "estimated_input_tokens": iterations * int(performance["input_tokens_total"]),
        "estimated_output_tokens": iterations * int(performance["output_tokens_total"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="c2hunter-ai-evaluation")
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--json", type=Path, required=True)
    evaluate_parser.add_argument("--markdown", type=Path, required=True)
    benchmark_parser = subparsers.add_parser("benchmark")
    benchmark_parser.add_argument("--json", type=Path, required=True)
    benchmark_parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args(argv)
    if args.command == "evaluate":
        write_evaluation_report(
            evaluate_fixture_profiles(), json_path=args.json, markdown_path=args.markdown
        )
    else:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(benchmark_evaluation(iterations=args.iterations), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
