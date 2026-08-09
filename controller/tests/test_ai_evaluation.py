from __future__ import annotations

import json
from pathlib import Path

from c2hunter_controller.ai_evaluation import (
    AssessmentCacheIdentity,
    BoundedAssessmentCache,
    EvaluationCase,
    benchmark_evaluation,
    compare_model_profiles,
    evaluate_cases,
    evaluate_fixture_profiles,
    write_evaluation_report,
)


def test_evaluation_report_covers_quality_safety_latency_and_tokens() -> None:
    cases = [
        EvaluationCase(
            scenario_id="AI-A",
            expected_malicious=True,
            predicted_verdict="LIKELY_C2",
            confidence=0.9,
            evidence_valid=True,
            unsafe_recommendation=False,
            latency_ms=120,
            input_tokens=800,
            output_tokens=100,
        ),
        EvaluationCase(
            scenario_id="AI-B",
            expected_malicious=False,
            predicted_verdict="LIKELY_BENIGN",
            confidence=0.8,
            evidence_valid=True,
            unsafe_recommendation=False,
            latency_ms=80,
            input_tokens=600,
            output_tokens=80,
        ),
        EvaluationCase(
            scenario_id="AI-C",
            expected_malicious=True,
            predicted_verdict="INCONCLUSIVE",
            confidence=0.4,
            evidence_valid=False,
            unsafe_recommendation=True,
            latency_ms=100,
            input_tokens=700,
            output_tokens=90,
        ),
    ]

    report = evaluate_cases(cases, model_profile="fake-v1")

    assert report["case_count"] == 3
    assert report["quality"] == {
        "true_positive": 1,
        "false_positive": 0,
        "true_negative": 1,
        "false_negative": 1,
        "precision": 1.0,
        "recall": 0.5,
        "f1": 0.6667,
    }
    assert report["calibration"]["brier_score"] == 0.1367
    assert report["safety"] == {
        "evidence_valid_rate": 0.6667,
        "unsafe_recommendation_rate": 0.3333,
    }
    assert report["performance"] == {
        "latency_ms_p50": 100.0,
        "latency_ms_p95": 118.0,
        "input_tokens_total": 2100,
        "output_tokens_total": 270,
        "estimated_cost_usd": 0.0,
    }


def test_model_profile_comparison_ranks_recall_then_safety_then_latency() -> None:
    reports = [
        evaluate_cases(
            [
                EvaluationCase(
                    scenario_id="AI-A",
                    expected_malicious=True,
                    predicted_verdict="LIKELY_C2",
                    confidence=0.9,
                    latency_ms=200,
                )
            ],
            model_profile="slow-safe",
        ),
        evaluate_cases(
            [
                EvaluationCase(
                    scenario_id="AI-A",
                    expected_malicious=True,
                    predicted_verdict="INCONCLUSIVE",
                    confidence=0.2,
                    latency_ms=50,
                )
            ],
            model_profile="fast-miss",
        ),
    ]

    comparison = compare_model_profiles(reports)

    assert comparison["recommended_profile"] == "slow-safe"
    assert [item["model_profile"] for item in comparison["profiles"]] == [
        "slow-safe",
        "fast-miss",
    ]


def test_bounded_assessment_cache_uses_full_versioned_key_and_lru_eviction() -> None:
    cache = BoundedAssessmentCache(max_entries=2)
    identity = AssessmentCacheIdentity(
        provider="ollama",
        model="model-a",
        model_config_hash="config-1",
        prompt_hash="prompt-1",
        output_schema_hash="schema-1",
    )
    changed_schema = AssessmentCacheIdentity(
        provider="ollama",
        model="model-a",
        model_config_hash="config-1",
        prompt_hash="prompt-1",
        output_schema_hash="schema-2",
    )
    cache.put(identity, "bundle-1", {"verdict": "LIKELY_C2"})
    cache.put(identity, "bundle-2", {"verdict": "LIKELY_BENIGN"})

    assert cache.get(identity, "bundle-1") == {"verdict": "LIKELY_C2"}
    assert cache.get(changed_schema, "bundle-1") is None
    cache.put(changed_schema, "bundle-3", {"verdict": "INCONCLUSIVE"})

    assert cache.get(identity, "bundle-2") is None
    assert cache.get(identity, "bundle-1") == {"verdict": "LIKELY_C2"}
    assert cache.get(changed_schema, "bundle-3") == {"verdict": "INCONCLUSIVE"}


def test_fixture_evaluation_writes_safe_json_and_markdown_reports(tmp_path: Path) -> None:
    report = evaluate_fixture_profiles()
    json_path = tmp_path / "evaluation.json"
    markdown_path = tmp_path / "evaluation.md"

    write_evaluation_report(report, json_path=json_path, markdown_path=markdown_path)

    saved = json.loads(json_path.read_text(encoding="utf-8"))
    assert saved["fixture_version"] == "ai-evaluation-v1"
    assert saved["case_count"] == 10
    baseline = next(
        profile for profile in saved["comparison"] if profile["model_profile"] == "fake-gateway"
    )
    assert saved["recommended_profile"] == "fake-gateway-conservative"
    assert baseline["model_profile"] == "fake-gateway"
    assert baseline["scenario_labels"]["AI-F"] == "BENIGN"
    assert 0 <= baseline["candidate_generation"]["recall_at_20"] <= 1
    assert 0 <= baseline["candidate_generation"]["precision_at_20"] <= 1
    assert baseline["candidate_generation"]["known_malicious_ranks"]
    assert baseline["candidate_generation"]["candidate_reduction_ratio"] > 0
    assert baseline["llm_validation"]["json_valid_rate"] == 1.0
    assert baseline["artifact_generation"]["validated_artifact_count"] > 0
    assert "precision" in markdown_path.read_text(encoding="utf-8").lower()
    assert "payload" not in json_path.read_text(encoding="utf-8").lower()


def test_benchmark_evaluation_reports_latency_and_token_statistics() -> None:
    report = benchmark_evaluation(iterations=5)

    assert report["iterations"] == 5
    assert report["case_evaluations"] == 50
    assert report["duration_ms"] >= 0
    assert report["latency_ms"]["p95"] >= 0
    assert report["peak_memory_bytes"] > 0
    assert report["stage_duration_ms_total"]["candidate_generation"] >= 0
    assert report["candidate_generation"]["known_malicious_ranks"]
    assert report["estimated_input_tokens"] > 0
