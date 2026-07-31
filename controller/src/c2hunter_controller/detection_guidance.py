from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from dataclasses import asdict
from typing import Any

from c2hunter_analysis.scoring import CAPS, MAX_DETECTOR_WEIGHT

from .flow_review import filter_flows
from .jobs import evaluate_candidates

_WEIGHT_STEPS = (1.25, 1.5, 1.75, 2.0)


def build_detection_guidance(
    job: dict[str, Any],
    requested_flow_id: str,
    *,
    allowlist: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build counterfactual score guidance for an analyst-confirmed C2 flow."""
    selected = next(
        (item for item in filter_flows(job) if item["flow_id"] == requested_flow_id),
        None,
    )
    if selected is None:
        raise LookupError("FLOW_NOT_FOUND")
    candidate_ip = selected.get("external_ip")
    if not candidate_ip:
        raise ValueError("EXTERNAL_ENDPOINT_UNAVAILABLE")

    policy_candidates = evaluate_candidates(job, allowlist)
    raw_candidates = evaluate_candidates(job)
    policy_candidate = _candidate(policy_candidates, str(candidate_ip))
    raw_candidate = _candidate(raw_candidates, str(candidate_ip))
    suppressed_by_policy = (
        policy_candidate is None and raw_candidate is not None and bool(allowlist)
    )
    candidate = policy_candidate or raw_candidate
    minimum_score = int(job["analysis"]["minimum_candidate_score"])
    current_score = int(candidate.score) if candidate is not None else 0
    conditions = _condition_breakdown(candidate, job) if candidate is not None else []
    recommendations: list[dict[str, Any]] = []
    recommended_weights = {
        str(name): float(weight)
        for name, weight in dict(job["analysis"].get("detector_weights", {})).items()
    }

    if suppressed_by_policy:
        recommendations.append(
            {
                "kind": "POLICY_REVIEW",
                "risk": "HIGH",
                "projected_score": current_score,
                "score_gain": 0,
                "rationale": (
                    "탐지 근거는 생성됐지만 allowlist 또는 신뢰 인프라 정책이 "
                    "후보를 억제했습니다. 정책 범위를 먼저 검토해야 합니다."
                ),
                "risk_note": "정책 변경은 신뢰 인프라 전체의 후보 억제를 해제할 수 있습니다.",
            }
        )
    elif candidate is not None and current_score < minimum_score:
        weight_recommendations = _weight_recommendations(
            job,
            str(candidate_ip),
            candidate,
            minimum_score,
            allowlist or [],
        )
        recommendations.extend(weight_recommendations)
        if weight_recommendations:
            best = min(
                weight_recommendations,
                key=lambda item: (
                    float(item["recommended_value"]) - float(item["current_value"]),
                    -int(item["projected_score"]),
                ),
            )
            recommended_weights[str(best["detector"])] = float(best["recommended_value"])
        elif current_score > 0:
            recommendations.append(
                {
                    "kind": "MINIMUM_SCORE",
                    "risk": "HIGH",
                    "current_value": minimum_score,
                    "recommended_value": current_score,
                    "projected_score": current_score,
                    "score_gain": 0,
                    "rationale": (
                        "가중치 상한 내에서 기준 점수에 도달하지 못합니다. 최소 후보 "
                        "점수를 낮추면 검출되지만 전체 후보와 오탐이 늘어날 수 있습니다."
                    ),
                    "risk_note": "모든 탐지기의 낮은 점수 후보가 함께 증가합니다.",
                }
            )
    elif candidate is None:
        recommendations.append(
            {
                "kind": (
                    "PAYLOAD_SIGNATURE"
                    if selected.get("payload_hash")
                    else "NEW_DETECTOR_CONDITION"
                ),
                "risk": "MEDIUM",
                "projected_score": 0,
                "score_gain": 0,
                "rationale": (
                    "현재 탐지 조건에서는 이 외부 IP에 대한 근거가 생성되지 않았습니다. "
                    "확인한 페이로드 서명으로 후속 분석을 보강하세요."
                    if selected.get("payload_hash")
                    else (
                        "현재 탐지 조건에서는 근거가 생성되지 않았습니다. 흐름 특성을 "
                        "반영한 새 탐지 조건이 필요합니다."
                    )
                ),
                "risk_note": "새 서명이나 조건은 별도 정상 데이터로 오탐 여부를 검증해야 합니다.",
            }
        )

    recommended_minimum = minimum_score
    minimum_recommendation = next(
        (item for item in recommendations if item["kind"] == "MINIMUM_SCORE"), None
    )
    if minimum_recommendation is not None:
        recommended_minimum = int(minimum_recommendation["recommended_value"])

    return {
        "flow_id": requested_flow_id,
        "candidate_ip": candidate_ip,
        "initially_detected": policy_candidate is not None and current_score >= minimum_score,
        "suppressed_by_policy": suppressed_by_policy,
        "current_score": current_score,
        "minimum_candidate_score": minimum_score,
        "score_gap": max(0, minimum_score - current_score),
        "conditions": conditions,
        "adjustments": [asdict(item) for item in candidate.adjustments]
        if candidate is not None
        else [],
        "recommendations": recommendations,
        "recommended_reanalysis": {
            "minimum_candidate_score": recommended_minimum,
            "detector_weights": recommended_weights,
        },
        "warnings": [
            (
                "추천 점수는 동일 데이터셋의 반사실 재평가 결과이며 미래 트래픽의 "
                "탐지율을 보장하지 않습니다."
            ),
            "가중치 또는 최소 점수 변경 전 정상 트래픽 데이터셋으로 오탐 증가를 비교해야 합니다.",
        ],
    }


def _weight_recommendations(
    job: dict[str, Any],
    candidate_ip: str,
    candidate: Any,
    minimum_score: int,
    allowlist: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    weights = {
        str(name): float(weight)
        for name, weight in dict(job["analysis"].get("detector_weights", {})).items()
    }
    recommendations: list[dict[str, Any]] = []
    for detector in sorted({item.detector for item in candidate.evidence}):
        current = float(weights.get(detector, 1.0))
        for proposed in _WEIGHT_STEPS:
            if proposed <= current:
                continue
            simulated = deepcopy(job)
            simulated_weights = dict(weights)
            simulated_weights[detector] = proposed
            simulated["analysis"] = {**simulated["analysis"], "detector_weights": simulated_weights}
            projected = _candidate(evaluate_candidates(simulated, allowlist), candidate_ip)
            projected_score = int(projected.score) if projected is not None else 0
            if projected_score < minimum_score:
                continue
            recommendations.append(
                {
                    "kind": "DETECTOR_WEIGHT",
                    "risk": "MEDIUM" if proposed <= 1.5 else "HIGH",
                    "detector": detector,
                    "current_value": current,
                    "recommended_value": proposed,
                    "projected_score": projected_score,
                    "score_gain": projected_score - int(candidate.score),
                    "rationale": (
                        f"{detector} 가중치를 {proposed:g}배로 적용하면 동일 데이터셋에서 "
                        f"기준 점수 {minimum_score}에 도달합니다."
                    ),
                    "risk_note": "같은 탐지 조건을 만족하는 정상 통신 점수도 함께 증가합니다.",
                }
            )
            break
    return recommendations


def _candidate(candidates: list[Any], candidate_ip: str) -> Any | None:
    return next((item for item in candidates if item.candidate_ip == candidate_ip), None)


def _condition_breakdown(candidate: Any, job: dict[str, Any]) -> list[dict[str, Any]]:
    """Allocate each capped evidence-type score proportionally across its evidence."""
    weights = {
        str(name): float(weight)
        for name, weight in dict(job["analysis"].get("detector_weights", {})).items()
    }
    by_type: dict[str, list[Any]] = defaultdict(list)
    for item in candidate.evidence:
        by_type[item.type].append(item)

    applied_by_item: dict[int, float] = {}
    for evidence_type, evidence_items in by_type.items():
        total = sum(max(0, item.contribution) for item in evidence_items)
        if not total:
            continue
        baseline = min(CAPS.get(evidence_type, 0), total)
        weighted_total = sum(
            max(0, item.contribution)
            * max(0.0, min(MAX_DETECTOR_WEIGHT, weights.get(item.detector, 1.0)))
            for item in evidence_items
        )
        weighted_type_score = min(
            CAPS.get(evidence_type, 0) * MAX_DETECTOR_WEIGHT,
            baseline * weighted_total / total,
        )
        for item in evidence_items:
            applied_by_item[id(item)] = weighted_type_score * max(0, item.contribution) / total

    return [
        {
            "evidence_type": item.type,
            "detector": item.detector,
            "description": item.description,
            "raw_score": item.raw_score,
            "contribution": item.contribution,
            "current_weight": weights.get(item.detector, 1.0),
            "weighted_contribution": round(applied_by_item.get(id(item), 0.0), 2),
            "metrics": dict(item.metrics),
        }
        for item in candidate.evidence
    ]
