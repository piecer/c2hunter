from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Policy:
    name: str
    cap: int | None = None
    strong_evidence_cap: int | None = None
    penalty: int | None = None


POLICIES = (
    Policy("cap-20", cap=20),
    Policy("strong-evidence-cap-40", cap=20, strong_evidence_cap=40),
    Policy("fixed-penalty-25", penalty=25),
)


def apply_policy(case: dict[str, Any], policy: Policy) -> int:
    score = max(0, min(100, int(case["raw_score"])))
    if not case["high_volume"] or case["analyst_exact_match"]:
        return score
    if policy.penalty is not None:
        return max(0, score - policy.penalty)
    cap = policy.cap
    if case["strong_evidence"] and policy.strong_evidence_cap is not None:
        cap = policy.strong_evidence_cap
    return min(score, cap) if cap is not None else score


def evaluate_policy(
    cases: Sequence[dict[str, Any]], policy: Policy, *, triage_threshold: int = 40
) -> dict[str, Any]:
    affected = [case for case in cases if case["high_volume"] and not case["analyst_exact_match"]]
    scored = [{**case, "score": apply_policy(case, policy)} for case in affected]
    positives = [case for case in scored if case["label"] == "C2"]
    negatives = [case for case in scored if case["label"] != "C2"]
    true_positive = sum(case["score"] >= triage_threshold for case in positives)
    false_positive = sum(case["score"] >= triage_threshold for case in negatives)
    recall = true_positive / len(positives) if positives else 0.0
    false_positive_rate = false_positive / len(negatives) if negatives else 0.0
    return {
        "policy": asdict(policy),
        "evaluated_case_count": len(affected),
        "exempt_case_count": len(cases) - len(affected),
        "triage_threshold": triage_threshold,
        "case_count": len(scored),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "recall": round(recall, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "analyst_queue_visible": sum(case["score"] >= triage_threshold for case in scored),
        "scores": [
            {"id": case["id"], "label": case["label"], "score": case["score"]} for case in scored
        ],
    }


def evaluate_cases(cases: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "dataset": "curated deterministic policy fixture; not historical production traffic",
        "case_count": len(cases),
        "results": [evaluate_policy(cases, policy) for policy in POLICIES],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# HIGH_VOLUME_TCP_SESSION policy backtest",
        "",
        f"Dataset: {report['dataset']}",
        "",
        "| Policy | Recall | False-positive rate | Analyst queue visible |",
        "|---|---:|---:|---:|",
    ]
    for result in report["results"]:
        lines.append(
            f"| {result['policy']['name']} | {result['recall']:.4f} | "
            f"{result['false_positive_rate']:.4f} | {result['analyst_queue_visible']} |"
        )
    lines.extend(
        [
            "",
            (
                "The fixture demonstrates policy trade-offs only. It does not authorize "
                "changing the production default without representative historical labels."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    report = evaluate_cases(cases)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.markdown.write_text(render_markdown(report), encoding="utf-8")


if __name__ == "__main__":
    main()
