import json
import sys
from pathlib import Path

import pytest

from c2hunter_analysis.high_volume_backtest import (
    POLICIES,
    apply_policy,
    evaluate_cases,
    main,
    render_markdown,
)

FIXTURE = Path(__file__).parent / "fixtures" / "high_volume_policy_cases.json"


def cases() -> list[dict[str, object]]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_high_volume_policies_quantify_recall_and_false_positive_tradeoff() -> None:
    report = evaluate_cases(cases())
    results = {item["policy"]["name"]: item for item in report["results"]}

    assert results["cap-20"]["recall"] == 0.0
    assert results["cap-20"]["false_positive_rate"] == 0.0
    assert results["cap-20"]["analyst_queue_visible"] == 0
    assert results["strong-evidence-cap-40"]["recall"] == 0.5
    assert results["strong-evidence-cap-40"]["false_positive_rate"] == 0.0
    assert results["strong-evidence-cap-40"]["analyst_queue_visible"] == 1
    assert results["fixed-penalty-25"]["recall"] == 1.0
    assert results["fixed-penalty-25"]["false_positive_rate"] == 1.0
    assert results["fixed-penalty-25"]["analyst_queue_visible"] == 4


def test_exact_analyst_match_and_low_volume_scores_are_exempt() -> None:
    fixture_cases = cases()
    exact = next(case for case in fixture_cases if case["id"] == "c2-exact-payload-signature")
    low_volume = next(case for case in fixture_cases if case["id"] == "c2-low-volume-beacon")

    for policy in POLICIES:
        assert apply_policy(exact, policy) == 95
        assert apply_policy(low_volume, policy) == 75


def test_empty_dataset_has_zero_metrics() -> None:
    result = evaluate_cases([])["results"][0]

    assert result["recall"] == 0.0
    assert result["false_positive_rate"] == 0.0


def test_render_markdown_and_cli_write_reproducible_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "high-volume-backtest",
            "--cases",
            str(FIXTURE),
            "--json",
            str(json_path),
            "--markdown",
            str(markdown_path),
        ],
    )

    main()

    saved = json.loads(json_path.read_text(encoding="utf-8"))
    assert saved["case_count"] == 8
    markdown = markdown_path.read_text(encoding="utf-8")
    assert markdown == render_markdown(saved)
    assert "strong-evidence-cap-40" in markdown
