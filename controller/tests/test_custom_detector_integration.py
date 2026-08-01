"""Controller integration tests for operator-installed custom detectors."""

from pathlib import Path
from typing import Any

from c2hunter_controller.jobs import evaluate_candidates


def test_evaluate_candidates_uses_operator_custom_detector(
    tmp_path: Path, monkeypatch: Any
) -> None:
    plugin_directory = tmp_path / "detectors"
    plugin_directory.mkdir()
    (plugin_directory / "controller_rule.py").write_text(
        "from c2hunter_analysis.domain import Evidence\n"
        "DETECTOR_NAME = 'controller-rule'\n"
        "DETECTOR_VERSION = '4.0.0'\n"
        "def analyze(context):\n"
        "    return [Evidence('203.0.113.88', 'COMMON_DESTINATION', 'ignored', '0', "
        "5, 5, 'controller rule match')]\n"
    )
    monkeypatch.setenv("C2HUNTER_CUSTOM_DETECTORS_DIR", str(plugin_directory))

    candidates = evaluate_candidates(
        {
            "dataset_id": "dataset-custom-controller",
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-01T01:00:00+00:00",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "flow_records": [],
            "analysis": {"periodicity_min_samples": 3},
        }
    )

    assert candidates[0].candidate_ip == "203.0.113.88"
    assert candidates[0].evidence[0].detector == "controller-rule"
    assert candidates[0].evidence[0].version == "4.0.0"


def test_evaluate_candidates_treats_whitespace_detector_directory_as_unset(
    tmp_path: Path, monkeypatch: Any
) -> None:
    (tmp_path / "cwd_rule.py").write_text(
        "from c2hunter_analysis.domain import Evidence\n"
        "DETECTOR_NAME = 'cwd-rule'\n"
        "def analyze(context):\n"
        "    return [Evidence('203.0.113.89', 'COMMON_DESTINATION', 'ignored', '0', "
        "5, 5, 'must not load')]\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("C2HUNTER_CUSTOM_DETECTORS_DIR", " \t ")

    candidates = evaluate_candidates(
        {
            "dataset_id": "dataset-whitespace-controller",
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-01T01:00:00+00:00",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "flow_records": [],
            "analysis": {"periodicity_min_samples": 3},
        }
    )

    assert candidates == []
