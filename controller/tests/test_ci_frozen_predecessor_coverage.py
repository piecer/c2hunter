"""Frozen compatibility code is test-owned, never current product coverage."""

import ast
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from coverage import CoverageData

_FROZEN = (
    "test_ai_job_investigation_store.py::"
    "test_frozen_predecessor_claims_only_ip_in_real_mixed_sqlite_queue"
)
_SENTINEL = "test_pcap_indexed_export.py::test_run_checks_invokes_one_shared_durable_guard_once"


def test_frozen_predecessor_does_not_pollute_native_product_coverage(tmp_path):
    tests = Path(__file__).resolve().parent
    root = tests.parents[1]
    product = root / "controller/src/c2hunter_controller/pcap_indexed_export.py"
    function = next(
        node
        for node in ast.parse(product.read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name == "_run_checks"
    )
    required = {statement.lineno for statement in function.body}
    runs = []
    for label, selected in (("control", [_SENTINEL]), ("frozen", [_FROZEN, _SENTINEL])):
        output = tmp_path / label
        output.mkdir()
        for directory in ("home", "tmp"):
            (output / directory).mkdir()
        # An allowlist excludes COV_CORE_* startup inherited from an outer pytest-cov.
        env = {
            "PATH": os.defpath,
            "HOME": str(output / "home"),
            "TMPDIR": str(output / "tmp"),
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
        command = [
            sys.executable,
            "-I",
            "-B",
            str(root / "tools/ci_pytest.py"),
            "--output-root",
            str(output / "evidence"),
            "--",
            "-q",
            "-W",
            "error::DeprecationWarning",
            "-p",
            "no:cacheprovider",
            "-p",
            "pytest_cov",
            f"--basetemp={output / 'pytest'}",
            "--cov=c2hunter_controller",
            f"--cov-config={root / 'controller/pyproject.toml'}",
            "--cov-context=test",
            *(str(tests / node) for node in selected),
        ]
        (output / "command.json").write_text(json.dumps(command, indent=2))
        result = subprocess.run(
            command, cwd=root, env=env, capture_output=True, text=True, timeout=180, check=False
        )
        (output / "child.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, result.stdout + result.stderr
        [evidence] = (output / "evidence").glob("invocation-*")
        invocation = json.loads((evidence / "invocation.json").read_text())
        assert invocation["child_exit"] == invocation["exit"] == 0
        assert invocation["cleanup"] == "complete"
        progress = [
            json.loads(line) for line in (evidence / "progress.jsonl").read_text().splitlines()
        ]
        finished = [event for event in progress if event["event"] == "FINISH"]
        assert len(finished) == len(selected)
        for event, node in zip(finished, selected, strict=True):
            assert event["nodeid"].endswith(node)
            assert event["outcomes"] == {"setup": "passed", "call": "passed", "teardown": "passed"}
        data = CoverageData(basename=str(evidence / ".coverage"))
        data.read()
        measured = {
            line
            for line, contexts in data.contexts_by_lineno(str(product)).items()
            if any(context.endswith(_SENTINEL + "|run") for context in contexts)
        }
        assert not required - measured, (required, measured)
        files = sorted(data.measured_files())
        unexpected = {
            filename: data.lines(filename)
            for filename in files
            if not Path(filename).is_relative_to(root / "controller/src/c2hunter_controller")
            or not Path(filename).is_file()
        }
        report = ET.parse(evidence / "coverage.xml").getroot()
        denominator = {
            item.attrib["filename"]: [line.attrib["number"] for line in item.findall("lines/line")]
            for item in report.findall(".//class")
        }
        runs.append(
            {
                "label": label,
                "files": files,
                "unexpected": unexpected,
                "denominator": denominator,
                "lines_valid": report.attrib["lines-valid"],
                "required_product_lines": sorted(required),
                "measured_sentinel_lines": sorted(measured),
                "product_sha256": hashlib.sha256(product.read_bytes()).hexdigest(),
                "fixture_sha256": hashlib.sha256(
                    (tests / _FROZEN.split("::")[0]).read_bytes()
                ).hexdigest(),
            }
        )
    (tmp_path / "proof.json").write_text(json.dumps(runs, indent=2))
    assert runs[0]["denominator"] == runs[1]["denominator"]
    assert runs[0]["lines_valid"] == runs[1]["lines_valid"]
    assert not runs[0]["unexpected"]
    assert not runs[1]["unexpected"], runs[1]["unexpected"]
    assert runs[0]["files"] == runs[1]["files"]
