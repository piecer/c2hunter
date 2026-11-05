"""Run the real fault inventories without stealing pytest-cov's tracer."""

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from coverage import CoverageData

_SENTINEL = "test_pcap_indexed_export.py::test_run_checks_invokes_one_shared_durable_guard_once"
_INVENTORIES = [
    (None, None),
    (
        "test_baseline_control_faults.py::test_memory_fallible_preparation_inventory[FREEZE]",
        "memory",
    ),
    (
        "test_baseline_control_completion.py::test_value_and_memory_preparation_sites[memory-FREEZE]",
        "value",
    ),
]


class _TraceObserver:
    """Observe actual objects; never replace or repair a trace function."""

    def __init__(self, output: Path) -> None:
        self.output = output
        self.calls = []
        self.reports = []

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_call(self, item):
        before = sys.gettrace()
        yield
        after = sys.gettrace()
        source = Path(item.obj.__code__.co_filename).resolve()
        self.calls.append(
            {
                "nodeid": item.nodeid,
                "source": str(source),
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "before_type": f"{type(before).__module__}.{type(before).__name__}",
                "before_id": id(before),
                "after_id": id(after),
                "same_object": before is after,
            }
        )

    def pytest_runtest_logreport(self, report):
        self.reports.append(
            {"nodeid": report.nodeid, "when": report.when, "outcome": report.outcome}
        )

    def pytest_sessionfinish(self, session, exitstatus):
        origins = {
            name: str(Path(module.__file__).resolve())
            for name, module in list(sys.modules.items())
            if name.startswith(("c2hunter_controller", "c2hunter_analysis"))
            and getattr(module, "__file__", None)
        }
        self.output.write_text(
            json.dumps({"calls": self.calls, "reports": self.reports, "origins": origins}, indent=2)
        )


@pytest.mark.parametrize("inventory,kind", _INVENTORIES, ids=["control", "memory", "value"])
def test_fault_inventory_preserves_pytest_cov_tracer(tmp_path, inventory, kind):
    tests = Path(__file__).resolve().parent
    root = tests.parents[1]
    for directory in ("home", "tmp"):
        (tmp_path / directory).mkdir()
    # Do not inherit coverage startup, service credentials, PYTHONPATH or pytest options.
    env = {
        "PATH": os.defpath,
        "HOME": str(tmp_path / "home"),
        "TMPDIR": str(tmp_path / "tmp"),
        "LANG": "C.UTF-8",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "COVERAGE_FILE": str(tmp_path / ".coverage"),
        "CONTROL_EVIDENCE": str(tmp_path / "faults.jsonl"),
    }
    selected = ([inventory] if inventory else []) + [_SENTINEL]
    # Load this observer by filename, not through the ambiguous tests.* namespace.
    # Only explicit existing nodeids run in the child, so this cannot recurse.
    command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        "import pathlib,runpy,sys,pytest; "
        "observer=runpy.run_path(sys.argv[1])['_TraceObserver'](pathlib.Path(sys.argv[2])); "
        "raise SystemExit(pytest.main(sys.argv[3:], plugins=[observer]))",
        str(Path(__file__).resolve()),
        str(tmp_path / "trace.json"),
        "-q",
        "-p",
        "no:cacheprovider",
        "-p",
        "pytest_cov",
        "-c",
        str(root / "controller/pyproject.toml"),
        f"--basetemp={tmp_path / 'pytest'}",
        "--cov=c2hunter_controller.pcap_indexed_export",
        f"--cov-config={root / 'controller/pyproject.toml'}",
        f"--cov-report=json:{tmp_path / 'coverage.json'}",
        "--cov-context=test",
        *(str(tests / node) for node in selected),
    ]
    (tmp_path / "command.json").write_text(json.dumps(command, indent=2))
    result = subprocess.run(
        command, cwd=root, env=env, capture_output=True, text=True, timeout=300, check=False
    )
    (tmp_path / "child.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads((tmp_path / "trace.json").read_text())
    assert len(observed["calls"]) == len(selected)
    assert len(observed["reports"]) == 3 * len(selected)
    assert all(report["outcome"] == "passed" for report in observed["reports"])
    for call, node in zip(observed["calls"], selected, strict=True):
        source = tests / node.split("::")[0]
        assert call["source"] == str(source)
        assert call["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert call["nodeid"].endswith(node)
    assert observed["origins"]
    for name, origin in observed["origins"].items():
        package = "controller" if name.startswith("c2hunter_controller") else "analysis"
        assert Path(origin).is_relative_to(root / package / "src"), (name, origin)

    faults = []
    if inventory:
        lines = (tmp_path / "faults.jsonl").read_text().splitlines()
        records = [json.loads(line) for line in lines]
        inventories = [record for record in records if record["kind"] == f"{kind}-inventory"]
        faults = [record for record in records if record["kind"] == f"{kind}-stage-fault"]
        assert len(inventories) == 1 and inventories[0]["sites"]
        assert len(faults) == len(inventories[0]["sites"])
        source_hash = hashlib.sha256(
            (root / "controller/src/c2hunter_controller/_baseline_storage.py").read_bytes()
        ).hexdigest()
        for target, (fault, site) in enumerate(zip(faults, inventories[0]["sites"], strict=True)):
            assert fault["fired"] == 1 and fault["target"] == target and fault["site"] == site
            assert fault["source_sha256"] == source_hash

    product = root / "controller/src/c2hunter_controller/pcap_indexed_export.py"
    function = next(
        node
        for node in ast.parse(product.read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name == "_run_checks"
    )
    # These two body lines execute only in the post-inventory sentinel, not at import.
    required = {statement.lineno for statement in function.body}
    data = CoverageData(basename=str(tmp_path / ".coverage"))
    data.read()
    contexts = data.contexts_by_lineno(str(product))
    measured = {
        line
        for line, names in contexts.items()
        if any(name.endswith(_SENTINEL + "|run") for name in names)
    }
    proof = {
        "calls": observed["calls"],
        "injected_faults": len(faults),
        "required_product_lines": sorted(required),
        "missing_post_inventory_lines": sorted(required - measured),
        "product_source": str(product),
        "product_sha256": hashlib.sha256(product.read_bytes()).hexdigest(),
    }
    (tmp_path / "proof.json").write_text(json.dumps(proof, indent=2))
    assert (
        all(
            call["before_type"].startswith("coverage.") and call["same_object"]
            for call in observed["calls"]
        )
        and not required - measured
    ), json.dumps(proof, indent=2)
