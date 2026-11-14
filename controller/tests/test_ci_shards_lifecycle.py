"""Actual run-time collection, failure, skip and nested-plugin boundaries."""

import json
import os
import subprocess
import sys
import time

import pytest
from test_ci_shards_engine import invoke, okay, plan, world


def snapshot(root):
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture delta",
        ],
        check=True,
    )


def test_production_plan_rejects_untracked_test_but_dev_binds_it(tmp_path):
    root = world(tmp_path / "source")
    new = root / "controller/tests/test_new_file.py"
    new.write_text("def test_new():\n    pass\n")
    result = invoke(root, "plan", "--output", tmp_path / "production.json")
    assert result.returncode != 0, "hosted plan accepted non-HEAD source"
    destination = tmp_path / "development.json"
    okay(invoke(root, "plan", "--allow-dirty", "--output", destination))
    data = json.loads(destination.read_text())
    assert "controller/tests/test_new_file.py" in data["source"]["files"]
    assert any(
        r["file"] == "controller/tests/test_new_file.py"
        for r in data["suites"]["plain"]["inventory"]
    )


def test_effective_collection_options_are_observed(tmp_path):
    root = world(tmp_path / "source")
    path, data = plan(root)
    assert data["integration"]["identity"]["options"]["markexpr"] == "not e2e"
    assert data["suites"]["plain"]["identity"]["options"]["markexpr"] == ""
    assert data["suites"]["controller-coverage"]["identity"]["options"]["cov_source"] == [
        "c2hunter_controller"
    ]


@pytest.mark.parametrize("phase", ["setup", "call", "teardown", "skip", "xfail", "teardown-skip"])
def test_real_outcomes_preserve_original_exit_and_skip_identity(tmp_path, phase):
    root = world(tmp_path / "source", coverage=True)
    prefix = "import pytest\nfrom c2hunter_controller.logic import part0\n"
    bodies = {
        "setup": '@pytest.fixture\ndef fixture():\n    raise RuntimeError("setup")\n'
        "def test_body(fixture):\n    part0()\n",
        "call": "def test_body():\n    assert part0() == 99\n",
        "teardown-skip": "@pytest.fixture\ndef fixture():\n    yield\n"
        '    pytest.skip("teardown skip")\n'
        "def test_body(fixture):\n    part0()\n",
        "teardown": "@pytest.fixture\ndef fixture():\n    yield\n"
        '    raise RuntimeError("teardown")\n'
        "def test_body(fixture):\n    part0()\n",
        "skip": '@pytest.mark.skip(reason="planned skip")\ndef test_body():\n    part0()\n',
        "xfail": '@pytest.mark.xfail(reason="expected")\n'
        "def test_body():\n    assert part0() == 99\n",
    }
    (root / "controller/tests/test_part0.py").write_text(prefix + bodies[phase])
    snapshot(root)
    path, data = plan(root)
    index = next(
        i
        for i, files in enumerate(data["suites"]["controller-coverage"]["shards"])
        if "controller/tests/test_part0.py" in files
    )
    output = tmp_path / "actual"
    result = invoke(
        root,
        "run",
        "--plan",
        path,
        "--suite",
        "controller-coverage",
        "--shard",
        index,
        "--output",
        output,
    )
    expected = 0 if phase in ("skip", "xfail", "teardown-skip") else 1
    assert result.returncode == expected, result.stdout + result.stderr
    receipt = json.loads((output / "shard-receipt.json").read_text())
    assert receipt["child_exit"] == receipt["wrapper_exit"] == expected
    assert receipt["cleanup"] == "complete"
    events = [
        json.loads(line) for line in next(output.rglob("progress.jsonl")).read_text().splitlines()
    ]
    finish = next(e for e in events if e["event"] == "FINISH")
    if expected:
        assert finish["outcomes"][phase] == "failed"
    else:
        assert "skipped" in finish["outcomes"].values()
    assert next(output.rglob(".coverage")).is_file()


def test_runtime_inventory_mismatch_fails_before_any_body(tmp_path):
    root = world(tmp_path / "source")
    (root / "controller/tests/conftest.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "def pytest_collection_modifyitems(items):\n"
        '    if os.environ.get("SHARD_REORDER"):\n        items.reverse()\n'
        'def pytest_runtest_call(item):\n    Path("body-entered").write_text("yes")\n'
    )
    snapshot(root)
    path, data = plan(root)
    output = tmp_path / "attempt"
    result = invoke(
        root,
        "run",
        "--plan",
        path,
        "--suite",
        "plain",
        "--shard",
        0,
        "--output",
        output,
        env_extra={"SHARD_REORDER": "1"},
    )
    assert result.returncode != 0
    assert "full collection mismatch" in result.stdout + result.stderr
    assert not (root / "body-entered").exists()
    receipt = json.loads((output / "shard-receipt.json").read_text())
    assert receipt["child_exit"] != 0
    assert receipt["cleanup"] == "complete"


def test_native_shard_does_not_inject_plugins_or_coverage_into_nested_pytest(tmp_path):
    root = world(tmp_path / "source", coverage=True)
    nested = root / "nested_case.py"
    nested.write_text(
        "import os\ndef test_nested(pytestconfig):\n"
        '    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "COVERAGE_FILE"):\n'
        "        assert name not in os.environ\n"
        '    assert not pytestconfig.pluginmanager.hasplugin("ci_shard_plugin")\n'
        '    assert not pytestconfig.pluginmanager.hasplugin("ci_pytest")\n'
    )
    (root / "controller/tests/test_part0.py").write_text(
        "import subprocess, sys, json\nfrom pathlib import Path\n"
        "from c2hunter_controller.logic import part0\n"
        "def test_nested(monkeypatch):\n"
        "    root = Path(__file__).resolve().parents[2]\n"
        '    command = [sys.executable, "-m", "pytest", "-q", str(root / "nested_case.py")]\n'
        "    child = subprocess.run(command, cwd=root)\n"
        "    assert child.returncode == 0\n"
        '    def guarded(*args, **kwargs):\n        raise RuntimeError("shared encoder guarded")\n'
        '    monkeypatch.setattr(json, "dumps", guarded)\n'
        "    assert part0() == 1\n"
    )
    snapshot(root)
    path, data = plan(root)
    index = next(
        i
        for i, files in enumerate(data["suites"]["controller-coverage"]["shards"])
        if "controller/tests/test_part0.py" in files
    )
    output = tmp_path / "native"
    okay(
        invoke(
            root,
            "run",
            "--plan",
            path,
            "--suite",
            "controller-coverage",
            "--shard",
            index,
            "--output",
            output,
            env_extra={"CI_SECRET_SENTINEL": "not-a-real-secret-123"},
        )
    )
    assert "not-a-real-secret-123" not in "".join(p.read_text() for p in output.rglob("*.json"))


@pytest.mark.parametrize(
    "variable", ["PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "COVERAGE_FILE"]
)
def test_ambient_configuration_is_refused(tmp_path, variable):
    root = world(tmp_path / "source")
    result = invoke(root, "plan", "--output", tmp_path / "plan.json", env_extra={variable: "bad"})
    assert result.returncode != 0
    assert "ambient pytest/coverage configuration" in result.stderr


def test_stale_plan_and_run_outputs_are_not_overwritten(tmp_path):
    root = world(tmp_path / "source")
    path, data = plan(root)
    before = path.read_bytes()
    assert invoke(root, "plan", "--output", path).returncode != 0
    assert path.read_bytes() == before
    output = tmp_path / "output"
    output.mkdir()
    (output / "sentinel").write_text("preserve")
    assert (
        invoke(
            root, "run", "--plan", path, "--suite", "plain", "--shard", 0, "--output", output
        ).returncode
        != 0
    )
    assert (output / "sentinel").read_text() == "preserve"


def test_source_changed_by_child_cannot_publish_success_receipt(tmp_path):
    root = world(tmp_path / "source")
    (root / "controller/tests/test_part0.py").write_text(
        "from pathlib import Path\ndef test_mutating_source():\n"
        '    path = Path("analysis/tests/test_analysis.py")\n'
        '    path.write_text(path.read_text() + "\\n# drift\\n")\n'
    )
    snapshot(root)
    path, data = plan(root)
    index = next(
        i
        for i, files in enumerate(data["suites"]["plain"]["shards"])
        if "controller/tests/test_part0.py" in files
    )
    output = tmp_path / "drift"
    result = invoke(
        root, "run", "--plan", path, "--suite", "plain", "--shard", index, "--output", output
    )
    assert result.returncode != 0
    receipt = json.loads((output / "shard-receipt.json").read_text())
    assert receipt["child_exit"] == receipt["wrapper_exit"] == 0
    assert receipt["engine_exit"] != 0
    assert receipt["source_after"] != receipt["source"]


def test_engine_cancellation_retires_actual_child_and_records_failure(tmp_path):
    root = world(tmp_path / "source")
    (root / "controller/tests/test_part0.py").write_text(
        "import time\nfrom pathlib import Path\ndef test_wait():\n"
        '    Path("ready").write_text("ready")\n    time.sleep(3)\n'
    )
    snapshot(root)
    path, data = plan(root)
    index = next(
        i
        for i, files in enumerate(data["suites"]["plain"]["shards"])
        if "controller/tests/test_part0.py" in files
    )
    output = tmp_path / "cancelled"
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PYTHONPATH", "PYTEST_ADDOPTS", "PYTEST_PLUGINS", "COVERAGE_FILE")
        and not k.startswith("COV_CORE_")
    }
    process = subprocess.Popen(
        [
            sys.executable,
            str(root / "tools/ci_shards.py"),
            "run",
            "--plan",
            str(path),
            "--suite",
            "plain",
            "--shard",
            str(index),
            "--output",
            str(output),
        ],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not (root / "ready").exists() and process.poll() is None:
            assert time.monotonic() < deadline, "child never became ready"
            time.sleep(0.02)
        assert (root / "ready").exists()
        process.terminate()
        log, _ = process.communicate(timeout=10)
        assert process.returncode != 0, log
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)
    receipt_path = output / "shard-receipt.json"
    assert receipt_path.is_file(), "engine died without retiring/recording its child"
    receipt = json.loads(receipt_path.read_text())
    assert receipt["engine_exit"] != 0
    assert receipt["child_exit"] != 0
    assert receipt["wrapper_exit"] == 143
    assert receipt["cleanup"] == "complete"
    actual = json.loads(next(output.rglob("invocation.json")).read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(actual["child_pid"], 0)
