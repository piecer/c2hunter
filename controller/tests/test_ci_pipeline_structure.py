"""Full CI contracts: all commands retained, complete shards and required gates."""

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def recipe(target: str) -> list[str]:
    makefile = (ROOT / "Makefile").read_text()
    match = re.search(rf"^{re.escape(target)}:.*\n((?:\t.*\n|\n)*)", makefile, re.MULTILINE)
    assert match, f"Missing canonical target: {target}"
    return [line for line in match[1].splitlines() if line.startswith("\t")]


def test_coverage_is_factored_without_reordering_or_changing_commands() -> None:
    assert recipe("test-coverage") == [
        "\t# Ratchet current package baselines separately so aggregate coverage "
        "cannot hide a regression.",
        "\t$(MAKE) test-coverage-controller",
        "\t$(MAKE) test-coverage-analysis",
        "\t$(MAKE) test-coverage-sensor",
    ]
    assert recipe("test-coverage-controller") == [
        "\t$(PYTEST) -q controller/tests --cov=c2hunter_controller "
        "--cov-config=controller/pyproject.toml --cov-report=term --cov-fail-under=80"
    ]
    assert recipe("test-coverage-analysis") == [
        "\t$(PYTEST) -q analysis/tests --cov=c2hunter_analysis "
        "--cov-report=term --cov-fail-under=86",
        "\t$(PYTEST) -q analysis/tests --cov=c2hunter_analysis.detectors "
        "--cov-report=term --cov-fail-under=90",
    ]
    sensor = recipe("test-coverage-sensor")
    assert len(sensor) == 6
    assert (
        sensor[0] == "\tcd sensor && go test -coverprofile=/tmp/c2hunter-sensor-coverage.out ./..."
    )
    assert sensor[3] == (
        "\tcd sensor && go test -coverprofile=/tmp/c2hunter-sensor-core-coverage.out "
        "$(SENSOR_CORE_PACKAGES)"
    )
    assert '"$(SENSOR_COVERAGE_MIN)"' in sensor[2]
    assert '"$(SENSOR_CORE_COVERAGE_MIN)"' in sensor[5]
    makefile = (ROOT / "Makefile").read_text()
    assert "SENSOR_COVERAGE_MIN := 69.0\n" in makefile
    assert "SENSOR_CORE_COVERAGE_MIN := 80.0\n" in makefile
    # Recursive recipes, rather than prerequisites, also serialize under make -j.
    dry = subprocess.run(
        ["make", "--no-print-directory", "-n", "-j8", "test-coverage"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    positions = [
        dry.index(part)
        for part in (
            "--cov=c2hunter_controller",
            "--cov=c2hunter_analysis ",
            "--cov=c2hunter_analysis.detectors",
            "-coverprofile=/tmp/c2hunter-sensor-coverage.out",
            "-coverprofile=/tmp/c2hunter-sensor-core-coverage.out",
        )
    ]
    assert positions == sorted(positions)


WORK_JOBS = (
    "lint",
    "security",
    "shard-plan",
    "python",
    "python-verify",
    "unit-go",
    "unit-worker",
    "unit-tools",
    "unit-web",
    "coverage-controller",
    "coverage-controller-merge",
    "coverage-analysis",
    "coverage-sensor",
    "scenarios",
    "e2e",
    "build",
)

SHARD_TARGETS = {
    "shard-plan": "ci-plan",
    "python": "ci-test-python",
    "python-verify": "ci-verify-python",
    "coverage-controller": "ci-test-coverage-controller",
    "coverage-controller-merge": "ci-merge-coverage-controller",
}


def job_blocks() -> dict[str, str]:
    # Deliberately limited text assertions, not a substitute for a YAML parser.
    text = (ROOT / ".github/workflows/ci.yml").read_text().split("\njobs:\n", 1)[1]
    matches = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\n", text, re.MULTILINE))
    return {
        match[1]: text[
            match.end() : matches[index + 1].start() if index + 1 < len(matches) else None
        ]
        for index, match in enumerate(matches)
    }


def test_job_graph_has_parallel_work_and_a_complete_always_gate() -> None:
    jobs = job_blocks()
    assert set(jobs) == {*WORK_JOBS, "ci"}
    for name in WORK_JOBS:
        needs = re.findall(r"^    needs: (.+)$", jobs[name], re.MULTILINE)
        expected = {
            "lint": [],
            "security": [],
            "python": ["shard-plan"],
            "coverage-controller": ["shard-plan"],
            "python-verify": ["[shard-plan, python]"],
            "coverage-controller-merge": ["[shard-plan, coverage-controller]"],
        }.get(name, ["lint"])
        assert needs == expected
        assert "    timeout-minutes: 360\n" in jobs[name]
    gate = jobs["ci"]
    assert "    if: always()\n" in gate
    needs = re.search(r"^    needs: \[(.*)\]$", gate, re.MULTILINE)
    assert needs
    assert needs[1].split(", ") == list(WORK_JOBS)
    assert "NEEDS_JSON: ${{ toJSON(needs) }}" in gate


def gate_script() -> str:
    gate = job_blocks().get("ci", "")
    marker = "        run: |\n"
    assert marker in gate, "Missing executable final CI gate"
    return textwrap.dedent(gate.split(marker, 1)[1])


@pytest.mark.parametrize(
    "state", ["success", "failure", "cancelled", "skipped", "unknown", "", None]
)
@pytest.mark.parametrize("job", WORK_JOBS)
def test_actual_final_gate_requires_every_success(job: str, state: str | None) -> None:
    results = {name: {"result": "success"} for name in WORK_JOBS}
    results[job]["result"] = state
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", gate_script()],
        env={**os.environ, "NEEDS_JSON": json.dumps(results)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) == (state == "success"), result.stdout + result.stderr


@pytest.mark.parametrize(
    "fault", ["missing-job", "extra-job", "missing-result", "non-object", "bad-json"]
)
def test_actual_final_gate_rejects_incomplete_or_malformed_needs(fault: str) -> None:
    results = {name: {"result": "success"} for name in WORK_JOBS}
    if fault == "missing-job":
        del results["security"]
    elif fault == "extra-job":
        results["unexpected"] = {"result": "success"}
    elif fault == "missing-result":
        results["python-verify"] = {}
    payload = json.dumps(results)
    if fault == "non-object":
        payload = "[]"
    elif fault == "bad-json":
        payload = "not-json"
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", gate_script()],
        env={**os.environ, "NEEDS_JSON": payload},
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0


def test_jobs_keep_runtime_dependencies_commands_and_diagnostic_reserve() -> None:
    jobs = job_blocks()
    artifact_names = []
    for name in WORK_JOBS:
        block = jobs[name]
        for step in block.split("      - ")[1:]:
            if step.startswith("uses: actions/upload-artifact@v4"):
                artifact_names.extend(re.findall(r"^          name: (.+)$", step, re.MULTILINE))
        assert "      - uses: actions/upload-artifact@v4\n        if: always()\n" in block
        assert "          include-hidden-files: true\n" in block
        if name == "security":
            continue
        for runtime in ("actions/setup-python@v5", "actions/setup-go@v5", "actions/setup-node@v4"):
            assert runtime in block
        assert "python-version: '3.12'" in block
        assert "go-version: '1.25.12'" in block
        assert "node-version: '22.14.0'" in block
        assert "run: make setup\n" in block
        target = SHARD_TARGETS.get(name, name if name in ("lint", "build") else "test-" + name)
        assert f"make {target} 2>&1 | tee artifacts/ci/{name}.log" in block
        assert "          set -o pipefail\n" in block
        assert "        timeout-minutes: 330\n" in block
        targets = re.findall(r"make ((?:test|ci)-[a-z0-9-]+)", block)
        assert targets == ([] if name in ("lint", "build") else [target])
    assert len(artifact_names) == len(set(artifact_names)) >= len(WORK_JOBS)


def test_ci_opt_in_wraps_only_top_level_pytest_without_changing_local_commands() -> None:
    assert recipe("test-unit") == [
        "\t$(MAKE) test-unit-go",
        "\t$(MAKE) test-unit-python",
        "\t$(MAKE) test-unit-worker",
        "\t$(MAKE) test-unit-tools",
        "\t$(MAKE) test-unit-web",
    ]
    commands = [
        line
        for target in ("go", "python", "worker", "tools", "web")
        for line in recipe("test-unit-" + target)
    ]
    assert commands == [
        "\tcd sensor && go test ./...",
        "\t$(PYTEST) -q controller/tests analysis/tests",
        "\tPYTHONPATH=sensor/worker/src $(PYTEST) -q sensor/worker/tests",
        "\t$(VENV)/bin/python tools/traffic-generator/test_generate.py",
        "\t$(VENV)/bin/python tools/benchmark/test_benchmark.py",
        "\t$(VENV)/bin/python tools/benchmark/test_ddos_analysis.py",
        "\tPYTHONPATH=controller/src:analysis/src $(VENV)/bin/python "
        "tools/benchmark/test_pcap_export_benchmark.py",
        "\tnpm --prefix web run test",
    ]
    assert recipe("test-integration") == [
        '\t$(PYTEST) -q controller/tests analysis/tests -m "not e2e"',
        "\t$(VENV)/bin/python tools/traffic-generator/generate.py --output testdata/generated",
    ]
    assert recipe("test-e2e") == [
        "\tnpm --prefix web exec playwright install chromium",
        "\tnpm --prefix web run test:e2e",
    ]
    env = {key: value for key, value in os.environ.items() if key != "CI_PYTEST_EVIDENCE"}
    dry = subprocess.run(
        ["make", "-n", "test-unit"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    wrapped = subprocess.run(
        ["make", "-n", "test-unit", "CI_PYTEST_EVIDENCE=1"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    assert "tools/ci_pytest.py" not in dry
    assert wrapped.count(".venv/bin/python tools/ci_pytest.py --") == 2
    assert wrapped.replace(".venv/bin/python tools/ci_pytest.py --", ".venv/bin/pytest") == dry
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "PYTEST_ADDOPTS" not in text and "PYTEST_PLUGINS" not in text
    jobs = job_blocks()
    for job in ("unit-worker", "coverage-analysis"):
        assert "          CI_PYTEST_EVIDENCE: '1'\n" in jobs[job]


def test_make_test_runs_every_distinct_command_once_without_plain_replay() -> None:
    env = {key: value for key, value in os.environ.items() if key != "CI_PYTEST_EVIDENCE"}
    result = subprocess.run(
        ["make", "--no-print-directory", "-n", "test"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    commands = [
        "cd sensor && go test ./...",
        ".venv/bin/pytest -q controller/tests analysis/tests",
        "PYTHONPATH=sensor/worker/src .venv/bin/pytest -q sensor/worker/tests",
        ".venv/bin/python tools/traffic-generator/test_generate.py",
        ".venv/bin/python tools/benchmark/test_benchmark.py",
        ".venv/bin/python tools/benchmark/test_ddos_analysis.py",
        "PYTHONPATH=controller/src:analysis/src .venv/bin/python "
        "tools/benchmark/test_pcap_export_benchmark.py",
        "npm --prefix web run test",
        ".venv/bin/python tools/traffic-generator/generate.py --output testdata/generated",
    ]
    lines = result.stdout.splitlines()
    assert all(lines.count(command) == 1 for command in commands), result.stdout
    assert '-m "not e2e"' not in result.stdout
    assert recipe("test-scenarios") == [
        "\t$(VENV)/bin/python tools/traffic-generator/generate.py --output testdata/generated"
    ]


def test_existing_job_setup_action_options_and_order_are_retained() -> None:
    jobs = job_blocks()
    for name in ("build",):
        block = jobs[name]
        assert block.index("actions/setup-python@v5") < block.index("actions/setup-node@v4")
        assert block.index("actions/setup-node@v4") < block.index("actions/setup-go@v5")
    assert "        with: { python-version: '3.12' }\n" in jobs["build"]


def test_setup_and_security_execution_also_reserve_upload_time() -> None:
    for name in WORK_JOBS:
        for step in job_blocks()[name].split("      - ")[1:]:
            if "run:" in step or step.startswith(("uses: gitleaks/", "uses: aquasecurity/")):
                assert "        timeout-minutes: 330\n" in step, (name, step.splitlines()[0])


@pytest.mark.parametrize("job,indices", [("python", "0, 1"), ("coverage-controller", "0, 1, 2, 3")])
def test_matrix_shards_keep_siblings_running_and_publish_distinct_evidence(job, indices):
    block = job_blocks()[job]
    assert "      fail-fast: false\n" in block
    assert f"        shard: [{indices}]\n" in block
    assert "          CI_SHARD: '${{ matrix.shard }}'\n" in block
    assert (
        f"          name: ci-{job}-${{{{ github.run_attempt }}}}-${{{{ matrix.shard }}}}\n" in block
    )
    assert "          name: ci-shard-plan-${{ github.run_attempt }}\n" in block
    assert "          path: artifacts/ci-shards\n" in block


@pytest.mark.parametrize(
    "job,producer",
    [("python-verify", "python"), ("coverage-controller-merge", "coverage-controller")],
)
def test_reconciliation_downloads_all_raw_artifacts_without_flattening(job, producer):
    block = job_blocks()[job]
    assert "uses: actions/download-artifact@v4" in block
    assert f"          pattern: ci-{producer}-${{{{ github.run_attempt }}}}-*\n" in block
    assert "          merge-multiple: false\n" in block
    assert "continue-on-error" not in block
    assert "if: always()" in job_blocks()["ci"]


def test_ci_make_targets_bind_the_real_engine_and_separate_input_output_roots():
    expected = {
        "ci-plan": "plan --output artifacts/ci-shards/plan.json",
        "ci-test-python": "run --plan artifacts/ci-shards/plan.json --suite plain "
        "--shard $(CI_SHARD) --output artifacts/ci-shards/plain-$(CI_SHARD)",
        "ci-test-coverage-controller": "run --plan artifacts/ci-shards/plan.json "
        "--suite controller-coverage --shard $(CI_SHARD) "
        "--output artifacts/ci-shards/controller-coverage-$(CI_SHARD)",
        "ci-verify-python": "verify --plan artifacts/ci-shards/plan.json --suite plain "
        "--results artifacts/ci-shards/downloaded-plain",
        "ci-merge-coverage-controller": "combine --plan artifacts/ci-shards/plan.json "
        "--results artifacts/ci-shards/downloaded-controller-coverage "
        "--output artifacts/ci-shards/combined-controller-coverage",
    }
    for target, arguments in expected.items():
        assert recipe(target) == ["\t$(VENV)/bin/python tools/ci_shards.py " + arguments]
