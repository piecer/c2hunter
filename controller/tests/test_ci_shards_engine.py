"""Exercise the sharding CLI in real, isolated repository/pytest worlds."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def invoke(root, *args, env_extra=None):
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PYTHONPATH", "PYTEST_PLUGINS", "PYTEST_ADDOPTS", "COVERAGE_FILE")
        and not k.startswith("COV_CORE_")
    }
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(root / "tools/ci_shards.py"), *map(str, args)],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def okay(result):
    assert result.returncode == 0, result.stdout + result.stderr


def world(root, *, coverage=False, unused=2):
    for name in (
        "tools",
        "controller/tests",
        "analysis/tests",
        "controller/src/c2hunter_controller",
    ):
        (root / name).mkdir(parents=True)
    for path in (ROOT / "tools").glob("ci_shard*"):
        if path.is_file():
            shutil.copyfile(path, root / "tools" / path.name)
    shutil.copyfile(ROOT / "tools/ci_pytest.py", root / "tools/ci_pytest.py")
    (root / "controller/pyproject.toml").write_text(
        '[tool.pytest.ini_options]\npythonpath=["src"]\n'
        'markers=["e2e: end to end"]\n'
        "[tool.coverage.run]\nomit=[]\n"
    )
    (root / "controller/src/c2hunter_controller/__init__.py").write_text("")
    for i in range(4):
        (root / f"controller/tests/test_part{i}.py").write_text(
            'import pytest\n@pytest.mark.parametrize("value", ["a::b", "x[y]"])\n'
            f"def test_part{i}(value):\n    assert value\n"
        )
    (root / "analysis/tests/test_analysis.py").write_text(
        "import pytest\n@pytest.mark.e2e\ndef test_analysis():\n    pass\n"
    )
    if coverage:
        package = root / "controller/src/c2hunter_controller"
        (package / "logic.py").write_text(
            "".join(f"def part{i}():\n    a = {i}\n    b = a + 1\n    return b\n" for i in range(4))
        )
        (package / "untouched.py").write_text("".join(f"x{i} = {i}\n" for i in range(unused)))
        for i in range(4):
            (root / f"controller/tests/test_part{i}.py").write_text(
                f"from c2hunter_controller.logic import part{i}\n"
                f"def test_part{i}():\n    assert part{i}() == {i + 1}\n"
            )
    subprocess.run(["git", "init", "-q", str(root)], check=True)
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
            "fixture",
        ],
        check=True,
    )
    return root


def plan(root):
    destination = root / "artifacts/plan.json"
    okay(invoke(root, "plan", "--output", destination))
    return destination, json.loads(destination.read_text())


def test_plan_real_collection_literal_ids_partition_and_subset(tmp_path):
    root = world(tmp_path / "repo")
    path, data = plan(root)
    assert data["schema"] == 1
    assert len(data["suites"]["plain"]["inventory"]) == 9
    assert len(data["integration"]["inventory"]) == 8
    assert any("a::b]" in row["nodeid"] for row in data["suites"]["plain"]["inventory"])
    for name, count in [("plain", 2), ("controller-coverage", 4)]:
        suite = data["suites"][name]
        assert len(suite["shards"]) == count
        files = [f for group in suite["shards"] for f in group]
        assert len(files) == len(set(files))
        assert set(files) == {row["file"] for row in suite["inventory"]}
        assert all(suite["shards"])
        assert suite["identity"]["cwd"] == str(root)
        assert suite["identity"]["rootpath"]
    second = root / "artifacts/second.json"
    okay(invoke(root, "plan", "--output", second))
    assert json.loads(second.read_text())["suites"] == data["suites"]
    assert path.is_file()


def test_real_shards_complete_and_verify_download_layout(tmp_path):
    root = world(tmp_path / "repo")
    path, data = plan(root)
    results = root / "artifacts/downloaded"
    for index in range(2):
        output = results / f"unique-artifact-{index}"
        okay(
            invoke(
                root,
                "run",
                "--plan",
                path,
                "--suite",
                "plain",
                "--shard",
                index,
                "--output",
                output,
            )
        )
        receipt = json.loads((output / "shard-receipt.json").read_text())
        assert receipt["child_exit"] == receipt["wrapper_exit"] == 0
        assert receipt["cleanup"] == "complete"
        selection = json.loads((output / "selection.json").read_text())
        expected = [
            r
            for r in data["suites"]["plain"]["inventory"]
            if r["file"] in data["suites"]["plain"]["shards"][index]
        ]
        assert selection["inventory"] == expected
        assert selection["full"] == data["suites"]["plain"]["inventory"]
        progress = [
            json.loads(line)
            for line in next(output.rglob("progress.jsonl")).read_text().splitlines()
        ]
        assert [r["nodeid"] for r in progress if r["event"] == "FINISH"] == [
            r["nodeid"] for r in expected
        ]
    okay(invoke(root, "verify", "--plan", path, "--suite", "plain", "--results", results))
    (results / "unique-artifact-0" / "selection.json").write_text("{}")
    assert (
        invoke(root, "verify", "--plan", path, "--suite", "plain", "--results", results).returncode
        != 0
    )


def coverage_worlds(tmp_path, unused=2):
    seed = world(tmp_path / "seed", coverage=True, unused=unused)
    producers = []
    for i in range(4):
        target = tmp_path / f"producer-{i}"
        shutil.copytree(seed, target)
        producers.append(target)
    consumer = tmp_path / "consumer"
    shutil.copytree(seed, consumer)
    plan_path, data = plan(seed)
    results = tmp_path / "downloaded"
    for index, producer in enumerate(producers):
        okay(
            invoke(
                producer,
                "run",
                "--plan",
                plan_path,
                "--suite",
                "controller-coverage",
                "--shard",
                index,
                "--output",
                results / f"artifact-{index}",
            )
        )
    return consumer, plan_path, data, results


def test_raw_coverage_union_relocates_four_roots_and_keeps_denominator(tmp_path):
    from coverage import CoverageData

    consumer, path, data, results = coverage_worlds(tmp_path)
    raws = list(results.rglob(".coverage"))
    assert len(raws) == 4
    originals = {str(p): p.read_bytes() for p in raws}
    line_sets = []
    for raw in raws:
        db = CoverageData(basename=str(raw))
        db.read()
        logic = next(f for f in db.measured_files() if f.endswith("/logic.py"))
        assert "/producer-" in logic
        line_sets.append(set(db.lines(logic)))
    assert len({frozenset(s) for s in line_sets}) == 4
    output = tmp_path / "combined"
    okay(invoke(consumer, "combine", "--plan", path, "--results", results, "--output", output))
    report = json.loads((output / "coverage.json").read_text())
    assert report["totals"]["num_statements"] == 18
    assert report["totals"]["covered_lines"] == 16
    assert 80 <= report["totals"]["percent_covered"] < 100
    assert {str(p): p.read_bytes() for p in raws} == originals
    db = CoverageData(basename=str(output / ".coverage"))
    db.read()
    assert all(f.startswith(str(consumer)) for f in db.measured_files())
    assert next(v for k, v in report["files"].items() if k.endswith("/untouched.py"))[
        "missing_lines"
    ] == [1, 2]


def test_raw_coverage_low_union_fails_unchanged_80_floor(tmp_path):
    consumer, path, data, results = coverage_worlds(tmp_path, unused=30)
    output = tmp_path / "low"
    result = invoke(consumer, "combine", "--plan", path, "--results", results, "--output", output)
    assert result.returncode != 0
    report = json.loads((output / "coverage.json").read_text())
    assert report["totals"]["percent_covered"] < 80


def test_lpt_weights_are_hints_never_a_file_filter(tmp_path):
    root = world(tmp_path / "source")
    timing = root / "tools/ci_shard_timings.json"
    timing.write_text(
        json.dumps(
            {"weights": {"controller/tests/test_part0.py": 100, "absent/test_removed.py": 9000}}
        )
    )
    subprocess.run(["git", "-C", str(root), "add", "tools/ci_shard_timings.json"], check=True)
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
            "synthetic weights",
        ],
        check=True,
    )
    path, data = plan(root)
    groups = data["suites"]["plain"]["shards"]
    assert groups[0] == ["controller/tests/test_part0.py"]
    assert len(groups[1]) == 4
    assert "absent/test_removed.py" not in sum(groups, [])
