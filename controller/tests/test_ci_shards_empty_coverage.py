"""Real coverage producers: empty diagnostics never replace measured raw data."""

import importlib.util
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
import test_ci_shards_faults
from coverage import CoverageData
from test_ci_shards_engine import coverage_worlds, invoke, okay, plan, world
from test_ci_shards_faults import reseal

SPEC = importlib.util.spec_from_file_location(
    "empty_sidecar_engine", Path(__file__).resolve().parents[2] / "tools/ci_shards.py"
)
ENGINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENGINE)


def test_run_finalizes_real_child_empty_sidecar(tmp_path):
    root = world(tmp_path / "source", coverage=True)
    test = root / "controller/tests/test_part0.py"
    test.write_text(
        "import atexit\nfrom coverage import CoverageData\n"
        "from c2hunter_controller.logic import part0\n"
        "def test_part0(pytestconfig):\n"
        "    assert part0() == 1\n"
        "    path = pytestconfig.getoption('ci_coverage_file')\n"
        "    def finish():\n"
        "        data = CoverageData(basename=path, suffix=True)\n"
        "        data.add_lines({})\n"
        "        data.write()\n"
        "    atexit.register(finish)\n"
    )
    subprocess.run(["git", "-C", str(root), "add", str(test)], check=True)
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
            "empty sidecar fixture",
        ],
        check=True,
    )
    path, data = plan(root)
    index = next(
        i
        for i, group in enumerate(data["suites"]["controller-coverage"]["shards"])
        if "controller/tests/test_part0.py" in group
    )
    output = tmp_path / "run"
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
        )
    )
    receipt = ENGINE.read(output / "shard-receipt.json")
    assert receipt["engine_exit"] == receipt["child_exit"] == receipt["wrapper_exit"] == 0
    assert len(list(output.rglob(".coverage.*"))) == 1
    before = ENGINE.artifacts(output)
    ENGINE.check_receipt(output, receipt, data, "controller-coverage", root)
    assert ENGINE.artifacts(output) == before


@pytest.fixture(scope="module")
def produced(tmp_path_factory):
    root, plan, data, results = coverage_worlds(tmp_path_factory.mktemp("empty-sidecars"))
    for directory in results.iterdir():
        receipt = ENGINE.read(directory / "shard-receipt.json")
        invocation = directory / receipt["invocation"]
        database = CoverageData(basename=str(invocation / ".coverage"), suffix=True)
        database.add_lines({})
        database.write()
        assert Path(database.data_filename()).is_file()
        reseal(directory)
    return root, plan, data, results


def test_check_receipt_keeps_real_empty_sidecar_and_raw_bytes(produced):
    root, _, data, results = produced
    directory = results / "artifact-0"
    receipt = ENGINE.read(directory / "shard-receipt.json")
    before = ENGINE.artifacts(directory)
    assert ENGINE.check_receipt(directory, receipt, data, "controller-coverage", root) == {
        "passed": 1,
        "skipped": 0,
    }
    assert ENGINE.artifacts(directory) == before
    assert len(list(directory.rglob(".coverage"))) == 1
    assert len(list(directory.rglob(".coverage.*"))) == 1


def test_transported_combine_preserves_empty_sidecars_and_coverage(produced, tmp_path):
    root, plan, _, original = produced
    results = tmp_path / "downloaded"
    shutil.copytree(original, results)
    before = ENGINE.artifacts(results)
    output = tmp_path / "combined"
    okay(invoke(root, "combine", "--plan", plan, "--results", results, "--output", output))
    assert ENGINE.artifacts(results) == before
    report = json.loads((output / "coverage.json").read_text())
    assert report["totals"]["num_statements"] == 18
    assert report["totals"]["covered_lines"] == 16
    assert ENGINE.read(output / "aggregate-receipt.json")["floor"] == 80


@pytest.mark.parametrize("route", ["receipt", "combine"])
@pytest.mark.parametrize(
    "fault",
    [
        "file",
        "context",
        "line_bits",
        "arc",
        "tracer",
        "schema",
        "view",
        "extra-table",
        "unknown-meta",
        "version",
        "branch",
        "malformed",
        "truncated",
        "trailing",
        "oversize",
        "many",
        "wrong-name",
        "wrong-path",
        "noncoverage",
        "symlink",
        "tampered-hash",
        "missing-raw",
        "duplicate-raw",
    ],
)
def test_invalid_sidecars_fail_closed(produced, tmp_path, route, fault):
    root, plan, data, original = produced
    results = tmp_path / "downloaded"
    shutil.copytree(original, results)
    directory = results / "artifact-0"
    sidecar = next(directory.rglob(".coverage.*"))
    sql = {
        "file": "INSERT INTO file VALUES (1, 'unmerged.py')",
        "context": "INSERT INTO context VALUES (1, '')",
        "line_bits": "INSERT INTO line_bits VALUES (1, 1, x'02')",
        "arc": "INSERT INTO arc VALUES (1, 1, 1, 2)",
        "tracer": "INSERT INTO tracer VALUES (1, 'plugin')",
        "schema": "UPDATE coverage_schema SET version=999",
        "view": "DROP TABLE file; CREATE VIEW file AS SELECT 1 id, 'hidden.py' path WHERE 0",
        "extra-table": "CREATE TABLE extra (payload BLOB)",
        "unknown-meta": "INSERT INTO meta VALUES ('unknown', 'value')",
        "version": "UPDATE meta SET value='unknown' WHERE key='version'",
        "branch": "UPDATE meta SET value='1' WHERE key='has_arcs'",
    }
    if fault in sql:
        with sqlite3.connect(sidecar) as db:
            db.executescript(sql[fault])
    elif fault == "malformed":
        sidecar.write_bytes(b"not a database")
    elif fault == "truncated":
        sidecar.write_bytes(sidecar.read_bytes()[:8192])
    elif fault == "trailing":
        sidecar.write_bytes(sidecar.read_bytes() + b"unexpected trailing payload")
    elif fault == "oversize":
        sidecar.write_bytes(sidecar.read_bytes() + bytes(128 * 1024))
    elif fault == "many":
        for i in range(17):
            shutil.copyfile(sidecar, sidecar.with_name(f".coverage.host.pid{i}.Xabcdefx"))
    elif fault == "wrong-name":
        sidecar.rename(sidecar.with_name(".coverage.arbitrary"))
    elif fault == "wrong-path":
        sidecar.rename(directory / sidecar.name)
    elif fault == "noncoverage":
        sidecar.rename(sidecar.with_name("extra.sqlite"))
    elif fault == "symlink":
        body = sidecar.read_bytes()
        sidecar.unlink()
        target = tmp_path / "target"
        target.write_bytes(body)
        sidecar.symlink_to(target)
    elif fault == "tampered-hash":
        with sqlite3.connect(sidecar) as db:
            db.execute("UPDATE meta SET value='changed' WHERE key='sys_argv'")
    elif fault == "missing-raw":
        sidecar.with_name(".coverage").unlink()
    elif fault == "duplicate-raw":
        sidecar.write_bytes(sidecar.with_name(".coverage").read_bytes())
    if fault != "tampered-hash":
        reseal(directory)
    receipt = ENGINE.read(directory / "shard-receipt.json")
    if route == "receipt":
        with pytest.raises(ValueError):
            ENGINE.check_receipt(directory, receipt, data, "controller-coverage", root)
    else:
        result = invoke(
            root, "combine", "--plan", plan, "--results", results, "--output", tmp_path / "combined"
        )
        assert result.returncode != 0, fault
        assert not (tmp_path / "combined/aggregate-receipt.json").exists()


def test_plain_suite_rejects_real_empty_sidecar(tmp_path_factory, tmp_path):
    root, _, data, original = test_ci_shards_faults.executed.__wrapped__(tmp_path_factory)
    directory = tmp_path / "plain"
    shutil.copytree(original / "plain-0", directory)
    receipt = ENGINE.read(directory / "shard-receipt.json")
    db = CoverageData(basename=str(directory / receipt["invocation"] / ".coverage"), suffix=True)
    db.add_lines({})
    db.write()
    reseal(directory)
    with pytest.raises(ValueError, match="unexpected artifact set"):
        ENGINE.check_receipt(
            directory, ENGINE.read(directory / "shard-receipt.json"), data, "plain", root
        )
