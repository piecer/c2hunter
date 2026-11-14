"""Receipt fault controls start from successful real subprocess executions."""

import hashlib
import json
import shutil
import xml.etree.ElementTree as ET

import pytest
from test_ci_shards_engine import coverage_worlds, invoke, okay, plan, world


def save(path, value):
    path.write_text(json.dumps(value))


def reseal(directory):
    path = directory / "shard-receipt.json"
    receipt = json.loads(path.read_text())
    receipt["artifacts"] = {
        str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.rglob("*")
        if p.is_file() and p != path
    }
    save(path, receipt)


@pytest.fixture(scope="module")
def executed(tmp_path_factory):
    root = world(tmp_path_factory.mktemp("shard-receipts") / "source")
    path, data = plan(root)
    results = root / "artifacts/results"
    for i in range(2):
        okay(
            invoke(
                root,
                "run",
                "--plan",
                path,
                "--suite",
                "plain",
                "--shard",
                i,
                "--output",
                results / f"plain-{i}",
            )
        )
    return root, path, data, results


@pytest.mark.parametrize("fault", ["argv", "request", "extra-file", "junit-identity", "junit-dtd"])
def test_rejects_semantically_invalid_resealed_artifacts(executed, tmp_path, fault):
    root, plan_path, data, original = executed
    results = tmp_path / "downloaded"
    shutil.copytree(original, results)
    directory = results / "plain-0"
    if fault == "argv":
        path = next(directory.rglob("invocation.json"))
        value = json.loads(path.read_text())
        value["pytest_args"][0] = "-x"
        save(path, value)
    elif fault == "request":
        path = directory / "request.json"
        value = json.loads(path.read_text())
        value["files"] = []
        save(path, value)
    elif fault == "extra-file":
        (directory / "undeclared.db").write_bytes(b"not an allowed artifact")
    elif fault == "junit-dtd":
        path = next(directory.rglob("junit.xml"))
        body = path.read_text().split("?>", 1)[-1]
        path.write_text('<!DOCTYPE testsuites [<!ENTITY harmless "value">]>' + body)
    else:
        path = next(directory.rglob("junit.xml"))
        tree = ET.parse(path)
        tree.find(".//testcase").set("name", "not-the-executed-case")
        tree.write(path)
    reseal(directory)
    result = invoke(root, "verify", "--plan", plan_path, "--suite", "plain", "--results", results)
    assert result.returncode != 0, "semantic corruption accepted: " + fault


@pytest.mark.parametrize(
    "fault",
    [
        "missing-shard",
        "extra-shard",
        "duplicate-shard",
        "missing-receipt",
        "stale",
        "child-exit",
        "wrapper-exit",
        "cleanup",
        "cancelled",
        "finish",
        "zero-selection",
        "missing-start",
        "duplicate-case",
        "missing-teardown",
        "failed-report",
        "extra-case",
        "malformed-json",
        "schema",
        "symlink",
    ],
)
def test_incomplete_and_inconsistent_execution_is_rejected(executed, tmp_path, fault):
    root, plan_path, data, original = executed
    results = tmp_path / "downloaded"
    shutil.copytree(original, results)
    directory = results / "plain-0"
    receipt_path = directory / "shard-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    if fault == "missing-shard":
        shutil.rmtree(directory)
    elif fault == "extra-shard":
        shutil.copytree(directory, results / "third")
    elif fault == "duplicate-shard":
        shutil.rmtree(results / "plain-1")
        shutil.copytree(directory, results / "plain-1")
    elif fault == "missing-receipt":
        receipt_path.unlink()
    elif fault in ("stale", "child-exit", "wrapper-exit", "cleanup", "schema"):
        key, value = {
            "stale": ("plan_id", "old"),
            "child-exit": ("child_exit", 1),
            "wrapper-exit": ("wrapper_exit", 1),
            "cleanup": ("cleanup", "pending"),
            "schema": ("schema", 999),
        }[fault]
        receipt[key] = value
        save(receipt_path, receipt)
    elif fault == "cancelled":
        path = next(directory.rglob("invocation.json"))
        value = json.loads(path.read_text())
        value["signal"] = 15
        save(path, value)
        reseal(directory)
    elif fault == "finish":
        (directory / "finish.json").unlink()
        reseal(directory)
    elif fault == "zero-selection":
        path = directory / "selection.json"
        value = json.loads(path.read_text())
        value["inventory"] = []
        save(path, value)
        reseal(directory)
    elif fault == "malformed-json":
        receipt_path.write_text("{")
    elif fault == "symlink":
        path = directory / "selection.json"
        path.unlink()
        path.symlink_to(original / "plain-0/selection.json")
    else:
        path = next(directory.rglob("progress.jsonl"))
        events = [json.loads(s) for s in path.read_text().splitlines()]
        if fault == "missing-start":
            events.pop(0)
        elif fault == "duplicate-case":
            events.insert(1, events[0])
        elif fault == "missing-teardown":
            events = [e for e in events if e.get("phase") != "teardown"]
        elif fault == "failed-report":
            next(e for e in events if e.get("phase") == "call")["outcome"] = "failed"
        else:
            events.append(events[0])
        path.write_text("".join(json.dumps(e) + "\n" for e in events))
        reseal(directory)
    assert (
        invoke(
            root, "verify", "--plan", plan_path, "--suite", "plain", "--results", results
        ).returncode
        != 0
    )


@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "helper",
        "timings",
        "toolchain",
        "plan-hash",
        "partition",
        "integration",
        "head",
        "missing-plan",
    ],
)
def test_source_plan_and_toolchain_mismatches_fail(executed, tmp_path, fault):
    root, path, data, results = executed
    target = tmp_path / "source"
    shutil.copytree(root, target, ignore=shutil.ignore_patterns("artifacts", "__pycache__"))
    data = json.loads(path.read_text())
    plan_path = tmp_path / "plan.json"
    if fault in ("source", "helper", "timings"):
        name = {
            "source": "controller/tests/test_part0.py",
            "helper": "tools/ci_shard_plugin.py",
            "timings": "tools/ci_shard_timings.json",
        }[fault]
        with (target / name).open("a") as stream:
            stream.write("\n")
    elif fault == "toolchain":
        data["source"]["toolchain"]["pytest"] = "0.0"
    elif fault == "partition":
        data["suites"]["plain"]["shards"][0] = []
    elif fault == "integration":
        data["integration"]["inventory"].append({"nodeid": "not-a-case", "file": "absent.py"})
    elif fault == "head":
        data["source"]["head"] = "0" * 40
    if fault != "plan-hash":
        unsigned = {k: v for k, v in data.items() if k != "plan_id"}
        data["plan_id"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    else:
        data["plan_id"] = "0" * 64
    if fault != "missing-plan":
        save(plan_path, data)
    result = invoke(
        target,
        "verify",
        "--allow-dirty",
        "--plan",
        plan_path,
        "--suite",
        "plain",
        "--results",
        results,
    )
    assert result.returncode != 0


@pytest.fixture(scope="module")
def covered(tmp_path_factory):
    return coverage_worlds(tmp_path_factory.mktemp("coverage-receipts"))


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "extra",
        "corrupt",
        "unknown-path",
        "empty",
        "branch",
        "hash",
        "wrong-producer-root",
    ],
)
def test_rejects_invalid_raw_coverage(covered, tmp_path, fault):
    from coverage import CoverageData

    root, path, data, original = covered
    results = tmp_path / "downloaded"
    shutil.copytree(original, results)
    directory = results / "artifact-0"
    raw = next(directory.rglob(".coverage"))
    if fault == "missing":
        raw.unlink()
    elif fault == "extra":
        shutil.copyfile(raw, raw.parent / ".coverage.extra")
    elif fault in ("corrupt", "hash"):
        raw.write_bytes(b"corrupt database")
    elif fault == "wrong-producer-root":
        receipt_path = directory / "shard-receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["producer_root"] = str(tmp_path / "wrong")
        save(receipt_path, receipt)
    else:
        db = CoverageData(basename=str(raw))
        if fault == "unknown-path":
            db.read()
            db.add_lines({"/undeclared/controller.py": {1}})
        else:
            db.erase()
            if fault == "empty":
                db.add_lines({"/empty.py": set()})
            else:
                db.add_arcs({"/branch.py": {(1, 2)}})
        db.write()
    if fault != "hash":
        receipt_path = directory / "shard-receipt.json"
        receipt = json.loads(receipt_path.read_text())
        if raw.exists():
            receipt["raw_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
        save(receipt_path, receipt)
        reseal(directory)
    result = invoke(
        root, "combine", "--plan", path, "--results", results, "--output", tmp_path / "combined"
    )
    assert result.returncode != 0, fault


def test_coverage_has_no_receipt_only_public_success_path(covered):
    root, path, data, results = covered
    result = invoke(
        root, "verify", "--plan", path, "--suite", "controller-coverage", "--results", results
    )
    assert result.returncode != 0, "coverage must go through the 80-percent combine gate"


@pytest.mark.parametrize("fault", ["boolean-exit", "boolean-schema", "duplicate-key"])
def test_invalid_receipt_scalar_types_and_duplicate_keys_fail(executed, tmp_path, fault):
    root, plan_path, data, original = executed
    results = tmp_path / "downloaded"
    shutil.copytree(original, results)
    path = results / "plain-0/shard-receipt.json"
    receipt = json.loads(path.read_text())
    if fault == "boolean-exit":
        receipt["child_exit"] = False
        save(path, receipt)
    elif fault == "boolean-schema":
        receipt["schema"] = True
        save(path, receipt)
    else:
        path.write_text('{"child_exit":1,' + json.dumps(receipt)[1:])
    result = invoke(root, "verify", "--plan", plan_path, "--suite", "plain", "--results", results)
    assert result.returncode != 0, fault
