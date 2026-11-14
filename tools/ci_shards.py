"""Fail-closed full-collection CI sharding; no ambient pytest configuration."""

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import re
import shutil
import sqlite3
import stat
from contextlib import closing
import subprocess
import sys
from pathlib import Path

COUNTS = {"plain": 2, "controller-coverage": 4}
PLAIN = ["-q", "controller/tests", "analysis/tests"]
COVERAGE = [
    "-q",
    "controller/tests",
    "--cov=c2hunter_controller",
    "--cov-config=controller/pyproject.toml",
    "--cov-report=term",
    "--cov-fail-under=80",
]
COMMANDS = {"plain": PLAIN, "controller-coverage": COVERAGE}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def unique_object(pairs):
    value = dict(pairs)
    require(len(value) == len(pairs), "duplicate JSON key")
    return value


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def git(root, *args):
    executable = shutil.which("git")
    require(executable is not None, "git is required")
    return (
        subprocess.check_output(  # noqa: S603 -- fixed read-only Git subcommands, no shell.
            [executable, "-C", str(root), *args]
        )
        .decode()
        .strip()
    )


def binding(root, allow_dirty=False, extra=()):
    require(
        Path(git(root, "rev-parse", "--show-toplevel")).resolve() == root,
        "not repository root",
    )
    if not allow_dirty:
        require(
            not git(root, "status", "--porcelain", "--untracked-files=no"),
            "dirty source",
        )
    paths = set(git(root, "ls-files", "-z").split("\0")) - {""}
    owned = [
        *root.glob("tools/ci_shard*"),
        *root.glob("controller/tests/test_ci_shards*.py"),
    ]
    additions = {str(p.relative_to(root)) for p in owned if p.is_file()} | set(extra)
    require(allow_dirty or additions <= paths, "untracked source in hosted plan")
    paths.update(additions)
    files = {}
    for name in sorted(paths):
        path = root / name
        require(path.resolve().is_relative_to(root), "source escapes root")
        require(path.is_file(), "missing source: " + name)
        files[name] = digest(path)
    return {
        "head": git(root, "rev-parse", "HEAD"),
        "files": files,
        "digest": seal(files),
        "toolchain": {
            "python": sys.version,
            **{
                name: importlib.metadata.version(name)
                for name in ("pytest", "pytest-cov", "coverage")
            },
        },
    }


def partition(inventory, count, weights):
    files = {row["file"] for row in inventory}
    require(len(files) >= count, "zero selection shard")
    loads = [0.0] * count
    groups = [[] for _ in range(count)]
    for file in sorted(files, key=lambda file: (-weights.get(file, 1.0), file)):
        index = min(range(count), key=lambda index: (loads[index], index))
        groups[index].append(file)
        loads[index] += max(weights.get(file, 1.0), 0.000001)
    return groups


def measured_args(args):
    return ["--cov-fail-under=0" if a == "--cov-fail-under=80" else a for a in args]


def launch(root, args, output, request):
    output.mkdir(parents=True, exist_ok=False)
    request = {**request, "root": str(root), "output": str(output)}
    request_path = output / "request.json"
    write(request_path, request)
    import ci_pytest

    # Own the supervisor in this CLI process: cancellation must reach its handler,
    # not kill an unsupervised intermediate process and orphan the real pytest.
    command = [
        "--output-root",
        str(output / "diagnostics"),
        "--",
        *args,
        "-p",
        "ci_shard_plugin",
        f"--ci-shard-request={request_path}",
    ]
    code = ci_pytest.main(command)
    invocations = list((output / "diagnostics").glob("invocation-*"))
    require(len(invocations) == 1, "invocation cardinality")
    return code, invocations[0]


def collect(root, args, output):
    code, invocation = launch(
        root, [*measured_args(args), "--collect-only"], output, {"mode": "collect"}
    )
    require(code == 0, "collection failed")
    receipt = read(invocation / "invocation.json")
    require(
        receipt["child_exit"] == 0 and receipt["cleanup"] == "complete",
        "collection incomplete",
    )
    require(read(output / "finish.json")["exitstatus"] == 0, "collection unfinished")
    result = read(output / "selection.json")
    rows = result["inventory"]
    require(
        rows and len({row["nodeid"] for row in rows}) == len(rows),
        "empty/duplicate collection",
    )
    return {"argv": args, "inventory": rows, "identity": result["identity"]}


def plan(options, root):
    output = options.output.resolve()
    require(not output.exists(), "stale plan output")
    before = binding(root, options.allow_dirty)
    timing_path = root / "tools/ci_shard_timings.json"
    timings = read(timing_path)
    weights = timings["weights"]
    require(
        all(
            isinstance(v, (int, float)) and math.isfinite(v) and v >= 0
            for v in weights.values()
        ),
        "invalid timings",
    )
    diagnostics = output.parent / (output.stem + "-collection")
    diagnostics.mkdir(parents=True, exist_ok=False)
    suites = {}
    for name, argv in COMMANDS.items():
        suite = collect(root, argv, diagnostics / name)
        suite["shards"] = partition(suite["inventory"], COUNTS[name], weights)
        suites[name] = suite
    integration = collect(root, [*PLAIN, "-m", "not e2e"], diagnostics / "integration")
    require(
        {seal(row) for row in integration["inventory"]}
        <= {seal(row) for row in suites["plain"]["inventory"]},
        "integration is not a subset",
    )
    extra = sorted(
        {row["file"] for suite in suites.values() for row in suite["inventory"]}
    )
    after = binding(root, options.allow_dirty, extra)
    require(
        all(after["files"].get(k) == v for k, v in before["files"].items()),
        "source changed during plan",
    )
    data = {
        "schema": 1,
        "source": after,
        "extra_sources": extra,
        "timing_hash": digest(timing_path),
        "suites": suites,
        "integration": integration,
    }
    data["plan_id"] = seal(data)
    write(output, data)


def relocate(identity, root):
    old = Path(identity["cwd"])
    return {
        **identity,
        **{
            key: str(root / Path(identity[key]).relative_to(old))
            if identity[key]
            else None
            for key in ("cwd", "rootpath", "inipath")
        },
    }


def load_plan(options, root):
    data = read(options.plan.resolve())
    unsigned = {k: v for k, v in data.items() if k != "plan_id"}
    require(
        data["schema"] == 1 and data["plan_id"] == seal(unsigned), "invalid plan hash"
    )
    require(
        data["source"] == binding(root, options.allow_dirty, data["extra_sources"]),
        "source/toolchain mismatch",
    )
    require(
        data["timing_hash"] == digest(root / "tools/ci_shard_timings.json"),
        "timing mismatch",
    )
    require(set(data["suites"]) == set(COUNTS), "suite set mismatch")
    weights = read(root / "tools/ci_shard_timings.json")["weights"]
    for name, suite in data["suites"].items():
        require(suite["argv"] == COMMANDS[name], "canonical argv mismatch")
        rows = suite["inventory"]
        require(
            rows and len({r["nodeid"] for r in rows}) == len(rows),
            "duplicate/empty inventory",
        )
        require(
            suite["shards"] == partition(rows, COUNTS[name], weights),
            "partition mismatch",
        )
    require(
        data["integration"]["argv"] == [*PLAIN, "-m", "not e2e"], "integration argv"
    )
    require(
        {seal(r) for r in data["integration"]["inventory"]}
        <= {seal(r) for r in data["suites"]["plain"]["inventory"]},
        "integration subset",
    )
    return data


def artifacts(output):
    files = {}
    for path in sorted(output.rglob("*")):
        require(not path.is_symlink(), "symlink artifact")
        if path.is_file() and path != output / "shard-receipt.json":
            files[str(path.relative_to(output))] = digest(path)
    return files


def progress_check(path, expected):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    cursor = 0
    counts = {"passed": 0, "skipped": 0}
    for row in expected:
        nodeid = row["nodeid"]
        require(cursor < len(events), "missing START")
        start = events[cursor]
        require(
            start["event"] == "START" and start["nodeid"] == nodeid,
            "START order mismatch",
        )
        cursor += 1
        phases = {}
        order = []
        while cursor < len(events) and events[cursor]["event"] == "REPORT":
            event = events[cursor]
            require(
                event["nodeid"] == nodeid and event["phase"] not in phases,
                "duplicate report",
            )
            require(event["outcome"] in ("passed", "skipped"), "failed report")
            phases[event["phase"]] = event["outcome"]
            order.append(event["phase"])
            cursor += 1
        require(
            order
            == (
                ["setup", "teardown"]
                if phases.get("setup") == "skipped"
                else ["setup", "call", "teardown"]
            ),
            "incomplete report phases",
        )
        require(
            phases.get("teardown") in ("passed", "skipped"), "unsuccessful teardown"
        )
        require(cursor < len(events), "missing FINISH")
        finish = events[cursor]
        require(
            finish["event"] == "FINISH"
            and finish["nodeid"] == nodeid
            and finish["outcomes"] == phases,
            "FINISH mismatch",
        )
        cursor += 1
        counts["skipped" if "skipped" in phases.values() else "passed"] += 1
    require(cursor == len(events), "extra progress events")
    return counts


def empty_coverage_sidecar(path, version):
    """Recognize only bounded, canonical, empty parallel coverage databases.

    Never use CoverageData.read here: it can initialize/normalize databases.
    Inspect a bounded private memory snapshot, leaving every artifact byte intact.
    """
    from coverage.sqldata import SCHEMA, SCHEMA_VERSION

    require(SCHEMA_VERSION == 7, "unsupported empty coverage schema")
    require(
        re.fullmatch(
            r"\.coverage\.[A-Za-z0-9_-]{1,255}\.pid[0-9]{1,20}"
            r"\.X[A-Za-z0-9]{6}x(?:\.H[A-Za-z0-9]{10}h)?",
            path.name,
        ),
        "unexpected coverage sidecar name",
    )
    require(stat.S_ISREG(path.lstat().st_mode), "nonregular coverage sidecar")
    limit = 128 * 1024
    require(0 < path.stat().st_size <= limit, "coverage sidecar size")
    with path.open("rb") as stream:
        body = stream.read(limit + 1)
    require(0 < len(body) <= limit, "coverage sidecar size")
    schema_query = "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name"
    try:
        with closing(sqlite3.connect(":memory:")) as reference:
            reference.executescript(SCHEMA)
            schema = reference.execute(schema_query).fetchall()
        with closing(sqlite3.connect(":memory:")) as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, limit)
            db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, limit)
            db.deserialize(body)
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.set_progress_handler(lambda: 1, 100000)
            require(
                db.execute("PRAGMA page_count").fetchone()[0]
                * db.execute("PRAGMA page_size").fetchone()[0]
                == len(body),
                "coverage sidecar physical size",
            )
            require(
                db.execute(schema_query).fetchall() == schema, "coverage sidecar schema"
            )
            require(
                db.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                "coverage sidecar integrity",
            )
            require(
                db.execute("SELECT * FROM coverage_schema").fetchall() == [(7,)],
                "coverage sidecar schema version",
            )
            rows = db.execute("SELECT key, value FROM meta").fetchall()
            meta = dict(rows)
            require(
                len(meta) == len(rows)
                and set(meta) <= {"version", "has_arcs", "sys_argv", "when", "hash"}
                and meta.get("version") == version
                and meta.get("has_arcs") == "0"
                and all(isinstance(v, str) for v in meta.values()),
                "coverage sidecar metadata",
            )
            for table in ("file", "context", "line_bits", "arc", "tracer"):
                require(
                    db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is None,  # noqa: S608 -- fixed table allowlist.
                    "nonempty coverage sidecar",
                )
    except sqlite3.Error as error:
        raise ValueError("invalid coverage sidecar database") from error


def check_receipt(output, receipt, data, suite_name, root):
    require(
        all(
            type(receipt[key]) is int
            for key in ("schema", "shard", "child_exit", "wrapper_exit", "engine_exit")
        ),
        "invalid receipt scalar type",
    )
    suite = data["suites"][suite_name]
    index = receipt["shard"]
    require(type(index) is int and 0 <= index < COUNTS[suite_name], "shard index")
    require(
        receipt["schema"] == 1 and receipt["suite"] == suite_name,
        "receipt schema/suite",
    )
    require(
        receipt["plan_id"] == data["plan_id"] and receipt["source"] == data["source"],
        "stale receipt",
    )
    require(
        receipt["engine_exit"] == 0 and receipt["source_after"] == data["source"],
        "incomplete engine/source finalization",
    )
    require(
        receipt["child_exit"] == 0
        and receipt["wrapper_exit"] == 0
        and receipt["cleanup"] == "complete",
        "unsuccessful invocation",
    )
    invocation = output / receipt["invocation"]
    require(invocation.resolve().is_relative_to(output.resolve()), "invocation escape")
    actual = read(invocation / "invocation.json")
    original_output = Path(receipt["producer_output"])
    original_invocation = original_output / receipt["invocation"]
    producer_root = Path(receipt["producer_root"])
    require(
        original_output.is_absolute() and producer_root.is_absolute(),
        "relative producer path",
    )
    request = {
        "mode": "run",
        "root": str(producer_root),
        "output": str(original_output),
        "inventory": suite["inventory"],
        "identity": relocate(suite["identity"], producer_root),
        "files": suite["shards"][index],
    }
    require(read(output / "request.json") == request, "request binding mismatch")
    expected_args = [
        *measured_args(suite["argv"]),
        "-p",
        "ci_shard_plugin",
        f"--ci-shard-request={original_output / 'request.json'}",
        "-p",
        "ci_pytest",
        f"--ci-progress={original_invocation / 'progress.jsonl'}",
        f"--junitxml={original_invocation / 'junit.xml'}",
        "--durations=50",
    ]
    names = {"request.json", "selection.json", "finish.json"}
    diagnostic_names = {"invocation.json", "pytest.log", "progress.jsonl", "junit.xml"}
    if suite_name == "controller-coverage":
        expected_args.extend(
            [
                f"--ci-coverage-file={original_invocation / '.coverage'}",
                f"--cov-report=xml:{original_invocation / 'coverage.xml'}",
            ]
        )
        diagnostic_names.update({".coverage", "coverage.xml"})
    names.update(str(Path(receipt["invocation"]) / name) for name in diagnostic_names)
    sidecars = set(receipt["artifacts"]) - names
    if suite_name == "controller-coverage":
        require(len(sidecars) <= 16, "coverage sidecar cardinality")
        for name in sorted(sidecars):
            path = Path(name)
            require(
                path.parent == Path(receipt["invocation"])
                and str(path) == name
                and not path.is_absolute(),
                "unexpected coverage sidecar path",
            )
            empty_coverage_sidecar(
                output / path, data["source"]["toolchain"]["coverage"]
            )
        names.update(sidecars)
    require(set(receipt["artifacts"]) == names, "unexpected artifact set")
    require(receipt["artifacts"] == artifacts(output), "artifact set/hash mismatch")
    require(actual["pytest_args"] == expected_args, "actual argv mismatch")
    require(
        actual["child_exit"] == 0
        and actual["exit"] == 0
        and actual["signal"] is None
        and actual["cleanup"] == "complete",
        "original invocation failure",
    )
    require(
        read(output / "finish.json")["exitstatus"] == 0, "missing successful finish"
    )
    selected = read(output / "selection.json")
    expected = [r for r in suite["inventory"] if r["file"] in suite["shards"][index]]
    require(
        expected
        and selected["inventory"] == expected
        and selected["full"] == suite["inventory"],
        "selection mismatch",
    )
    require(
        selected["identity"]
        == relocate(suite["identity"], Path(receipt["producer_root"])),
        "collection identity mismatch",
    )
    counts = progress_check(invocation / "progress.jsonl", expected)
    import xml.etree.ElementTree as ET

    xml = (invocation / "junit.xml").read_text(encoding="utf-8")
    require(
        "\x00" not in xml and "<!DOCTYPE" not in xml and "<!ENTITY" not in xml,
        "JUnit DTD/entities/alternate encodings forbidden",
    )
    cases = ET.fromstring(xml).findall(".//testcase")  # noqa: S314 -- UTF-8 only; no DTD/entities.
    require(
        len(cases) == len(expected)
        and not any(
            c.find("failure") is not None or c.find("error") is not None for c in cases
        ),
        "JUnit mismatch",
    )
    from _pytest.junitxml import bin_xml_escape, mangle_test_address

    expected_cases = []
    for row in expected:
        names = mangle_test_address(row["nodeid"])
        expected_cases.append((".".join(names[:-1]), bin_xml_escape(names[-1])))
    require(
        [(c.get("classname"), c.get("name")) for c in cases] == expected_cases,
        "JUnit case identities mismatch",
    )
    require(
        sum(c.find("skipped") is not None for c in cases) == counts["skipped"],
        "JUnit skips",
    )
    raw = [
        p
        for p in output.rglob(".coverage*")
        if str(p.relative_to(output)) not in sidecars
    ]
    if suite_name == "controller-coverage":
        require(raw == [invocation / ".coverage"], "raw coverage cardinality")
        require(receipt["raw_sha256"] == digest(raw[0]), "raw coverage hash")
    else:
        require(not raw and receipt["raw_sha256"] is None, "unexpected raw coverage")
    return counts


def run(options, root):
    data = load_plan(options, root)
    suite = data["suites"][options.suite]
    require(0 <= options.shard < COUNTS[options.suite], "invalid shard")
    output = options.output.resolve()
    code, invocation = launch(
        root,
        measured_args(suite["argv"]),
        output,
        {
            "mode": "run",
            "inventory": suite["inventory"],
            "identity": relocate(suite["identity"], root),
            "files": suite["shards"][options.shard],
        },
    )
    actual = read(invocation / "invocation.json")
    raw = invocation / ".coverage"
    receipt = {
        "schema": 1,
        "plan_id": data["plan_id"],
        "suite": options.suite,
        "shard": options.shard,
        "source": data["source"],
        "producer_root": str(root),
        "producer_output": str(output),
        "child_exit": actual["child_exit"],
        "wrapper_exit": code,
        "cleanup": actual["cleanup"],
        "invocation": str(invocation.relative_to(output)),
        "raw_sha256": digest(raw) if raw.is_file() else None,
        "artifacts": artifacts(output),
    }
    receipt["engine_exit"] = 1
    receipt["source_after"] = None
    write(output / "shard-receipt.json", receipt)
    try:
        receipt["source_after"] = binding(root, True, data["extra_sources"])
        require(
            receipt["source_after"] == data["source"], "source changed during execution"
        )
        # Validate the exact prospective successful receipt before publication.
        receipt["engine_exit"] = 0
        check_receipt(output, receipt, data, options.suite, root)
    except Exception:
        receipt["engine_exit"] = 1
        raise
    finally:
        write(output / "shard-receipt.json", receipt)


def verify(options, root, suite_name=None):
    data = load_plan(options, root)
    suite_name = suite_name or options.suite
    results = options.results.resolve()
    children = list(results.iterdir())
    require(
        len(children) == COUNTS[suite_name]
        and all(p.is_dir() and not p.is_symlink() for p in children),
        "artifact cardinality",
    )
    receipts = []
    for output in children:
        require(
            len(list(output.rglob("shard-receipt.json"))) == 1, "receipt cardinality"
        )
        receipt = read(output / "shard-receipt.json")
        check_receipt(output, receipt, data, suite_name, root)
        receipts.append((output, receipt))
    require(
        sorted(r["shard"] for _, r in receipts) == list(range(COUNTS[suite_name])),
        "duplicate/missing shard",
    )
    return data, receipts


def combine(options, root):
    import fnmatch

    from coverage import Coverage, CoverageData

    data, receipts = verify(options, root, "controller-coverage")
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    package = root / "controller/src/c2hunter_controller"
    cov = Coverage(
        data_file=str(output / ".coverage"),
        config_file=str(root / "controller/pyproject.toml"),
        source=[str(package)],
    )
    require(not cov.get_option("run:branch"), "unexpected branch configuration")
    require(not cov.get_option("report:ignore_errors"), "ignore-errors forbidden")
    omit = cov.get_option("run:omit") or []
    universe = {
        str(p.resolve())
        for p in package.rglob("*.py")
        if not any(fnmatch.fnmatch(str(p), pattern) for pattern in omit)
    }
    require(universe, "empty coverage source universe")
    require(
        all(
            str(Path(p).relative_to(root)) in data["source"]["files"] for p in universe
        ),
        "unbound coverage source",
    )
    merged = cov.get_data()
    for directory, receipt in receipts:
        raw = directory / receipt["invocation"] / ".coverage"
        database = CoverageData(basename=str(raw))
        database.read()
        require(not database.has_arcs(), "unexpected branch data")
        files = database.measured_files()
        require(
            files and any(database.lines(f) for f in files), "empty raw coverage data"
        )
        producer = Path(receipt["producer_root"])
        mappings = {}
        for filename in files:
            original = Path(filename)
            require(
                original.is_absolute() and original.is_relative_to(producer),
                "unknown raw coverage path",
            )
            target = str(root / original.relative_to(producer))
            require(target in universe, "unknown/omitted raw source")
            require(not database.file_tracer(filename), "unexpected coverage tracer")
            mappings[filename] = target
        merged.update(database, map_path=lambda filename: mappings[filename])
    merged.touch_files(sorted(universe))
    cov.save()
    percent = cov.json_report(outfile=str(output / "coverage.json"))
    cov.xml_report(outfile=str(output / "coverage.xml"))
    cov.report()
    # The original raw inputs remain immutable; a partial union never certifies a gate.
    verify(options, root, "controller-coverage")
    write(
        output / "aggregate-receipt.json",
        {
            "schema": 1,
            "plan_id": data["plan_id"],
            "source": data["source"],
            "raw_sha256": {str(r["shard"]): r["raw_sha256"] for _, r in receipts},
            "coverage_source": "c2hunter_controller",
            "source_root": str(package),
            "omit": omit,
            "percent": percent,
            "floor": 80,
            "passed": percent >= 80,
        },
    )
    require(percent >= 80, "Controller coverage below 80")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("plan")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument(
        "--allow-dirty", action="store_true", help="Explicit development snapshot only"
    )
    for name in ("run", "verify"):
        p = commands.add_parser(name)
        p.add_argument("--plan", type=Path, required=True)
        p.add_argument(
            "--suite", choices=COUNTS if name == "run" else ("plain",), required=True
        )
        p.add_argument("--allow-dirty", action="store_true")
        if name == "run":
            p.add_argument("--shard", type=int, required=True)
            p.add_argument("--output", type=Path, required=True)
        else:
            p.add_argument("--results", type=Path, required=True)
    p = commands.add_parser("combine")
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--results", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--allow-dirty", action="store_true")
    options = parser.parse_args()
    try:
        require(
            not any(
                os.environ.get(k)
                for k in (
                    "PYTEST_ADDOPTS",
                    "PYTEST_PLUGINS",
                    "PYTHONPATH",
                    "COVERAGE_FILE",
                )
            ),
            "ambient pytest/coverage configuration",
        )
        {"plan": plan, "run": run, "verify": verify, "combine": combine}[
            options.command
        ](options, Path.cwd().resolve())
        return 0
    except Exception as error:
        print(f"ci-shards: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
