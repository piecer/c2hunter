"""Real, short pytest children exercise the CI-only evidence launcher."""

import json
import os
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "tools/ci_pytest.py"


def command(work: Path, *args: str) -> list[str]:
    return [
        sys.executable,
        "-B",
        str(LAUNCHER),
        "--output-root",
        str(work / "evidence"),
        "--",
        "-q",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        *args,
    ]


def clean_env() -> dict[str, str]:
    # Do not forward outer pytest-cov's child instrumentation into fixture worlds.
    return {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "COVERAGE_FILE")
        and not key.startswith("COV_CORE_")
    } | {"PYTHONDONTWRITEBYTECODE": "1", "CI_TEST_SECRET": "secret-sentinel-not-a-credential"}


def launch(work: Path, *args: str) -> subprocess.CompletedProcess:
    assert LAUNCHER.is_file(), "Missing CI-only pytest launcher"
    return subprocess.run(
        command(work, *args),
        cwd=work,
        env=clean_env(),
        capture_output=True,
        text=True,
        timeout=30,
    )


def invocation(work: Path) -> Path:
    dirs = list((work / "evidence").iterdir())
    assert len(dirs) == 1
    return dirs[0]


@pytest.mark.parametrize(
    ("body", "exit_code", "outcome"),
    [
        ("def test_case():\n    assert True\n", 0, "passed"),
        ("def test_case():\n    assert False\n", 1, "failure"),
        (
            "import pytest\n@pytest.fixture\ndef broken():\n    raise RuntimeError('setup')\n"
            "def test_case(broken):\n    pass\n",
            1,
            "error",
        ),
        ("import pytest\ndef test_case():\n    pytest.skip('fixture control')\n", 0, "skipped"),
    ],
)
def test_launcher_preserves_exit_and_records_junit_and_durations(
    tmp_path: Path,
    body: str,
    exit_code: int,
    outcome: str,
) -> None:
    (tmp_path / "test_case.py").write_text(body)
    result = launch(tmp_path, "test_case.py")
    assert result.returncode == exit_code, result.stdout + result.stderr
    evidence = invocation(tmp_path)
    report = ET.parse(evidence / "junit.xml")
    cases = report.findall(".//testcase")
    assert len(cases) == 1
    assert cases[0].get("name") == "test_case"
    if outcome == "passed":
        assert not list(cases[0])
    else:
        assert cases[0].find(outcome) is not None
    receipt = json.loads((evidence / "invocation.json").read_text())
    assert receipt["child_exit"] == exit_code
    assert receipt["exit"] == exit_code
    assert "--durations=50" in receipt["pytest_args"]
    assert "slowest" in (evidence / "pytest.log").read_text()
    events = progress(tmp_path)
    assert [row["event"] for row in events].count("START") == 1
    assert [row["event"] for row in events].count("FINISH") == 1
    phases = events[-1]["outcomes"]
    if outcome == "error":
        assert phases == {"setup": "failed", "teardown": "passed"}
    else:
        assert (
            phases["call"]
            == {"failure": "failed", "skipped": "skipped", "passed": "passed"}[outcome]
        )
    for path in evidence.iterdir():
        if path.is_file():
            assert b"secret-sentinel-not-a-credential" not in path.read_bytes()


def test_repeated_top_level_invocations_never_overwrite(tmp_path: Path) -> None:
    (tmp_path / "test_case.py").write_text("def test_case():\n    pass\n")
    first = launch(tmp_path, "test_case.py")
    assert first.returncode == 0
    first_dir = invocation(tmp_path)
    before = {p.name: p.read_bytes() for p in first_dir.iterdir() if p.is_file()}
    second = launch(tmp_path, "test_case.py")
    assert second.returncode == 0
    assert len(list((tmp_path / "evidence").iterdir())) == 2
    assert {p.name: p.read_bytes() for p in first_dir.iterdir() if p.is_file()} == before


def test_usage_error_preserves_real_pytest_exit(tmp_path: Path) -> None:
    result = launch(tmp_path, "--not-a-pytest-option")
    assert result.returncode == 4
    receipt = json.loads((invocation(tmp_path) / "invocation.json").read_text())
    assert receipt["child_exit"] == receipt["exit"] == 4


def wait_for(predicate, *, timeout: float = 10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError("Fixture observation deadline expired")


@contextmanager
def running(work: Path, *args: str, argv: list[str] | None = None):
    assert LAUNCHER.is_file()
    # Protection begins immediately after spawn, including failed readiness checks.
    process = subprocess.Popen(
        command(work, *args) if argv is None else argv,
        cwd=work,
        env=clean_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        yield process
    finally:
        # Unblock fixture bodies even if the observation assertion fails.
        (work / "release").touch()
        if process.poll() is None:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        process.stdout.close()
        identity = work / "case-identity"
        if identity.exists():
            pid, start = identity.read_text().split()
            if live_identity(int(pid)) == start:
                os.kill(int(pid), signal.SIGKILL)
                wait_for(lambda: live_identity(int(pid)) is None)


def progress(work: Path) -> list[dict]:
    paths = list((work / "evidence").glob("*/progress.jsonl"))
    if not paths:
        return []
    return [json.loads(line) for line in paths[0].read_text().splitlines()]


def test_progress_is_flushed_before_case_finishes_and_nested_pytest_is_clean(
    tmp_path: Path,
) -> None:
    (tmp_path / "nested_case.py").write_text(
        "import os\ndef test_nested(pytestconfig):\n"
        "    assert not pytestconfig.pluginmanager.hasplugin('ci_pytest')\n"
        "    assert 'PYTEST_ADDOPTS' not in os.environ\n"
        "    assert 'PYTEST_PLUGINS' not in os.environ\n"
    )
    (tmp_path / "test_case.py").write_text(
        "import subprocess, sys, time\nfrom pathlib import Path\n"
        "def test_case():\n"
        "    Path('entered').touch()\n"
        "    deadline = time.monotonic() + 15\n"
        "    while not Path('release').exists():\n"
        "        assert time.monotonic() < deadline\n"
        "        time.sleep(0.02)\n"
        "    subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',\n"
        "                    'nested_case.py'], check=True, timeout=10)\n"
    )
    with running(tmp_path, "test_case.py") as process:
        wait_for(lambda: (tmp_path / "entered").exists())
        events = progress(tmp_path)
        assert any(
            row["event"] == "START" and row["nodeid"].endswith("::test_case") for row in events
        )
        assert not any(row["event"] == "FINISH" for row in events)
        assert process.poll() is None
        (tmp_path / "release").touch()
        output, _ = process.communicate(timeout=20)
        assert process.returncode == 0, output
    events = progress(tmp_path)
    assert [row["event"] for row in events].count("START") == 1
    assert [row["event"] for row in events].count("FINISH") == 1
    assert events[-1]["outcomes"] == {"setup": "passed", "call": "passed", "teardown": "passed"}
    assert not any("test_nested" in row["nodeid"] for row in events)
    receipt = json.loads((invocation(tmp_path) / "invocation.json").read_text())
    assert "-p" in receipt["pytest_args"] and "ci_pytest" in receipt["pytest_args"]


@pytest.mark.parametrize("complete", [True, False])
def test_coverage_raw_xml_and_original_floor_are_preserved(tmp_path: Path, complete: bool) -> None:
    (tmp_path / "sample.py").write_text(
        "def exercised():\n    return 1\ndef missed():\n    return 2\n"
    )
    (tmp_path / "test_case.py").write_text(
        "import sample\ndef test_case():\n    assert sample.exercised() == 1\n"
        + ("    assert sample.missed() == 2\n" if complete else "")
    )
    args = ["test_case.py", "--cov=sample", "--cov-report=term", "--cov-fail-under=80"]
    plain = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", *args],
        cwd=tmp_path,
        env=clean_env(),
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert plain.returncode == (0 if complete else 1), plain.stdout + plain.stderr
    raw_before = (tmp_path / ".coverage").read_bytes()
    result = launch(tmp_path, *args)
    assert result.returncode == plain.returncode, result.stdout + result.stderr
    evidence = invocation(tmp_path)
    assert (evidence / ".coverage").is_file(), "Keep unique raw coverage, not just a percentage"
    assert (evidence / ".coverage").read_bytes().startswith(b"SQLite format 3")
    assert (tmp_path / ".coverage").read_bytes() == raw_before
    xml = ET.parse(evidence / "coverage.xml")
    sample = next(node for node in xml.findall(".//class") if node.get("filename") == "sample.py")
    assert float(sample.get("line-rate")) == (1.0 if complete else 0.75)
    receipt = json.loads((evidence / "invocation.json").read_text())
    assert "--cov-fail-under=80" in receipt["pytest_args"]
    assert "--cov-report=term" in receipt["pytest_args"]
    assert receipt["child_exit"] == plain.returncode


def live_identity(pid: int) -> str | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
    except FileNotFoundError:
        return None
    return fields[19] if fields[0] != "Z" else None


@contextmanager
def orphan_fixture(work: Path):
    # The fixture also owns cleanup if its observation or the launcher fails.
    (work / "orphan.py").write_text(
        "import os, signal, time\nfrom pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "pid = os.getpid()\n"
        "start = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[19]\n"
        "Path('orphan-identity').write_text(f'{pid} {start}')\n"
        "time.sleep(20)\n"
    )
    try:
        yield
    finally:
        identity = work / "orphan-identity"
        if identity.exists():
            pid, start = identity.read_text().split()
            if live_identity(int(pid)) == start:
                os.kill(int(pid), signal.SIGKILL)
                wait_for(lambda: live_identity(int(pid)) is None)


@pytest.mark.parametrize("fail", [False, True])
def test_launcher_retires_owned_descendants_on_normal_exit(tmp_path: Path, fail: bool) -> None:
    (tmp_path / "test_case.py").write_text(
        "import subprocess, sys, time\nfrom pathlib import Path\n"
        "def test_case():\n"
        "    subprocess.Popen([sys.executable, 'orphan.py'])\n"
        "    deadline = time.monotonic() + 10\n"
        "    while not Path('orphan-identity').exists():\n"
        "        assert time.monotonic() < deadline\n"
        "        time.sleep(0.02)\n"
        f"    assert {not fail}\n"
    )
    with orphan_fixture(tmp_path):
        result = launch(tmp_path, "test_case.py")
        assert result.returncode == int(fail), result.stdout + result.stderr
        pid, start = (tmp_path / "orphan-identity").read_text().split()
        assert live_identity(int(pid)) != start, "Launcher left an owned descendant running"
        receipt = json.loads((invocation(tmp_path) / "invocation.json").read_text())
        assert receipt["cleanup"] == "complete"
        assert receipt["child_exit"] == int(fail)


@pytest.mark.parametrize("graceful_zero", [False, True])
def test_signal_is_latched_and_child_is_cleaned_even_if_it_exits_zero(
    tmp_path: Path,
    graceful_zero: bool,
) -> None:
    (tmp_path / "test_case.py").write_text(
        "import os, signal, time\nfrom pathlib import Path\n"
        "def test_case():\n"
        + (
            "    signal.signal(signal.SIGTERM, lambda *args: os._exit(0))\n"
            if graceful_zero
            else ""
        )
        + "    pid = os.getpid()\n"
        "    start = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[19]\n"
        "    Path('case-identity').write_text(f'{pid} {start}')\n"
        "    Path('entered').touch()\n"
        "    deadline = time.monotonic() + 15\n"
        "    while not Path('release').exists():\n"
        "        assert time.monotonic() < deadline\n"
        "        time.sleep(0.02)\n"
    )
    with running(tmp_path, "test_case.py") as process:
        wait_for(lambda: (tmp_path / "entered").exists())
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=10)
        assert process.returncode == 128 + signal.SIGTERM, output
    receipt = json.loads((invocation(tmp_path) / "invocation.json").read_text())
    assert receipt["signal"] == signal.SIGTERM
    assert receipt["child_exit"] == (0 if graceful_zero else -signal.SIGTERM)
    assert receipt["exit"] == 128 + signal.SIGTERM
    assert receipt["cleanup"] == "complete"
    assert live_identity(receipt["child_pid"]) is None
    assert any(row["event"] == "START" for row in progress(tmp_path))
    assert not any(row["event"] == "FINISH" for row in progress(tmp_path))


def test_child_signal_exit_is_not_reinterpreted_as_success(tmp_path: Path) -> None:
    (tmp_path / "test_case.py").write_text(
        "import os, signal\ndef test_case():\n    os.kill(os.getpid(), signal.SIGTERM)\n"
    )
    result = launch(tmp_path, "test_case.py")
    assert result.returncode == 128 + signal.SIGTERM
    receipt = json.loads((invocation(tmp_path) / "invocation.json").read_text())
    assert receipt["child_exit"] == -signal.SIGTERM
    assert receipt["signal"] is None


@pytest.mark.parametrize("fault", ["spawn", "relay", "receipt"])
def test_supervisor_failure_is_nonzero_and_retires_only_owned_children(
    tmp_path: Path, fault: str
) -> None:
    (tmp_path / "test_case.py").write_text(
        "import os, signal, time\nfrom pathlib import Path\n"
        "def test_case():\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "    pid = os.getpid()\n"
        "    start = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[19]\n"
        "    Path('case-identity').write_text(f'{pid} {start}')\n"
        "    Path('entered').touch()\n"
        "    time.sleep(15)\n"
    )
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import json, sys, time\nfrom pathlib import Path\n"
        f"sys.path.insert(0, {str(LAUNCHER.parent)!r})\n"
        "import ci_pytest as launcher\n"
        f"sys.argv = {command(tmp_path, 'test_case.py')[2:]!r}\n"
        f"fault = {fault!r}\n"
        "def fail_spawn(*args, **kwargs):\n"
        "    raise FileNotFoundError('synthetic-spawn-failure')\n"
        "original_relay = launcher.relay\n"
        "def fail_relay(source):\n"
        "    if Path('entered').exists():\n"
        "        raise OSError('synthetic-observer-failure')\n"
        "    original_relay(source)\n"
        "original_write = Path.write_text\n"
        "fired = False\n"
        "def fail_receipt(path, text, *args, **kwargs):\n"
        "    global fired\n"
        "    if path.name == 'invocation.json' and json.loads(text)['child_pid'] and not fired:\n"
        "        fired = True\n"
        "        deadline = time.monotonic() + 10\n"
        "        while not Path('entered').exists():\n"
        "            assert time.monotonic() < deadline\n"
        "            time.sleep(0.02)\n"
        "        raise OSError('synthetic-receipt-failure')\n"
        "    return original_write(path, text, *args, **kwargs)\n"
        "if fault == 'spawn':\n"
        "    launcher.subprocess.Popen = fail_spawn\n"
        "elif fault == 'relay':\n"
        "    launcher.relay = fail_relay\n"
        "else:\n"
        "    Path.write_text = fail_receipt\n"
        "raise SystemExit(launcher.main())\n"
    )
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], env=clean_env()
    )
    try:
        with running(tmp_path, argv=[sys.executable, "-B", str(probe)]) as process:
            output, _ = process.communicate(timeout=20)
            assert process.returncode == 125, output
            assert unrelated.poll() is None
            receipt = json.loads((invocation(tmp_path) / "invocation.json").read_text())
            assert receipt["exit"] == 125
            if fault == "spawn":
                assert receipt["child_exit"] is None
                assert receipt["child_pid"] is None
                assert receipt["cleanup"] == "not-started"
                assert receipt["error"] == "FileNotFoundError"
            else:
                assert receipt["child_exit"] == -signal.SIGKILL
                assert receipt["cleanup"] == "complete"
                assert receipt["error"] == "OSError"
                assert live_identity(receipt["child_pid"]) is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_coverage_destination_does_not_override_nested_explicit_coverage(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "inner.py").write_text("VALUE = 42\n")
    (nested / "test_inner.py").write_text(
        "import inner\ndef test_inner():\n    assert inner.VALUE == 42\n"
    )
    (tmp_path / "sample.py").write_text("VALUE = 17\n")
    (tmp_path / "test_case.py").write_text(
        "import os, subprocess, sys\nfrom pathlib import Path\nimport sample\n"
        "def test_case():\n"
        "    assert sample.VALUE == 17\n"
        "    assert 'COVERAGE_FILE' not in set(os.environ)\n"
        "    subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',\n"
        "                    '--cov=inner', '--cov-report=term', '--cov-fail-under=100'],\n"
        "                   cwd='nested', check=True, timeout=10)\n"
        "    assert Path('nested/.coverage').is_file()\n"
    )
    result = launch(
        tmp_path, "test_case.py", "--cov=sample", "--cov-report=term", "--cov-fail-under=100"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = ET.parse(invocation(tmp_path) / "coverage.xml")
    names = {node.get("filename") for node in report.findall(".//class")}
    assert names == {"sample.py"}


@pytest.mark.parametrize("fail", [False, True])
def test_progress_is_independent_of_test_json_dumps_instrumentation(
    tmp_path: Path, fail: bool
) -> None:
    (tmp_path / "test_case.py").write_text(
        "import json, pytest\n"
        "def test_case(monkeypatch):\n"
        "    original = json.dumps\n"
        "    def bounded(value, *args, **kwargs):\n"
        "        assert not isinstance(value, (dict, list)), 'subject-serialization-guard'\n"
        "        return original(value, *args, **kwargs)\n"
        "    monkeypatch.setattr(json, 'dumps', bounded)\n"
        "    assert json.dumps(1) == '1'\n"
        "    with pytest.raises(AssertionError, match='subject-serialization-guard'):\n"
        "        json.dumps({})\n"
        f"    assert {not fail!r}, 'original-test-failure'\n"
    )
    result = launch(tmp_path, "test_case.py")
    assert result.returncode == (1 if fail else 0), result.stdout + result.stderr
    evidence = invocation(tmp_path)
    cases = ET.parse(evidence / "junit.xml").findall(".//testcase")
    assert len(cases) == 1 and cases[0].get("name") == "test_case"
    assert cases[0].find("error") is None
    if fail:
        failure = cases[0].find("failure")
        assert failure is not None
        assert "original-test-failure" in failure.get("message", "")
    else:
        assert cases[0].find("failure") is None
    events = [json.loads(line) for line in (evidence / "progress.jsonl").read_text().splitlines()]
    assert [event["event"] for event in events] == [
        "START",
        "REPORT",
        "REPORT",
        "REPORT",
        "FINISH",
    ]
    assert events[-1]["outcomes"] == {
        "setup": "passed",
        "call": "failed" if fail else "passed",
        "teardown": "passed",
    }
