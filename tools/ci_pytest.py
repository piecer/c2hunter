"""CI-only pytest evidence; ordinary local Make targets still use pytest directly."""

import argparse
import ctypes
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--ci-progress", help="Invocation-owned append-only progress log")
    parser.addoption(
        "--ci-coverage-file", help="Invocation-owned raw coverage database"
    )


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_load_initial_conftests(early_config):
    # pytest-cov initializes its collector here. Scope this output-only override
    # to initialization, so nested explicit coverage keeps its own destination.
    destination = early_config.known_args_namespace.ci_coverage_file
    previous = os.environ.get("COVERAGE_FILE")
    if destination:
        os.environ["COVERAGE_FILE"] = destination
    try:
        return (yield)
    finally:
        if destination:
            if previous is None:
                os.environ.pop("COVERAGE_FILE", None)
            else:
                os.environ["COVERAGE_FILE"] = previous


def pytest_configure(config):
    path = config.getoption("--ci-progress")
    if path:
        config.pluginmanager.register(Progress(Path(path)), "ci-progress-writer")


class Progress:
    """Flush each event immediately; a killed test retains its last START."""

    def __init__(self, path: Path):
        self.stream = path.open("a", encoding="utf-8")
        self.outcomes = {}
        # Test fixtures can instrument shared json.dumps until teardown. Keep
        # observation independent without undoing their application-side guard.
        self.encode = json.JSONEncoder().encode

    def write(self, event: str, nodeid: str, **details):
        self.stream.write(
            self.encode(
                {
                    "event": event,
                    "nodeid": nodeid,
                    "time": time.time(),
                    **details,
                }
            )
            + "\n"
        )
        self.stream.flush()

    def pytest_runtest_logstart(self, nodeid, location):
        self.outcomes[nodeid] = {}
        self.write("START", nodeid)

    def pytest_runtest_logreport(self, report):
        self.outcomes.setdefault(report.nodeid, {})[report.when] = report.outcome
        self.write(
            "REPORT",
            report.nodeid,
            phase=report.when,
            outcome=report.outcome,
            duration=report.duration,
        )

    def pytest_runtest_logfinish(self, nodeid, location):
        self.write("FINISH", nodeid, outcomes=self.outcomes.pop(nodeid, {}))

    def pytest_unconfigure(self):
        self.stream.close()


def signal_group(child, signum: int) -> bool:
    try:
        os.killpg(child.pid, signum)
    except ProcessLookupError:
        return False
    return True


def retire_group(child) -> None:
    """Only signal/reap the session created by this invocation."""
    signal_group(child, signal.SIGTERM)
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        signal_group(child, signal.SIGKILL)
        child.wait(timeout=2)
    # A successful pytest may still have left a grandchild holding resources.
    signal_group(child, signal.SIGKILL)
    deadline = time.monotonic() + 2
    while True:
        try:
            while os.waitpid(-child.pid, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        if not signal_group(child, 0):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned process group did not retire")
        time.sleep(0.02)


def relay(source) -> None:
    shutil.copyfileobj(source, sys.stdout.buffer)
    sys.stdout.buffer.flush()


def supervise(args: list[str], environment: dict[str, str], evidence: Path) -> int:
    receipt = {
        "pytest_args": args,
        "child_exit": None,
        "exit": None,
        "signal": None,
        "child_pid": None,
        "cleanup": "not-started",
    }
    receipt_path = evidence / "invocation.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    child = None
    received = None
    interrupted_at = None

    def interrupted(signum, frame):
        nonlocal received, interrupted_at
        if received is None:
            received = signum
            interrupted_at = time.monotonic()

    previous = {
        sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        # Linux CI: adopt orphaned grandchildren so cleanup can reap its own group,
        # not rely on a container/runner PID 1 to reap them promptly.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "Cannot own orphaned test children")
        with (evidence / "pytest.log").open("wb") as output:
            with (evidence / "pytest.log").open("rb") as reader:
                try:
                    child = subprocess.Popen(  # noqa: S603 -- explicit argv, no shell.
                        [
                            sys.executable,
                            "-u",
                            str(Path(__file__).resolve()),
                            "--child",
                            *args,
                        ],
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        env=environment,
                        start_new_session=True,
                    )
                    receipt["child_pid"] = child.pid
                    receipt["cleanup"] = "pending"
                    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
                    forwarded = False
                    while child.poll() is None:
                        if received is not None:
                            if not forwarded:
                                signal_group(child, received)
                                forwarded = True
                            elif time.monotonic() - interrupted_at >= 2:
                                signal_group(child, signal.SIGKILL)
                        relay(reader)
                        time.sleep(0.05)
                    receipt["child_exit"] = child.returncode
                    relay(reader)
                finally:
                    if child is not None:
                        try:
                            retire_group(child)
                            receipt["cleanup"] = "complete"
                        finally:
                            receipt["child_exit"] = child.returncode
        code = receipt["child_exit"]
        receipt["exit"] = code if code >= 0 else 128 - code
    except Exception as error:
        # No exception text/environment dump: paths/values may contain credentials.
        receipt["error"] = type(error).__name__
        receipt["exit"] = 125
    finally:
        receipt["signal"] = received
        if received is not None:
            receipt["exit"] = 128 + received
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt["exit"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=Path("artifacts/pytest"))
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    args = options.pytest_args
    if args[:1] == ["--"]:
        args = args[1:]
    options.output_root.mkdir(parents=True, exist_ok=True)
    evidence = Path(
        tempfile.mkdtemp(prefix="invocation-", dir=options.output_root)
    ).resolve()
    args = [
        *args,
        "-p",
        "ci_pytest",
        f"--ci-progress={evidence / 'progress.jsonl'}",
        f"--junitxml={evidence / 'junit.xml'}",
        "--durations=50",
    ]
    environment = os.environ.copy()
    if any(arg == "--cov" or arg.startswith("--cov=") for arg in args):
        args.append(f"--ci-coverage-file={evidence / '.coverage'}")
        args.append(f"--cov-report=xml:{evidence / 'coverage.xml'}")
    return supervise(args, environment, evidence)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--child"]:
        raise SystemExit(pytest.main(sys.argv[2:]))
    raise SystemExit(main())
