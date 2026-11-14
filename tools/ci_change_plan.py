"""Conservative, fixed CSS-only CI selection and artifact-bound final admission."""

import argparse
import hashlib
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ("tools/ci_change_plan.py", ".github/workflows/ci.yml")
CSS = (
    "web/src/styles.css",
    "web/src/investigation.css",
    "web/src/jobInvestigation.css",
)
DIFF = (
    "diff",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--ignore-submodules=none",
)
SHA = re.compile(r"[0-9a-f]{40}")
KEEP = frozenset({"lint", "security", "unit-web", "e2e", "build"})
JOBS = KEEP | {
    "shard-plan",
    "python",
    "python-verify",
    "unit-go",
    "unit-worker",
    "unit-tools",
    "coverage-controller",
    "coverage-controller-merge",
    "coverage-analysis",
    "coverage-sensor",
    "scenarios",
}


def canonical(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


class Invalid(ValueError):
    """Bounded, predefined diagnostic; never include arbitrary input contents."""


def json_object(raw, limit):
    if len(raw) > limit:
        raise Invalid("JSON size limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Invalid("duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise Invalid("nonfinite JSON constant")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(value, dict):
        raise Invalid("expected JSON object")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 32:
            raise Invalid("JSON nesting limit")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def git(*args, limit=262144, allowed=(0,)):
    executable = shutil.which("git")
    if executable is None:
        raise Invalid("git is required")
    env = {
        key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ
    }
    env.update(
        LC_ALL="C",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
        GIT_NO_LAZY_FETCH="1",
    )
    # Fixed read-only Git subcommands and validated identities; never a shell.
    with subprocess.Popen(  # noqa: S603 -- fixed read-only Git argv, no shell.
        [executable, *args],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as child:
        result = bytearray()
        deadline = time.monotonic() + 10
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise Invalid("git timeout")
                    chunk = os.read(
                        child.stdout.fileno(), min(8192, limit + 1 - len(result))
                    )
                    if not chunk:
                        break
                    result.extend(chunk)
                    if len(result) > limit:
                        raise Invalid("git output limit")
            status = child.wait(timeout=max(0.01, deadline - time.monotonic()))
            if status not in allowed:
                raise Invalid("git command failed")
            return status, bytes(result)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def revision(value, suffix=""):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise Invalid("invalid commit identity")
    return git("rev-parse", "--verify", value + suffix)[1].decode().strip()


def bounded_read(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise Invalid("invalid input file")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise Invalid("input size limit")
    return value


def tree_entry(commit, path):
    raw = git("ls-tree", "-z", commit, "--", ":(top,literal)" + path, limit=1024)[1]
    fields = raw.removesuffix(b"\0").split(b"\t")
    if len(fields) != 2 or fields[1] != path.encode():
        raise Invalid("missing tree entry")
    mode, kind, oid = fields[0].decode().split()
    if mode != "100644" or kind != "blob" or not SHA.fullmatch(oid):
        raise Invalid("nonregular tree entry")
    return oid


def blob(oid, limit):
    size = int(git("cat-file", "-s", oid, limit=32)[1])
    if size > limit:
        raise Invalid("blob size limit")
    return git("cat-file", "blob", oid, limit=limit)[1]


def css_changes(base, head):
    # The endpoint tree delta is authoritative, not HEAD^ or intermediate commits.
    outside = git(
        *DIFF,
        "--quiet",
        base,
        head,
        "--",
        *(":(top,literal,exclude)" + path for path in CSS),
        allowed=(0, 1),
    )[0]
    if outside:
        raise Invalid("outside CSS policy")
    changes = []
    for path in CSS:
        literal = ":(top,literal)" + path
        if git(*DIFF, "--quiet", base, head, "--", literal, allowed=(0, 1))[0] == 0:
            continue
        old, new = tree_entry(base, path), tree_entry(head, path)
        # Check both sizes before loading either content; read only the fixed CSS paths.
        for oid in (old, new):
            if int(git("cat-file", "-s", oid, limit=32)[1]) > 131072:
                raise Invalid("CSS blob size limit")
        for oid in (old, new):
            content = blob(oid, 131072)
            if b"\0" in content:
                raise Invalid("binary CSS")
            content.decode("utf-8")
        stat = git(*DIFF, "--numstat", base, head, "--", literal, limit=1024)[1]
        added, deleted, name = stat.decode().rstrip("\n").split("\t")
        if name != path or not added.isdecimal() or not deleted.isdecimal():
            raise Invalid("invalid CSS statistics")
        changes.append(
            {
                "path": path,
                "old_blob": old,
                "new_blob": new,
                "added": int(added),
                "deleted": int(deleted),
            }
        )
    if not changes or sum(c["added"] + c["deleted"] for c in changes) > 200:
        raise Invalid("empty or excessive CSS delta")
    return changes


def select(plan):
    plan.update(
        raw_base=None,
        raw_head=None,
        diff_base=None,
        diff_head=None,
        changes=[],
        changes_complete=False,
    )
    event = json_object(
        bounded_read(Path(os.environ.get("GITHUB_EVENT_PATH", "")), 1048576),
        1048576,
    )
    if plan["event"] not in {"push", "pull_request"}:
        return
    if plan["event"] == "push":
        endpoints = (event.get("before"), event.get("after"))
    else:
        pr = event.get("pull_request", {})
        if not isinstance(pr, dict) or any(
            not isinstance(pr.get(key, {}), dict) for key in ("base", "head")
        ):
            raise Invalid("invalid PR event")
        endpoints = (pr.get("base", {}).get("sha"), pr.get("head", {}).get("sha"))
    for field, value in zip(("raw_base", "raw_head"), endpoints, strict=True):
        if isinstance(value, str) and SHA.fullmatch(value):
            plan[field] = value
    plan["reason"] = "invalid-diff-context"
    try:
        base, head = plan["raw_base"], plan["raw_head"]
        revision(base, "^{commit}")
        revision(head, "^{commit}")
        if plan["event"] == "push":
            if head != plan["tested_sha"] or not plan["ref"].startswith("refs/heads/"):
                return
        else:
            if not re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", plan["ref"]):
                return
            for endpoint in (base, head):
                git("merge-base", "--is-ancestor", endpoint, plan["tested_sha"])
            if revision(head, "^{tree}") != plan["tested_tree"]:
                return
            bases = (
                git("merge-base", "--all", base, head, limit=1024)[1]
                .decode()
                .splitlines()
            )
            if len(bases) != 1 or not SHA.fullmatch(bases[0]):
                return
            base = bases[0]
        plan.update(diff_base=base, diff_head=head, reason="outside-css-policy")
        changes = css_changes(base, head)
    except (Invalid, OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return
    plan.update(
        mode="frontend-only",
        reason="small-existing-css-only",
        changes=changes,
        changes_complete=True,
        jobs={job: job in KEEP for job in JOBS},
    )


def make_plan():
    # Older Git versions may not honor GIT_NO_LAZY_FETCH. Never enter a promisor
    # repository, where a nominally local object lookup could initiate a fetch.
    if (
        git(
            "config",
            "--get-regexp",
            r"^(extensions\.partialclone|remote\..*\.promisor)$",
            allowed=(0, 1),
        )[0]
        == 0
    ):
        raise Invalid("partial clone is not supported")
    identity = {}
    for field, key, pattern in (
        (
            "repository",
            "GITHUB_REPOSITORY",
            r"[A-Za-z0-9_-]{1,100}/[A-Za-z0-9_.-]{1,100}",
        ),
        ("run_id", "GITHUB_RUN_ID", r"[1-9][0-9]{0,19}"),
        ("run_attempt", "GITHUB_RUN_ATTEMPT", r"[1-9][0-9]{0,9}"),
        ("ref", "GITHUB_REF", r"refs/[^\s\x00-\x1f]{1,240}"),
        ("event", "GITHUB_EVENT_NAME", r"[a-z_]{1,64}"),
    ):
        value = os.environ.get(key, "")
        if not re.fullmatch(pattern, value):
            raise Invalid("invalid run identity")
        identity[field] = value
    if identity["repository"].split("/")[1] in {".", ".."}:
        raise Invalid("invalid repository identity")
    git("check-ref-format", identity["ref"])
    tested = os.environ.get("GITHUB_SHA", "")
    revision(tested, "^{commit}")
    if git("rev-parse", "HEAD")[1].decode().strip() != tested:
        raise Invalid("tested checkout mismatch")
    manifest = {}
    for path in POLICY:
        source = blob(tree_entry(tested, path), 262144)
        if source != bounded_read(ROOT / path, 262144):
            raise Invalid("executing policy mismatch")
        manifest[path] = hashlib.sha256(source).hexdigest()
    plan = {
        "schema": 1,
        "mode": "full",
        "reason": "unsupported-event",
        "jobs": dict.fromkeys(JOBS, True),
        **identity,
        "tested_sha": tested,
        "tested_tree": revision(tested, "^{tree}"),
        "policy_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
    }
    select(plan)
    return plan


def gate(path, plan):
    raw = bounded_read(path, 16384)
    # Byte equality also enforces the closed schema, canonical form and exact types
    # (Python dictionary equality alone treats True == 1).
    if raw != canonical(plan):
        raise Invalid("plan mismatch")
    needs = json_object(os.environ.get("NEEDS_JSON", "").encode("utf-8"), 65536)
    if not isinstance(needs, dict) or set(needs) != JOBS | {"change-plan"}:
        raise Invalid("unexpected job set")
    expected_outputs = {
        "mode": plan["mode"],
        "plan_sha256": hashlib.sha256(raw).hexdigest(),
    }
    for name in sorted(needs):
        record = needs[name]
        expected = (
            "success" if name == "change-plan" or plan["jobs"][name] else "skipped"
        )
        if not isinstance(record, dict) or record.get("result") != expected:
            raise Invalid("unexpected job result")
    if needs["change-plan"].get("outputs") != expected_outputs:
        raise Invalid("selector outputs mismatch")
    if plan["mode"] == "full":
        print(
            "All required CI jobs, shard reconciliation and coverage floors succeeded"
        )
    else:
        print(
            "Frontend-only partial validation succeeded; backend jobs are planned skips: "
            + ", ".join(sorted(JOBS - KEEP))
        )
        print("No backend test, coverage or inherited base-health claim is made.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan").add_argument("--output", type=Path, required=True)
    commands.add_parser("gate").add_argument("--plan", type=Path, required=True)
    args = parser.parse_args()
    plan = make_plan()
    if args.command == "gate":
        gate(args.plan, plan)
        return 0
    raw = canonical(plan)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(
                f"mode={plan['mode']}\nplan_sha256={hashlib.sha256(raw).hexdigest()}\n"
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, ValueError, RecursionError):
        print(
            "CI change plan rejected: invalid context, input, or publication",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
