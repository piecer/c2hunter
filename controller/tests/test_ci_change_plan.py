"""CLI contracts against actual policy bytes committed into disposable Git repos."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = "tools/ci_change_plan.py"
WORKFLOW = ".github/workflows/ci.yml"
CSS = ("web/src/styles.css", "web/src/investigation.css", "web/src/jobInvestigation.css")
KEEP = {"lint", "security", "unit-web", "e2e", "build"}
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
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        + "\n"
    ).encode()


class Repository:
    def __init__(self, tmp):
        self.root = tmp / "repo"
        self.root.mkdir()
        self.env = {
            # Do not inherit outer native-coverage startup or runner secrets.
            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.defpath,
            "HOME": str(tmp),
            "TMPDIR": str(tmp),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LC_ALL": "C.UTF-8",
        }
        self.git("init", "-q")
        for name in (SCRIPT, WORKFLOW):
            if (ROOT / name).exists():
                self.write(name, (ROOT / name).read_bytes())
        for name in CSS:
            self.write(name, b"body { color: black; }\n")
        self.write("backend.txt", b"baseline\n")
        self.base = self.commit()
        self.env.update(
            GITHUB_EVENT_NAME="workflow_dispatch",
            GITHUB_SHA=self.base,
            GITHUB_REF="refs/heads/main",
            GITHUB_REPOSITORY="owner/repo",
            GITHUB_RUN_ID="1234",
            GITHUB_RUN_ATTEMPT="1",
            GITHUB_EVENT_PATH=str(tmp / "event.json"),
            GITHUB_OUTPUT=str(tmp / "outputs"),
        )
        self.event({})
        self.plan_path = tmp / "artifact/plan.json"

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def git(self, *args):
        return (
            subprocess.run(
                ["git", *args],
                cwd=self.root,
                env=self.env,
                capture_output=True,
                check=True,
                timeout=10,
            )
            .stdout.decode()
            .strip()
        )

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def event(self, value):
        Path(self.env["GITHUB_EVENT_PATH"]).write_bytes(canonical(value))

    def push(self, before=None):
        head = self.git("rev-parse", "HEAD")
        self.env.update(GITHUB_EVENT_NAME="push", GITHUB_SHA=head)
        self.event({"before": before or self.base, "after": head})

    def cli(self, command="plan"):
        args = ["plan", "--output"] if command == "plan" else ["gate", "--plan"]
        return subprocess.run(
            [sys.executable, "-I", "-B", str(self.root / SCRIPT), *args, str(self.plan_path)],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def pull_request(self, variant="same-tree"):
        self.write(CSS[0], b"body { color: blue; }\n")
        head = self.commit()
        tree = self.git("rev-parse", "HEAD^{tree}")
        base = self.base
        parents = ["-p", base, "-p", head]
        if variant == "changed-tree":
            self.write("backend.txt", b"merge-only change\n")
            self.commit()
            tree = self.git("rev-parse", "HEAD^{tree}")
        elif variant == "head-not-ancestor":
            parents = ["-p", base]
        elif variant == "base-not-ancestor":
            base = self.git("commit-tree", tree, "-m", "unrelated base")
        tested = self.git("commit-tree", tree, *parents, "-m", "synthetic merge")
        self.git("reset", "--hard", tested)
        self.env.update(
            GITHUB_EVENT_NAME="pull_request", GITHUB_SHA=tested, GITHUB_REF="refs/pull/7/merge"
        )
        self.event({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}})
        return base, head, tested

    def plan(self):
        result = self.cli()
        assert result.returncode == 0, result.stderr
        raw = self.plan_path.read_bytes()
        value = json.loads(raw)
        assert raw == canonical(value)
        return value

    def needs(self, plan):
        needs = {
            job: {"result": "success" if selected else "skipped", "outputs": {}}
            for job, selected in plan["jobs"].items()
        }
        needs["change-plan"] = {
            "result": "success",
            "outputs": {
                "mode": plan["mode"],
                "plan_sha256": hashlib.sha256(self.plan_path.read_bytes()).hexdigest(),
            },
        }
        self.env["NEEDS_JSON"] = json.dumps(needs)
        return needs


@pytest.fixture
def repo(tmp_path):
    return Repository(tmp_path)


def test_manual_plan_publishes_fixed_full_map_and_digest(repo):
    plan = repo.plan()
    assert plan["mode"] == "full"
    assert plan["jobs"] == dict.fromkeys(JOBS, True)
    assert plan["schema"] == 1
    output = Path(repo.env["GITHUB_OUTPUT"]).read_text()
    digest = hashlib.sha256(repo.plan_path.read_bytes()).hexdigest()
    assert output == f"mode=full\nplan_sha256={digest}\n"


def test_plan_binds_identity_and_commit_policy_manifest(repo):
    plan = repo.plan()
    manifest = {
        name: hashlib.sha256((repo.root / name).read_bytes()).hexdigest()
        for name in (SCRIPT, WORKFLOW)
    }
    assert plan["policy_sha256"] == hashlib.sha256(canonical(manifest)).hexdigest()
    assert plan["tested_sha"] == repo.base
    assert plan["tested_tree"] == repo.git("rev-parse", "HEAD^{tree}")
    for field, env in (
        ("repository", "GITHUB_REPOSITORY"),
        ("run_id", "GITHUB_RUN_ID"),
        ("run_attempt", "GITHUB_RUN_ATTEMPT"),
        ("ref", "GITHUB_REF"),
        ("event", "GITHUB_EVENT_NAME"),
    ):
        assert plan[field] == repo.env[env]


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_SHA", "a" * 40),
        ("GITHUB_SHA", "HEAD"),
        ("GITHUB_RUN_ID", ""),
        ("GITHUB_RUN_ATTEMPT", "0"),
        ("GITHUB_REPOSITORY", "../repo"),
    ],
)
def test_invalid_required_identity_fails(repo, field, value):
    repo.env[field] = value
    assert repo.cli().returncode != 0


@pytest.mark.parametrize("name", [SCRIPT, WORKFLOW])
def test_uncommitted_executing_policy_fails(repo, name):
    with (repo.root / name).open("ab") as stream:
        stream.write(b"\n# changed policy\n")
    assert repo.cli().returncode != 0


@pytest.mark.parametrize("paths", [(path,) for path in CSS] + [CSS])
def test_small_existing_css_push_is_partial(repo, paths):
    for path in paths:
        repo.write(path, b"body { color: blue; }\n")
    head = repo.commit()
    repo.push()
    plan = repo.plan()
    assert plan["mode"] == "frontend-only"
    assert plan["jobs"] == {job: job in KEEP for job in JOBS}
    assert plan["raw_base"] == plan["diff_base"] == repo.base
    assert plan["raw_head"] == plan["diff_head"] == head
    assert plan["changes_complete"] is True
    assert {change["path"] for change in plan["changes"]} == set(paths)
    assert sum(c["added"] + c["deleted"] for c in plan["changes"]) == 2 * len(paths)


@pytest.mark.parametrize("lines,mode", [(199, "frontend-only"), (200, "full")])
def test_total_added_plus_deleted_boundary(repo, lines, mode):
    repo.write(CSS[0], b".new {}\n" * lines)
    repo.commit()
    repo.push()
    assert repo.plan()["mode"] == mode  # One old line also counts.


@pytest.mark.parametrize(
    "change",
    [
        "mixed",
        "prefix",
        "add",
        "delete",
        "rename",
        "mode",
        "binary",
        "utf8",
        "oversize",
        "old-oversize",
        "old-binary",
        "old-mode",
        "symlink",
        "noop",
        "multicommit",
        "gitlink",
    ],
)
def test_non_css_or_unsafe_css_is_full(repo, change):
    before = repo.base
    if change.startswith("old-"):
        if change == "old-mode":
            (repo.root / CSS[0]).chmod(0o755)
        else:
            repo.write(CSS[0], b"a" * 131073 if change == "old-oversize" else b"a\0")
        before = repo.commit()
        (repo.root / CSS[0]).chmod(0o644)
    if change == "gitlink":
        repo.git("update-index", "--add", "--cacheinfo", f"160000,{repo.base},sub")
        repo.git("commit", "-qm", "gitlink baseline")
        before = repo.git("rev-parse", "HEAD")
        repo.git("update-index", "--cacheinfo", f"160000,{before},sub")
        repo.git("commit", "-qm", "gitlink change")
        repo.git("config", "diff.ignoreSubmodules", "all")
        repo.git("config", "submodule.sub.ignore", "all")
    if change == "multicommit":
        repo.write("backend.txt", b"changed in earlier commit\n")
        repo.commit()
    repo.write(CSS[0], b"body { color: blue; }\n")
    if change in {"mixed", "prefix", "add"}:
        name = {"mixed": "backend.txt", "prefix": CSS[0] + ".extra", "add": "web/new.css"}
        repo.write(name[change], b"new\n")
    elif change == "delete":
        (repo.root / CSS[0]).unlink()
    elif change == "rename":
        repo.git("mv", CSS[0], "web/src/renamed.css")
    elif change == "mode":
        (repo.root / CSS[0]).chmod(0o755)
    elif change in {"binary", "utf8", "oversize"}:
        data = {"binary": b"\0binary", "utf8": b"\xff", "oversize": b"a" * 131073}
        repo.write(CSS[0], data[change])
    elif change == "symlink":
        (repo.root / CSS[0]).unlink()
        (repo.root / CSS[0]).symlink_to("investigation.css")
    if change == "noop":
        repo.git("reset", "--hard", repo.base)
    else:
        repo.commit()
    if change == "gitlink":
        repo.git("update-index", "--add", "--cacheinfo", f"160000,{before},sub")
        repo.git("commit", "--amend", "--no-edit", "-q")
        assert "160000 commit " + before in repo.git("ls-tree", "HEAD", "sub")
        assert "160000 commit " + repo.base in repo.git("ls-tree", before, "sub")
    repo.push(before)
    plan = repo.plan()
    assert plan["mode"] == "full"
    assert plan["jobs"] == dict.fromkeys(JOBS, True)


@pytest.mark.parametrize(
    "context",
    [
        "new-branch",
        "missing",
        "invalid",
        "uppercase",
        "after-mismatch",
        "tag",
        "unknown",
    ],
)
def test_invalid_push_context_is_full(repo, context):
    repo.write(CSS[0], b"body { color: blue; }\n")
    head = repo.commit()
    repo.push()
    if context in {"new-branch", "missing", "invalid", "uppercase"}:
        before = {
            "new-branch": "0" * 40,
            "missing": "a" * 40,
            "invalid": "HEAD^",
            "uppercase": repo.base.upper(),
        }[context]
        repo.event({"before": before, "after": head})
    elif context == "after-mismatch":
        repo.event({"before": repo.base, "after": repo.base})
    elif context == "tag":
        repo.env["GITHUB_REF"] = "refs/tags/v1"
    else:
        repo.env["GITHUB_EVENT_NAME"] = "unknown"
    assert repo.plan()["mode"] == "full"


@pytest.mark.parametrize(
    "variant,mode",
    [
        ("same-tree", "frontend-only"),
        ("changed-tree", "full"),
        ("head-not-ancestor", "full"),
        ("base-not-ancestor", "full"),
    ],
)
def test_pr_requires_both_ancestors_and_head_tree(repo, variant, mode):
    base, head, tested = repo.pull_request(variant)
    plan = repo.plan()
    assert plan["mode"] == mode
    assert plan["raw_base"] == base
    assert plan["raw_head"] == head
    assert plan["tested_sha"] == tested
    if mode == "frontend-only":
        assert plan["diff_base"] == base
        assert plan["diff_head"] == head


@pytest.fixture(params=["full", "frontend-only"])
def planned(repo, request):
    if request.param == "frontend-only":
        repo.write(CSS[0], b"body { color: blue; }\n")
        repo.commit()
        repo.push()
    plan = repo.plan()
    assert plan["mode"] == request.param
    return repo, plan, repo.needs(plan)


def test_gate_accepts_only_current_plan_and_distinct_verdict(planned):
    repo, plan, _ = planned
    result = repo.cli("gate")
    assert result.returncode == 0, result.stderr
    if plan["mode"] == "full":
        assert (
            "All required CI jobs, shard reconciliation and coverage floors succeeded"
            in result.stdout
        )
    else:
        assert "partial validation" in result.stdout
        assert "coverage floors succeeded" not in result.stdout
        for job in JOBS - KEEP:
            assert job in result.stdout


@pytest.mark.parametrize("job", sorted(JOBS))
@pytest.mark.parametrize("status", ["success", "skipped", "failure", "cancelled", "unknown"])
def test_every_work_job_status_in_both_modes(planned, job, status):
    repo, plan, needs = planned
    needs[job]["result"] = status
    repo.env["NEEDS_JSON"] = json.dumps(needs)
    expected = "success" if plan["jobs"][job] else "skipped"
    assert (repo.cli("gate").returncode == 0) == (status == expected)


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "extra",
        "failure",
        "skipped",
        "cancelled",
        "malformed",
        "no-outputs",
        "no-mode",
        "wrong-mode",
        "no-hash",
        "wrong-hash",
        "extra-output",
        "unknown",
        "no-result",
        "bool-result",
        "wrong-output-type",
    ],
)
def test_selector_itself_and_exact_outputs_are_required(planned, damage):
    repo, _, needs = planned
    selector = needs["change-plan"]
    if damage == "missing":
        del needs["change-plan"]
    elif damage == "extra":
        needs["extra-job"] = {"result": "success"}
    elif damage == "malformed":
        needs["change-plan"] = []
    elif damage in {"failure", "skipped", "cancelled", "unknown"}:
        selector["result"] = damage
    elif damage == "no-result":
        del selector["result"]
    elif damage == "bool-result":
        selector["result"] = True
    elif damage == "wrong-output-type":
        selector["outputs"] = []
    elif damage == "no-outputs":
        del selector["outputs"]
    elif damage == "no-mode":
        del selector["outputs"]["mode"]
    elif damage == "wrong-mode":
        selector["outputs"]["mode"] = "invalid"
    elif damage == "no-hash":
        del selector["outputs"]["plan_sha256"]
    elif damage == "wrong-hash":
        selector["outputs"]["plan_sha256"] = "0" * 64
    else:
        selector["outputs"]["extra"] = "value"
    repo.env["NEEDS_JSON"] = json.dumps(needs)
    assert repo.cli("gate").returncode != 0


@pytest.mark.parametrize("target", ["event", "needs", "plan"])
def test_duplicate_json_keys_fail_closed(planned, target):
    repo, _, _ = planned
    if target == "event":
        # Use a duplicated otherwise valid key, even on a manual/full run.
        path = Path(repo.env["GITHUB_EVENT_PATH"])
        data = path.read_bytes()
        path.write_bytes(
            b'{"duplicate":1,"duplicate":1,' + data[1:]
            if data != b"{}\n"
            else b'{"duplicate":1,"duplicate":1}\n'
        )
    elif target == "needs":
        data = repo.env["NEEDS_JSON"]
        repo.env["NEEDS_JSON"] = '{"lint":{"result":"failure"},' + data[1:]
    else:
        data = repo.plan_path.read_bytes()
        repo.plan_path.write_bytes(b'{"schema":1,' + data[1:])
    assert repo.cli("gate").returncode != 0


@pytest.mark.parametrize("target", ["event", "needs", "plan"])
def test_oversized_inputs_fail_closed(planned, target):
    repo, _, _ = planned
    if target == "event":
        path = Path(repo.env["GITHUB_EVENT_PATH"])
        path.write_bytes(path.read_bytes() + b" " * 1048577)
    elif target == "needs":
        repo.env["NEEDS_JSON"] += " " * 65537
    else:
        repo.plan_path.write_bytes(repo.plan_path.read_bytes() + b" " * 16385)
    assert repo.cli("gate").returncode != 0


@pytest.mark.parametrize(
    "damage",
    [
        "wrong-bool",
        "wrong-schema-type",
        "policy",
        "raw-base",
        "raw-head",
        "diff-base",
        "diff-head",
        "run-id",
        "attempt",
        "repository",
        "tested",
        "tree",
        "missing",
        "malformed",
        "extra-key",
        "noncanonical",
        "deleted-job",
        "extra-job",
    ],
)
def test_tampered_artifact_rejected_even_with_matching_published_digest(planned, damage):
    repo, plan, needs = planned
    if damage == "wrong-bool":
        plan["jobs"]["lint"] = 1
    elif damage == "wrong-schema-type":
        plan["schema"] = True
    elif damage == "extra-key":
        plan["extra"] = "value"
    elif damage == "deleted-job":
        del plan["jobs"]["lint"]
    elif damage == "extra-job":
        plan["jobs"]["extra"] = True
    elif damage not in {"missing", "malformed", "noncanonical"}:
        field = {
            "policy": "policy_sha256",
            "raw-base": "raw_base",
            "raw-head": "raw_head",
            "diff-base": "diff_base",
            "diff-head": "diff_head",
            "run-id": "run_id",
            "attempt": "run_attempt",
            "repository": "repository",
            "tested": "tested_sha",
            "tree": "tested_tree",
        }[damage]
        plan[field] = "tampered"
    raw = canonical(plan)
    if damage == "noncanonical":
        raw = json.dumps(plan, indent=2).encode()
    elif damage == "malformed":
        raw = b"not json"
    repo.plan_path.write_bytes(raw)
    needs["change-plan"]["outputs"]["plan_sha256"] = hashlib.sha256(raw).hexdigest()
    repo.env["NEEDS_JSON"] = json.dumps(needs)
    if damage == "missing":
        repo.plan_path.unlink()
    assert repo.cli("gate").returncode != 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_RUN_ID", "5678"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_REPOSITORY", "different/repo"),
        ("GITHUB_SHA", "a" * 40),
        ("GITHUB_REF", "refs/tags/v2"),
        ("GITHUB_EVENT_NAME", "unknown"),
    ],
)
def test_current_identity_must_match_artifact(planned, field, value):
    repo, _, _ = planned
    repo.env[field] = value
    assert repo.cli("gate").returncode != 0


@pytest.mark.parametrize("job", sorted(JOBS))
@pytest.mark.parametrize("damage", ["missing", "malformed", "no-result", "bool-result"])
def test_closed_work_job_records(planned, job, damage):
    repo, _, needs = planned
    if damage == "missing":
        del needs[job]
    elif damage == "malformed":
        needs[job] = []
    elif damage == "no-result":
        needs[job] = {}
    else:
        needs[job]["result"] = True
    repo.env["NEEDS_JSON"] = json.dumps(needs)
    assert repo.cli("gate").returncode != 0


@pytest.mark.parametrize("name", [SCRIPT, WORKFLOW])
def test_gate_rechecks_executing_policy(planned, name):
    repo, _, _ = planned
    with (repo.root / name).open("ab") as stream:
        stream.write(b"\n# altered after planning\n")
    assert repo.cli("gate").returncode != 0


def test_raw_pr_base_is_bound_even_with_same_merge_base(repo):
    repo.write(CSS[0], b"body { color: blue; }\n")
    head = repo.commit()
    tree = repo.git("rev-parse", "HEAD^{tree}")
    basetree = repo.git("rev-parse", repo.base + "^{tree}")
    advanced = repo.git("commit-tree", basetree, "-p", repo.base, "-m", "advanced base")
    tested = repo.git("commit-tree", tree, "-p", advanced, "-p", head, "-m", "merge")
    repo.git("reset", "--hard", tested)
    repo.env.update(
        GITHUB_EVENT_NAME="pull_request", GITHUB_SHA=tested, GITHUB_REF="refs/pull/7/merge"
    )
    repo.event({"pull_request": {"base": {"sha": advanced}, "head": {"sha": head}}})
    plan = repo.plan()
    assert plan["mode"] == "frontend-only"
    assert plan["diff_base"] == repo.base
    assert plan["raw_base"] == advanced
    repo.needs(plan)
    assert repo.cli("gate").returncode == 0
    repo.event({"pull_request": {"base": {"sha": repo.base}, "head": {"sha": head}}})
    assert repo.cli("gate").returncode != 0


@pytest.mark.parametrize("kind", ["missing", "ambiguous"])
def test_pr_requires_unique_merge_base(repo, kind):
    repo.write(CSS[0], b"body { color: blue; }\n")
    head = repo.commit()
    tree = repo.git("rev-parse", "HEAD^{tree}")
    if kind == "missing":
        base = repo.git("commit-tree", tree, "-m", "unrelated")
    else:
        sibling = repo.git("commit-tree", tree, "-p", repo.base, "-m", "sibling")
        base = repo.git("commit-tree", tree, "-p", sibling, "-p", head, "-m", "left")
        head = repo.git("commit-tree", tree, "-p", head, "-p", sibling, "-m", "right")
        assert len(repo.git("merge-base", "--all", base, head).splitlines()) == 2
    tested = repo.git("commit-tree", tree, "-p", base, "-p", head, "-m", "merge")
    repo.git("reset", "--hard", tested)
    repo.env.update(
        GITHUB_EVENT_NAME="pull_request", GITHUB_SHA=tested, GITHUB_REF="refs/pull/7/merge"
    )
    repo.event({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}})
    assert repo.plan()["mode"] == "full"


def test_allowlisted_addition_is_not_existing_css(repo):
    (repo.root / CSS[0]).unlink()
    before = repo.commit()
    repo.write(CSS[0], b"body { color: blue; }\n")
    repo.commit()
    repo.push(before)
    assert repo.plan()["mode"] == "full"


def test_line_budget_is_aggregate_not_per_file(repo):
    for path in CSS:
        repo.write(path, b".new {}\n" * 67)
    repo.commit()
    repo.push()
    assert repo.plan()["mode"] == "full"


def test_exact_blob_size_boundary_is_allowed(repo):
    repo.write(CSS[0], b"a" * 131072)
    repo.commit()
    repo.push()
    assert repo.plan()["mode"] == "frontend-only"


def test_git_diff_error_is_not_a_clean_outside_diff(repo):
    repo.write(CSS[0], b"body { color: blue; }\n")
    repo.commit()
    repo.push()
    repo.git("config", "diff.algorithm", "invalid-algorithm")
    assert repo.plan()["mode"] == "full"


def test_external_diff_and_textconv_are_never_invoked(repo):
    marker = repo.root.parent / "external-called"
    executable = repo.root.parent / "external"
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n")
    executable.chmod(0o755)
    repo.write(".git/info/attributes", b"*.css diff=fixture\n")
    repo.git("config", "diff.external", str(executable))
    repo.git("config", "diff.fixture.textconv", str(executable))
    repo.write(CSS[0], b"body { color: blue; }\n")
    repo.commit()
    repo.push()
    assert repo.plan()["mode"] == "frontend-only"
    assert not marker.exists()


@pytest.mark.parametrize("target", ["event", "needs"])
@pytest.mark.parametrize("raw", [b"null", b"[]", b"{", b'{"x":NaN}', b'{"x":Infinity}'])
def test_malformed_json_admission(planned, target, raw):
    repo, _, _ = planned
    if target == "event":
        Path(repo.env["GITHUB_EVENT_PATH"]).write_bytes(raw)
    else:
        repo.env["NEEDS_JSON"] = raw.decode()
    result = repo.cli("gate")
    assert result.returncode != 0
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("target", ["artifact", "outputs"])
def test_publication_failure_is_hard_failure(repo, target):
    if target == "artifact":
        repo.plan_path.mkdir(parents=True)
    else:
        repo.env["GITHUB_OUTPUT"] = str(repo.root)
    assert repo.cli().returncode != 0


@pytest.mark.parametrize("target", ["event", "needs"])
def test_deep_input_has_bounded_diagnostic(planned, target):
    repo, _, _ = planned
    raw = '{"nested":' * 1500 + "0" + "}" * 1500
    if target == "event":
        Path(repo.env["GITHUB_EVENT_PATH"]).write_text(raw)
    else:
        repo.env["NEEDS_JSON"] = raw
    result = repo.cli("gate")
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert len(result.stderr) < 200


@pytest.mark.parametrize("config", ["extensions.partialClone", "remote.origin.promisor"])
def test_partial_clone_cannot_trigger_network_fetch(repo, config):
    repo.git("config", config, "true")
    assert repo.cli().returncode != 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_REF", "refs/heads/invalid..ref"),
        ("GITHUB_REPOSITORY", "owner/.."),
        ("GITHUB_REPOSITORY", "owner/" + "a" * 2000),
    ],
)
def test_invalid_or_excessive_context_identity_is_rejected(repo, field, value):
    repo.env[field] = value
    assert repo.cli().returncode != 0


def test_fixture_children_do_not_inherit_native_coverage_or_secrets(tmp_path, monkeypatch):
    for key in (
        "COV_CORE_SOURCE",
        "COV_CORE_CONFIG",
        "COV_CORE_DATAFILE",
        "COVERAGE_PROCESS_START",
        "GITHUB_TOKEN",
    ):
        monkeypatch.setenv(key, "not-a-child-input")
    repo = Repository(tmp_path)
    assert not any(key.startswith(("COV_", "COVERAGE_")) for key in repo.env)
    assert "GITHUB_TOKEN" not in repo.env
    assert repo.plan()["mode"] == "full"
