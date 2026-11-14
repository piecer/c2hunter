"""Collection-only CLI regressions for shard metadata, never product bodies."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def metadata_world(tmp_path):
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    for name in ("ci_pytest.py", "ci_shard_plugin.py"):
        shutil.copyfile(ROOT / "tools" / name, root / "tools" / name)
    (root / "pytest.ini").write_text(
        "[pytest]\nmarkers =\n    custom: literal description  \n"
        "    custom: literal description  \n"
        "filterwarnings =\n    ignore:first:UserWarning\n    error:second:UserWarning\n"
        "pythonpath = first second\n"
    )
    (root / "test_literal.py").write_text(
        "import pytest\n"
        "@pytest.fixture(autouse=True)\n"
        "def forbidden_fixture():\n"
        "    raise AssertionError('collection must not enter fixtures')\n"
        "@pytest.mark.parametrize('value', ['a::b', 'x[y]'])\n"
        "def test_literal(value):\n"
        "    raise AssertionError('collection must not enter bodies')\n"
    )
    return root


def collection(root, name, request, plugins):
    output = root.parent / name
    output.mkdir()
    (output / "request.json").write_text(
        json.dumps({**request, "root": str(root), "output": str(output)})
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PYTHONPATH", "PYTEST_PLUGINS", "PYTEST_ADDOPTS", "COVERAGE_FILE")
        and not k.startswith("COV_CORE_")
    }
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    command = [
        sys.executable,
        str(root / "tools/ci_pytest.py"),
        "--output-root",
        str(output / "diagnostics"),
        "--",
        "-q",
        "--collect-only",
        *[arg for plugin in plugins for arg in ("-p", plugin)],
        "-p",
        "ci_shard_plugin",
        f"--ci-shard-request={output / 'request.json'}",
    ]
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=20)
    invocation = next((output / "diagnostics").glob("invocation-*"))
    receipt = json.loads((invocation / "invocation.json").read_text())
    assert receipt["child_exit"] == result.returncode
    assert receipt["cleanup"] == "complete"
    assert (invocation / "progress.jsonl").read_text() == ""
    return result, output


def test_marker_declaration_order_independent_through_explicit_plugin_cli(tmp_path):
    root = metadata_world(tmp_path)
    result, output = collection(root, "plan", {"mode": "collect"}, ("pytest_cov", "anyio"))
    assert result.returncode == 0, result.stdout + result.stderr
    plan = json.loads((output / "selection.json").read_text())
    request = {
        "mode": "run",
        "identity": plan["identity"],
        "inventory": plan["inventory"],
        "files": ["test_literal.py"],
    }
    result, output = collection(root, "run", request, ("anyio", "pytest_cov"))
    assert result.returncode == 0, result.stdout + result.stderr
    selected = json.loads((output / "selection.json").read_text())
    assert selected == plan
    assert [row["nodeid"] for row in selected["inventory"]] == [
        "test_literal.py::test_literal[a::b]",
        "test_literal.py::test_literal[x[y]]",
    ]
    assert selected["identity"]["ini"]["markers"].count("custom: literal description") == 2


@pytest.mark.parametrize(
    "change",
    [
        "filterwarnings-order",
        "pythonpath-order",
        "marker-description",
        "marker-multiplicity",
        "marker-whitespace",
        "keyword",
        "importmode",
        "rootpath",
        "nodeid-literal",
        "nodeid-order",
    ],
)
def test_semantic_or_literal_changes_still_fail_collection(tmp_path, change):
    root = metadata_world(tmp_path)
    plugins = ("pytest_cov", "anyio")
    result, output = collection(root, "plan", {"mode": "collect"}, plugins)
    assert result.returncode == 0, result.stdout + result.stderr
    plan = json.loads((output / "selection.json").read_text())
    identity = plan["identity"]
    if change in ("filterwarnings-order", "pythonpath-order"):
        identity["ini"][change.removesuffix("-order")].reverse()
    elif change == "marker-description":
        identity["ini"]["markers"][0] += " changed"
    elif change == "marker-multiplicity":
        identity["ini"]["markers"].append(identity["ini"]["markers"][0])
    elif change == "marker-whitespace":
        identity["ini"]["markers"][0] += " "
    elif change == "keyword":
        identity["options"]["keyword"] = "literal"
    elif change == "importmode":
        identity["options"]["importmode"] = "importlib"
    elif change == "rootpath":
        identity["rootpath"] += "/different"
    elif change == "nodeid-literal":
        plan["inventory"][0]["nodeid"] = "test_literal.py::test_literal[a:b]"
    elif change == "nodeid-order":
        plan["inventory"].reverse()
    result, output = collection(
        root,
        "run",
        {
            "mode": "run",
            "identity": identity,
            "inventory": plan["inventory"],
            "files": ["test_literal.py"],
        },
        plugins,
    )
    assert result.returncode == 4, result.stdout + result.stderr
    expected = (
        "full collection mismatch"
        if change.startswith("nodeid-")
        else "collection identity mismatch"
    )
    assert expected in result.stdout
    assert not (output / "selection.json").exists()


@pytest.mark.parametrize(
    ("change", "fields"),
    [
        ("multiple", "cwd, ini.markers, options.keyword"),
        ("missing-leaf", "options.keyword"),
        ("missing-group", "ini"),
        ("leaf-type", "ini.markers"),
        ("group-type", "options"),
        ("root-type", "identity"),
        ("unknown-root", "identity"),
        ("unknown-ini", "ini"),
        ("unknown-options", "options"),
        ("many-unknown", "identity, ini, options"),
    ],
)
def test_mismatch_diagnostics_are_bounded_nonsecret_field_paths(tmp_path, change, fields):
    root = metadata_world(tmp_path)
    plugins = ("pytest_cov", "anyio")
    result, output = collection(root, "plan", {"mode": "collect"}, plugins)
    assert result.returncode == 0, result.stdout + result.stderr
    plan = json.loads((output / "selection.json").read_text())
    identity = plan["identity"]
    secret = "SECRET_SENTINEL_DO_NOT_PRINT_" + "x" * 4096
    if change == "multiple":
        identity["cwd"] = secret
        identity["ini"]["markers"] = [secret]
        identity["options"]["keyword"] = secret
    elif change == "missing-leaf":
        del identity["options"]["keyword"]
    elif change == "missing-group":
        del identity["ini"]
    elif change == "leaf-type":
        identity["ini"]["markers"] = {secret: secret}
    elif change == "group-type":
        identity["options"] = [secret]
    elif change == "root-type":
        identity = secret
    elif change == "many-unknown":
        for group in (identity, identity["ini"], identity["options"]):
            group.update({secret + str(i): secret for i in range(100)})
    else:
        group = identity if change == "unknown-root" else identity[change.removeprefix("unknown-")]
        group[secret] = secret
    result, output = collection(
        root,
        "run",
        {
            "mode": "run",
            "identity": identity,
            "inventory": plan["inventory"],
            "files": ["test_literal.py"],
        },
        plugins,
    )
    assert result.returncode == 4, result.stdout + result.stderr
    text = result.stdout + result.stderr
    lines = [line for line in text.splitlines() if "collection identity mismatch" in line]
    assert lines == [f"ERROR: collection identity mismatch (fields: {fields})"]
    assert len(lines[0]) < 1024
    assert "SECRET_SENTINEL" not in text
    assert not (output / "selection.json").exists()
    assert {p.name for p in output.iterdir()} == {"request.json", "finish.json", "diagnostics"}
    for path in (output / "diagnostics").rglob("*"):
        if path.is_file():
            assert b"SECRET_SENTINEL" not in path.read_bytes()
