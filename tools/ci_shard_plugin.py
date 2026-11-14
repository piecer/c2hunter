"""Explicit child-only collection observer and whole-file shard selector."""

import json
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--ci-shard-request")


def pytest_configure(config):
    request = config.getoption("--ci-shard-request")
    if request:
        config.pluginmanager.register(
            ShardObserver(config, Path(request)), "shard-observer"
        )


class ShardObserver:
    def __init__(self, config, request):
        self.request = json.loads(request.read_text())
        self.encode = json.JSONEncoder(sort_keys=True).encode
        self.config = config
        self.full = []

    def rows(self, items):
        root = Path(self.request["root"])
        return [
            {"nodeid": item.nodeid, "file": str(item.path.resolve().relative_to(root))}
            for item in items
        ]

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_collection_modifyitems(self, session, config, items):
        self.full = self.rows(items)
        yield
        if self.request["mode"] == "run":
            if self.full != self.request["inventory"] or self.rows(items) != self.full:
                raise pytest.UsageError("full collection mismatch")
            assigned = set(self.request["files"])
            selected = [
                item for item in items if self.rows([item])[0]["file"] in assigned
            ]
            deselected = [
                item for item in items if self.rows([item])[0]["file"] not in assigned
            ]
            if not selected:
                raise pytest.UsageError("zero selection")
            config.hook.pytest_deselected(items=deselected)
            items[:] = selected

    def pytest_collection_finish(self, session):
        selected = self.rows(session.items)
        identity = {
            "cwd": str(Path.cwd()),
            "rootpath": str(self.config.rootpath),
            "inipath": str(self.config.inipath) if self.config.inipath else None,
            "ini": {
                name: self.config.getini(name)
                for name in (
                    "addopts",
                    "testpaths",
                    "markers",
                    "filterwarnings",
                    "xfail_strict",
                    "junit_family",
                    "junit_suite_name",
                    "junit_duration_report",
                )
            }
            | {
                "pythonpath": [
                    str(p.relative_to(Path.cwd()))
                    for p in self.config.getini("pythonpath")
                ]
            },
            "options": {
                name: self.config.getoption(name)
                for name in (
                    "keyword",
                    "markexpr",
                    "importmode",
                    "noconftest",
                    "deselect",
                    "ignore",
                    "ignore_glob",
                    "keepduplicates",
                    "strict_markers",
                    "strict_config",
                    "cov_source",
                    "cov_config",
                    "cov_fail_under",
                )
            },
        }
        if self.request["mode"] == "run" and identity != self.request["identity"]:
            raise pytest.UsageError("collection identity mismatch")
        self.write(
            "selection.json",
            {"inventory": selected, "full": self.full, "identity": identity},
        )

    def pytest_sessionfinish(self, session, exitstatus):
        self.write("finish.json", {"exitstatus": int(exitstatus)})

    def write(self, name, data):
        (Path(self.request["output"]) / name).write_text(self.encode(data) + "\n")
