"""Keep the sensor's resolved dependencies and shipped Go toolchain patched."""

import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GO_VERSION = "1.26.11"
GO_IMAGE = (
    "golang:1.26.11-alpine3.23@sha256:"
    "db99415e2625ce0ee03eed09edf7f32ae8c58dc399f28cc602a87fe7238119e4"
)


def test_x_net_requirement_sets_a_patched_mvs_floor() -> None:
    # A direct requirement floors MVS selection; stale go.sum entries do not.
    # Reading go.mod must also work in a fresh offline CI job without a module cache.
    result = subprocess.run(
        ["go", "mod", "edit", "-json"],
        cwd=ROOT / "sensor",
        env={**os.environ, "GOTOOLCHAIN": "local", "GOPROXY": "off"},
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    manifest = json.loads(result.stdout)
    assert not manifest["Replace"], "A replacement must not bypass the patched module"
    requirements = [item for item in manifest["Require"] if item["Path"] == "golang.org/x/net"]
    assert len(requirements) == 1
    module = requirements[0]
    # GO-2026-6860 (HTML) requires v0.62.0; HTTP/2 was fixed in v0.60.0.
    assert re.fullmatch(r"v\d+\.\d+\.\d+", module["Version"])
    assert tuple(map(int, module["Version"][1:].split("."))) >= (0, 62, 0)


def test_minimum_go_requires_the_patched_standard_library() -> None:
    # The x/net-only fix does not update net/http in older Go toolchains.
    text = (ROOT / "sensor/go.mod").read_text()
    minimum = re.search(r"^go (\d+\.\d+\.\d+)$", text, re.MULTILINE)
    assert minimum, "Require an explicit patched Go release"
    assert minimum[1] == GO_VERSION


def test_every_ci_go_toolchain_matches_the_security_baseline() -> None:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    versions = re.findall(r"go-version:\s*'([^']+)'", text)
    assert versions and len(versions) == text.count("uses: actions/setup-go@")
    assert set(versions) == {GO_VERSION}


def test_sensor_builder_uses_the_verified_go_image_digest() -> None:
    lines = (ROOT / "scripts/sensor.Dockerfile").read_text().splitlines()
    assert lines[0] == f"FROM {GO_IMAGE} AS build"
    assert "RUN CGO_ENABLED=1 go test ./... && CGO_ENABLED=1 go build " in "\n".join(lines)
