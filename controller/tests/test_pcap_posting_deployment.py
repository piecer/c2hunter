from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from c2hunter_controller.config import Settings

ROOT = Path(__file__).parents[2]
ENV_EXAMPLE = ROOT / ".env.example"
COMPOSE = ROOT / "docker-compose.yml"
POSTING_FIELDS = tuple(
    name for name in Settings.model_fields if name.startswith("pcap_posting_index_")
)
POSTING_ENV = {f"C2HUNTER_{name.upper()}" for name in POSTING_FIELDS}
CONTROLLER_POSTING_ENV = {
    "C2HUNTER_PCAP_POSTING_INDEX_ENABLED",
    "C2HUNTER_PCAP_POSTING_INDEX_QUEUE_CAPACITY",
    "C2HUNTER_PCAP_POSTING_INDEX_MAX_ATTEMPTS",
}


def _assignments() -> dict[str, str]:
    return {
        key: value
        for line in ENV_EXAMPLE.read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
        for key, _, value in (line.partition("="),)
    }


def _rendered_compose() -> dict[str, object]:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ENV_EXAMPLE),
            "-f",
            str(COMPOSE),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_env_example_declares_every_posting_setting_with_safe_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assignments = _assignments()
    assert POSTING_ENV <= assignments.keys()
    assert assignments["C2HUNTER_PCAP_POSTING_INDEX_ENABLED"] == "false"
    assert assignments["C2HUNTER_PCAP_POSTING_INDEX_BACKFILL_ENABLED"] == "false"
    assert not any("PASSWORD" in key or "SECRET" in key or "API_KEY" in key for key in POSTING_ENV)

    for key in tuple(os.environ):
        if key.startswith("C2HUNTER_PCAP_POSTING_INDEX_"):
            monkeypatch.delenv(key, raising=False)
    for key in POSTING_ENV:
        monkeypatch.setenv(key, assignments[key])
    settings = Settings(environment="test")
    defaults = Settings(environment="test")
    for field in POSTING_FIELDS:
        assert getattr(settings, field) == getattr(defaults, field)


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "C2HUNTER_PCAP_POSTING_INDEX_WORKER_CONCURRENCY": "2",
            "C2HUNTER_PCAP_POSTING_INDEX_QUEUE_CAPACITY": "1",
        },
        {
            "C2HUNTER_PCAP_POSTING_INDEX_HEARTBEAT_INTERVAL_SECONDS": "61",
            "C2HUNTER_PCAP_POSTING_INDEX_LEASE_SECONDS": "120",
        },
        {
            "C2HUNTER_PCAP_POSTING_INDEX_OPERATION_TIMEOUT_SECONDS": "120",
            "C2HUNTER_PCAP_POSTING_INDEX_LEASE_SECONDS": "120",
        },
    ],
)
def test_posting_env_invalid_cross_fields_fail(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str]
) -> None:
    for key in tuple(os.environ):
        if key.startswith("C2HUNTER_PCAP_POSTING_INDEX_"):
            monkeypatch.delenv(key, raising=False)
    for key, value in _assignments().items():
        if key in POSTING_ENV:
            monkeypatch.setenv(key, value)
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValidationError):
        Settings(environment="test")


def test_rendered_compose_preserves_joint_worker_shape_and_exact_posting_env() -> None:
    rendered = _rendered_compose()
    services = rendered["services"]
    assert isinstance(services, dict)
    assert set(services) == {
        "postgres",
        "redis",
        "clickhouse",
        "minio",
        "controller",
        "worker",
        "pcap-export-worker",
        "pcap-offset-index-worker",
        "web",
    }

    controller = services["controller"]
    joint_worker = services["pcap-offset-index-worker"]
    assert isinstance(controller, dict) and isinstance(joint_worker, dict)
    assert controller["environment"].keys() & POSTING_ENV == CONTROLLER_POSTING_ENV
    assert joint_worker["environment"].keys() & POSTING_ENV == POSTING_ENV
    assert joint_worker["command"] == [
        "python",
        "-m",
        "c2hunter_controller.pcap_offset_index_worker",
        "run",
    ]
    assert joint_worker["expose"] == ["9104"]
    assert joint_worker["environment"]["C2HUNTER_PCAP_OFFSET_INDEX_METRICS_PORT"] == "9104"
    assert "C2HUNTER_PCAP_POSTING_INDEX_METRICS_PORT" not in joint_worker["environment"]
    assert joint_worker["environment"]["C2HUNTER_PCAP_POSTING_INDEX_ENABLED"] == "false"
    assert joint_worker["environment"]["C2HUNTER_PCAP_POSTING_INDEX_BACKFILL_ENABLED"] == "false"
    assert all(isinstance(joint_worker["environment"][key], str) for key in POSTING_ENV)
    assert "depends_on" in joint_worker and "healthcheck" in joint_worker
