"""Account-mode deployment contracts; no containers or service connections."""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from c2hunter_controller.config import Settings

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
ACCOUNT_ENV = "C2HUNTER_ACCOUNT_AUTH_ENABLED"
CONTROLLER_SERVICES = (
    "postgres-migrate",
    "controller",
    "pcap-export-worker",
    "pcap-offset-index-worker",
    "ai-worker",
)


def _service_blocks() -> dict[str, str]:
    sections = re.split(r"(?m)^  (?=[a-z][a-z-]*:)", COMPOSE.read_text())
    return {
        section.partition(":\n")[0]: section
        for section in sections
        if ":\n" in section and not section.startswith("services:")
    }


@pytest.mark.parametrize("service", CONTROLLER_SERVICES)
def test_every_controller_image_consumer_propagates_account_mode(service: str) -> None:
    block = _service_blocks()[service]
    assert "dockerfile: scripts/controller.Dockerfile" in block
    assert f'      {ACCOUNT_ENV}: "${{{ACCOUNT_ENV}:-true}}"' in block
    assert "C2HUNTER_AUTH_DATABASE_PATH" not in block


def test_controller_propagates_explicit_origin_and_safe_loopback_default() -> None:
    controller = _service_blocks()["controller"]
    assert 'C2HUNTER_AUTH_PUBLIC_ORIGIN: "${C2HUNTER_AUTH_PUBLIC_ORIGIN:-}"' in controller
    assert (
        'C2HUNTER_AUTH_INSECURE_LOOPBACK_HTTP: "${C2HUNTER_AUTH_INSECURE_LOOPBACK_HTTP:-false}"'
        in controller
    )


def _rendered_compose(tmp_path: Path, overrides: dict[str, str]) -> dict[str, Any]:
    # Same daemon-free `compose config --format json` interface as posting deployment
    # tests, but never read the operator's .env or template credential values.
    fixture = tmp_path / "compose.env"
    values = {
        name: secrets.token_hex(16)
        for name in (
            "POSTGRES_PASSWORD",
            "CLICKHOUSE_PASSWORD",
            "MINIO_ROOT_USER",
            "MINIO_ROOT_PASSWORD",
        )
    }
    values.update(overrides)
    fixture.write_text("".join(f"{name}={value}\n" for name, value in values.items()))
    fixture.chmod(0o600)
    config = tmp_path / "docker"
    config.mkdir()
    child_env = {
        name: os.environ[name]
        for name in ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL")
        if name in os.environ
    }
    child_env.update(
        DOCKER_HOST="unix:///unavailable-account-deployment-test.sock",
        DOCKER_CONFIG=str(config),
    )
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(fixture),
            "-f",
            str(COMPOSE),
            "--project-name",
            "c2hunter-auth-test",
            "--profile",
            "ai",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=child_env,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(result.stdout)["services"]


def _settings(monkeypatch: pytest.MonkeyPatch, environment: dict[str, str]) -> Settings:
    with monkeypatch.context() as clean:
        for name in tuple(os.environ):
            if name.startswith("C2HUNTER_"):
                clean.delenv(name)
        for name, value in environment.items():
            if name.startswith("C2HUNTER_"):
                clean.setenv(name, value)
        return Settings(_env_file=None)


@pytest.mark.parametrize("value", [None, "", "true", "false"])
def test_rendered_mode_and_postgres_are_shared_without_device_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    value: str | None,
) -> None:
    overrides = {"C2HUNTER_AUTH_PUBLIC_ORIGIN": "https://hunter.example.test"}
    if value is not None:
        overrides[ACCOUNT_ENV] = value
    services = _rendered_compose(tmp_path, overrides)
    expected = "false" if value == "false" else "true"
    consumers = {
        name
        for name, service in services.items()
        if service.get("build", {}).get("dockerfile") == "scripts/controller.Dockerfile"
    }
    assert consumers == set(CONTROLLER_SERVICES)
    assert set(services) == {
        *CONTROLLER_SERVICES,
        "postgres",
        "redis",
        "clickhouse",
        "minio",
        "worker",
        "web",
    }
    dsn = services["controller"]["environment"]["C2HUNTER_DATABASE_URL"]
    assert dsn.startswith("postgresql://")
    for name in CONTROLLER_SERVICES:
        environment = services[name]["environment"]
        assert environment[ACCOUNT_ENV] == expected
        assert environment["C2HUNTER_DATABASE_URL"] == dsn
        assert "C2HUNTER_AUTH_DATABASE_PATH" not in environment
        settings = _settings(monkeypatch, environment)
        assert settings.account_auth_enabled is (expected == "true")
        assert settings.api_auth_required is True
        assert settings.dev_login_enabled is False
        assert settings.database_url == dsn
    sensor_worker = services["worker"]
    assert sensor_worker["build"]["dockerfile"] == "scripts/worker.Dockerfile"
    assert set(sensor_worker["environment"]) == {"C2HUNTER_REDIS_URL", "C2HUNTER_DATABASE_URL"}
    assert sensor_worker["environment"]["C2HUNTER_DATABASE_URL"] == dsn
    assert services["postgres-migrate"]["command"] == [
        "python",
        "-m",
        "c2hunter_controller.migrate",
    ]
    assert all("auth_cli" not in str(service.get("command", "")) for service in services.values())
    assert services["ai-worker"]["profiles"] == ["ai"]


@pytest.mark.parametrize("origin", [None, ""])
def test_missing_public_origin_is_setup_required_configuration_not_invalid_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    origin: str | None,
) -> None:
    overrides = {} if origin is None else {"C2HUNTER_AUTH_PUBLIC_ORIGIN": origin}
    environment = _rendered_compose(tmp_path, overrides)["controller"]["environment"]
    assert environment["C2HUNTER_AUTH_PUBLIC_ORIGIN"] == ""
    assert environment["C2HUNTER_AUTH_INSECURE_LOOPBACK_HTTP"] == "false"
    settings = _settings(monkeypatch, environment)
    assert settings.account_auth_enabled is True
    assert settings.auth_public_origin is None
    assert settings.auth_insecure_loopback_http is False


@pytest.mark.parametrize(
    "origin, insecure, port",
    [
        ("https://hunter.example.test", "false", "8080"),
        ("https://hunter.example.test:9443", "false", "8080"),
        ("http://127.0.0.1:9001", "true", "9001"),
    ],
)
def test_rendered_controller_origin_preserves_external_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    origin: str,
    insecure: str,
    port: str,
) -> None:
    services = _rendered_compose(
        tmp_path,
        {
            "C2HUNTER_AUTH_PUBLIC_ORIGIN": origin,
            "C2HUNTER_AUTH_INSECURE_LOOPBACK_HTTP": insecure,
            "WEB_PORT": port,
        },
    )
    settings = _settings(monkeypatch, services["controller"]["environment"])
    assert settings.auth_public_origin == origin
    assert settings.auth_insecure_loopback_http is (insecure == "true")
    assert services["web"]["ports"][0]["published"] == port
    assert services["web"]["ports"][0]["target"] == 8080


@pytest.mark.parametrize(
    "overrides",
    [
        {"C2HUNTER_DEV_LOGIN_ENABLED": "true"},
        {"C2HUNTER_API_AUTH_REQUIRED": "false"},
        {ACCOUNT_ENV: "false", "C2HUNTER_API_AUTH_REQUIRED": "false"},
        {
            "C2HUNTER_AUTH_PUBLIC_ORIGIN": "http://hunter.example.test",
            "C2HUNTER_AUTH_INSECURE_LOOPBACK_HTTP": "true",
        },
        {"C2HUNTER_AUTH_PUBLIC_ORIGIN": "http://127.0.0.1:9001"},
        {"C2HUNTER_AUTH_PUBLIC_ORIGIN": "https://hunter.example.test/api"},
        {"C2HUNTER_AUTH_PUBLIC_ORIGIN": "https://hunter.example.test:443"},
        {ACCOUNT_ENV: "invalid-boolean"},
        {"C2HUNTER_AUTH_INSECURE_LOOPBACK_HTTP": "invalid-boolean"},
    ],
)
def test_rendered_insecure_or_malformed_configuration_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, str],
) -> None:
    values = {"C2HUNTER_AUTH_PUBLIC_ORIGIN": "https://hunter.example.test", **overrides}
    environment = _rendered_compose(tmp_path, values)["controller"]["environment"]
    with pytest.raises(ValidationError):
        _settings(monkeypatch, environment)


def test_legacy_dev_login_requires_account_opt_out_and_explicit_dev_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    services = _rendered_compose(
        tmp_path,
        {
            ACCOUNT_ENV: "false",
            "C2HUNTER_DEV_LOGIN_ENABLED": "true",
            "C2HUNTER_AUTH_PUBLIC_ORIGIN": "https://hunter.example.test",
        },
    )
    settings = _settings(monkeypatch, services["controller"]["environment"])
    assert settings.account_auth_enabled is False
    assert settings.api_auth_required is True
    assert settings.dev_login_enabled is True
    assert all(
        services[name]["environment"][ACCOUNT_ENV] == "false" for name in CONTROLLER_SERVICES
    )
