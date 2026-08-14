"""Verify that dev-login is blocked in non-development environments."""

from __future__ import annotations

import pytest

from c2hunter_controller.config import Settings


def test_dev_login_allowed_in_development() -> None:
    """Dev login must work when environment is development and the flag is set."""
    settings = Settings(environment="development", dev_login_enabled=True)
    assert settings.dev_login_enabled is True
    assert settings.environment == "development"


def test_dev_login_default_is_disabled() -> None:
    """Python-level default must be False so bare instantiations stay secure."""
    settings = Settings(environment="development")
    assert settings.dev_login_enabled is False


@pytest.mark.parametrize("env", ["production", "staging"])
def test_dev_login_blocked_in_non_development(env: str) -> None:
    """Settings must refuse dev_login_enabled=True outside development/test."""
    with pytest.raises(ValueError, match="dev_login_enabled"):
        Settings(environment=env, dev_login_enabled=True)


def test_dev_login_allowed_in_test_environment() -> None:
    """Test environment is allowed to use dev login for unit testing."""
    settings = Settings(environment="test", dev_login_enabled=True)
    assert settings.dev_login_enabled is True


def test_dev_login_disabled_in_production_ok() -> None:
    """Production with dev_login disabled must configure without error."""
    settings = Settings(environment="production", dev_login_enabled=False)
    assert settings.dev_login_enabled is False


def test_trusted_proxy_cidrs_are_validated() -> None:
    """Only syntactically valid CIDRs may become trusted proxy boundaries."""
    settings = Settings(environment="test", trusted_proxy_cidrs="127.0.0.1/32, 10.0.0.0/8")
    assert settings.trusted_proxy_networks == ("127.0.0.1/32", "10.0.0.0/8")

    with pytest.raises(ValueError, match="trusted_proxy_cidrs"):
        Settings(environment="test", trusted_proxy_cidrs="not-a-network")


def test_remote_openai_compatible_endpoint_is_classified_for_warning() -> None:
    """Hosted AI endpoints must be visible to startup logging and operators."""
    remote = Settings(
        environment="test",
        ai_model_provider="openai-compatible",
        ai_model_base_url="https://api.example.com/v1",
    )
    local = Settings(
        environment="test",
        ai_model_provider="openai-compatible",
        ai_model_base_url="http://10.0.0.10:11434/v1",
    )

    assert remote.ai_model_endpoint_is_remote is True
    assert local.ai_model_endpoint_is_remote is False


def test_remote_ollama_endpoint_is_classified_but_docker_host_is_local() -> None:
    remote = Settings(
        environment="test",
        ai_model_provider="ollama",
        ai_model_base_url="https://ollama.example.com",
    )
    docker_host = Settings(
        environment="test",
        ai_model_provider="ollama",
        ai_model_base_url="http://host.docker.internal:11434",
    )

    assert remote.ai_model_endpoint_is_remote is True
    assert docker_host.ai_model_endpoint_is_remote is False


@pytest.mark.parametrize(
    "url",
    ["file:///tmp/model", "https://user:password@example.com/v1", "not-a-url"],
)
def test_ai_model_endpoint_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValueError, match="ai_model_base_url"):
        Settings(environment="test", ai_model_base_url=url)
