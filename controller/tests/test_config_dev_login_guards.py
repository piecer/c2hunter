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
