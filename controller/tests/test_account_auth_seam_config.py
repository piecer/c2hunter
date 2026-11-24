"""Legacy fixture opt-out must not relax inferred account-mode guardrails."""

import pytest

from c2hunter_controller.config import Settings


@pytest.mark.parametrize("environment", ["development", "test"])
def test_explicit_account_mode_still_refuses_dev_login(environment):
    with pytest.raises(ValueError, match="dev_login_enabled"):
        Settings(
            environment=environment,
            account_auth_enabled=True,
            api_auth_required=True,
            dev_login_enabled=True,
        )


def test_development_still_infers_account_mode_and_refuses_dev_login():
    assert Settings(environment="development").account_auth_enabled is True
    with pytest.raises(ValueError, match="dev_login_enabled"):
        Settings(environment="development", dev_login_enabled=True)
