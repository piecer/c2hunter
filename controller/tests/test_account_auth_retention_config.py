"""Retention configuration through Settings and actual Compose rendering."""

import pytest
from pydantic import ValidationError
from test_account_auth_deployment import _rendered_compose, _settings

from c2hunter_controller.config import Settings

ENV = "C2HUNTER_AUTH_AUDIT_RETENTION_DAYS"


def test_default_and_environment_days(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert Settings().auth_audit_retention_days == 180
    for value in ("1", "180", "3650"):
        monkeypatch.setenv(ENV, value)
        assert Settings().auth_audit_retention_days == int(value)


@pytest.mark.parametrize("value", [0, -1, 3651, True, False, 1.5, "1.5", "bad"])
def test_rejects_invalid_retention(value):
    with pytest.raises(ValidationError):
        Settings(auth_audit_retention_days=value)


@pytest.mark.parametrize("value", [None, "", "1", "3650"])
def test_compose_controller_retention_reaches_settings(tmp_path, monkeypatch, value):
    overrides = {} if value is None else {ENV: value}
    services = _rendered_compose(tmp_path, overrides)
    environment = services["controller"]["environment"]
    expected = int(value) if value else 180
    assert environment[ENV] == str(expected)
    assert _settings(monkeypatch, environment).auth_audit_retention_days == expected
