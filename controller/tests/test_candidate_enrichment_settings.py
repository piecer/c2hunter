"""Candidate enrichment configuration validation tests."""

import pytest
from pydantic import ValidationError

from c2hunter_controller.config import Settings


def test_candidate_integration_secrets_are_masked() -> None:
    settings = Settings(
        environment="test",
        virustotal_api_key="vt-secret",
        abuseipdb_api_key="abuse-secret",
        misp_api_key="misp-secret",
    )

    assert settings.virustotal_api_key.get_secret_value() == "vt-secret"
    representation = repr(settings)
    assert "vt-secret" not in representation
    assert "abuse-secret" not in representation
    assert "misp-secret" not in representation


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("threat_intel_timeout_seconds", 0),
        ("threat_intel_timeout_seconds", 31),
        ("abuseipdb_max_age_days", 0),
        ("abuseipdb_max_age_days", 366),
    ],
)
def test_candidate_integration_numeric_bounds(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(environment="test", **{field: value})
