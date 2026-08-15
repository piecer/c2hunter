import pytest
from pydantic import ValidationError

from c2hunter_controller.schemas import AnalysisParameters


def test_population_anomaly_defaults_are_safe() -> None:
    parameters = AnalysisParameters()

    assert parameters.ml_anomaly_enabled is False
    assert parameters.ml_anomaly_allow_standalone is False
    assert parameters.ml_anomaly_min_population == 30
    assert parameters.ml_anomaly_z_threshold == 3.5
    assert parameters.ml_anomaly_contribution_cap == 5.0


def test_population_anomaly_can_be_enabled_explicitly() -> None:
    parameters = AnalysisParameters.model_validate(
        {
            "ml_anomaly_enabled": True,
            "ml_anomaly_allow_standalone": True,
            "ml_anomaly_min_population": 40,
            "ml_anomaly_z_threshold": 4.0,
            "ml_anomaly_min_directional_features": 3,
            "ml_anomaly_contribution_cap": 3.0,
        }
    )

    assert parameters.ml_anomaly_enabled is True
    assert parameters.ml_anomaly_allow_standalone is True
    assert parameters.ml_anomaly_min_population == 40
    assert parameters.ml_anomaly_contribution_cap == 3.0


def test_population_anomaly_contribution_cannot_exceed_safe_cap() -> None:
    with pytest.raises(ValidationError):
        AnalysisParameters.model_validate({"ml_anomaly_contribution_cap": 6.0})
