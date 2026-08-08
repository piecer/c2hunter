"""Validate high-volume TCP session analysis parameters."""

import pytest

from c2hunter_controller.schemas import AnalysisParameters


def test_high_volume_tcp_session_defaults_are_safe() -> None:
    parameters = AnalysisParameters()

    assert parameters.high_volume_tcp_session_bytes_threshold == 50 * 1024 * 1024
    assert parameters.high_volume_tcp_session_packet_threshold == 100_000
    assert parameters.high_volume_tcp_session_score_cap == 20


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("high_volume_tcp_session_bytes_threshold", -1),
        ("high_volume_tcp_session_packet_threshold", -1),
        ("high_volume_tcp_session_score_cap", -1),
        ("high_volume_tcp_session_score_cap", 101),
    ],
)
def test_high_volume_tcp_session_parameters_reject_invalid_values(field: str, value: int) -> None:
    with pytest.raises(ValueError):
        AnalysisParameters(**{field: value})


def test_high_volume_tcp_session_thresholds_can_be_disabled() -> None:
    parameters = AnalysisParameters(
        high_volume_tcp_session_bytes_threshold=0,
        high_volume_tcp_session_packet_threshold=0,
        high_volume_tcp_session_score_cap=0,
    )

    assert parameters.high_volume_tcp_session_bytes_threshold == 0
    assert parameters.high_volume_tcp_session_packet_threshold == 0
    assert parameters.high_volume_tcp_session_score_cap == 0
