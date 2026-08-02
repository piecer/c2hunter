from __future__ import annotations

import pytest

from c2hunter_controller.security import Role, SecurityError, require_role, required_role


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/health"),
        ("POST", "/api/v1/sensor-enrollments/one-time-token/claim"),
        ("POST", "/api/v1/sensors/register"),
        ("POST", "/api/v1/sensors/sensor-1/heartbeat"),
        ("POST", "/api/v1/sensors/sensor-1/flow-batches"),
        ("GET", "/api/v1/sensors/sensor-1/agent-config"),
        ("PUT", "/api/v1/sensors/sensor-1/pcap-segments/segment-1"),
    ],
)
def test_sensor_authenticated_and_operational_routes_do_not_require_human_roles(
    method: str, path: str
) -> None:
    assert required_role(method, path) is None


@pytest.mark.parametrize(
    ("method", "path", "role"),
    [
        ("GET", "/api/v1/dashboard", Role.VIEWER),
        ("POST", "/api/v1/analysis-jobs", Role.ANALYST),
        ("DELETE", "/api/v1/candidates/candidate-1", Role.ANALYST),
        ("POST", "/api/v1/sensor-enrollments", Role.ADMIN),
        ("PUT", "/api/v1/sensors/sensor-1/configuration", Role.ADMIN),
        ("POST", "/api/v1/sensors/sensor-1/credentials/rotate", Role.ADMIN),
    ],
)
def test_human_routes_have_explicit_minimum_roles(method: str, path: str, role: Role) -> None:
    assert required_role(method, path) is role


def test_lower_role_cannot_satisfy_higher_role() -> None:
    from c2hunter_controller.security import Principal

    with pytest.raises(SecurityError) as error:
        require_role(Principal("viewer", Role.VIEWER), Role.ANALYST)

    assert error.value.status == 403
    assert error.value.code == "INSUFFICIENT_ROLE"
