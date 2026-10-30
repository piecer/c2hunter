"""The real authenticated API supplies policy context, not request fields."""

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository
from tests.test_operational_sensor_api import register, sensor_payload
from tests.test_postgres_heartbeat_audit import telemetry


def test_api_passes_configured_heartbeat_audit_thresholds(monkeypatch):
    repo = MemoryRepository()
    app = create_app(
        Settings(environment="test", clock_skew_threshold_seconds=7, heartbeat_timeout_seconds=41),
        repo,
    )
    captured = []
    original = repo.update_sensor_heartbeat

    def observe(sensor_id, fields, **context):
        captured.append(context)
        return original(sensor_id, fields, **context)

    monkeypatch.setattr(repo, "update_sensor_heartbeat", observe)
    with TestClient(app) as api:
        assert register(api, sensor_payload("heartbeat"))[0].status_code == 201
        fields = telemetry()
        for name in (
            "sensor_id",
            "last_heartbeat_at",
            "clock_offset_ms",
            "reported_status",
            "derived_status",
            "config_version",
            "capture_sources",
        ):
            fields.pop(name)
        fields["interfaces"][0]["direction"] = "OUTBOUND"
        response = api.post(
            "/api/v1/sensors/heartbeat/heartbeat",
            json=fields,
            headers={"X-Sensor-Token": "token-heartbeat"},
        )
        assert response.status_code == 200
    assert captured == [{"clock_skew_threshold_seconds": 7, "heartbeat_timeout_seconds": 41}]
