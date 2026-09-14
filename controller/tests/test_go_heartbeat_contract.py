"""Exercise actual Go HTTP request bytes against the real controller route, offline."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


@pytest.fixture(scope="module")
def heartbeat_wire(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("go-heartbeat-wire")
    subprocess.run(
        [
            "go",
            "test",
            "./internal/transport",
            "-run",
            "^TestWriteHeartbeatWireFixtures$",
            "-count=1",
        ],
        cwd=Path(__file__).resolve().parents[2] / "sensor",
        env={
            **os.environ,
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "C2HUNTER_HEARTBEAT_FIXTURE_DIR": str(directory),
        },
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert {path.name for path in directory.iterdir()} == {
        "nil.json",
        "empty.json",
        "populated.json",
    }
    return directory


@pytest.mark.parametrize("case", ["nil", "empty", "populated"])
def test_go_heartbeat_accepted_without_relaxing_consumer(heartbeat_wire: Path, case: str) -> None:
    wire = (heartbeat_wire / f"{case}.json").read_bytes()
    repository = MemoryRepository()
    repository.upsert_sensor({"sensor_id": "contract-sensor"})
    repository.save_sensor_credential(
        {
            "sensor_id": "contract-sensor",
            "token_hash": hashlib.sha256(b"contract-token").hexdigest(),
        }
    )
    api = TestClient(create_app(Settings(environment="test", _env_file=None), repository))
    url = "/api/v1/sensors/contract-sensor/heartbeat"
    headers = {"Content-Type": "application/json", "X-Sensor-Token": "contract-token"}
    response = api.post(url, content=wire, headers=headers)
    assert response.status_code == 200, response.text
    payload = json.loads(wire)
    assert isinstance(payload["interfaces"], list)
    assert response.json()["interfaces"] == payload["interfaces"]
    stored = repository.get_sensor("contract-sensor")
    assert stored is not None
    assert stored["interfaces"] == payload["interfaces"]
    assert (
        api.post(url, content=wire, headers={"Content-Type": "application/json"}).status_code == 401
    )
    assert (
        api.post(url, content=wire, headers={**headers, "X-Sensor-Token": "wrong"}).status_code
        == 401
    )

    # Strict consumer must still reject null; only the producer should normalize it.
    payload["interfaces"] = None
    assert api.post(url, json=payload, headers=headers).status_code == 422
