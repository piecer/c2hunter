"""Synthetic inventory through real models and public TestClient producers; no physical sensor."""
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DENIED = []


def audit(event, args):
    if event in {"socket.bind", "socket.connect", "socket.connect_ex", "socket.getaddrinfo", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        DENIED.append(event)
        raise RuntimeError("Sensor fixture denies network/process operation: " + event)


sys.addaudithook(audit)
sys.path[:0] = [str(ROOT / part) for part in ("controller/src", "analysis/src", "sensor/worker/src")]
from fastapi.testclient import TestClient
import c2hunter_controller.app as app_module
import c2hunter_controller.schemas as schemas
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


def generate():
    repo = MemoryRepository()
    client = TestClient(app_module.create_app(Settings(_env_file=None, environment="test", database_url="memory://", clickhouse_url="memory://", redis_url="memory://", s3_endpoint="memory://", ai_analysis_enabled=False), repo))
    try:
        configuration = schemas.SensorConfiguration(
            capture_sources=[{"interface": f"eth{i}", "direction": "INBOUND", "bpf_filter": "tcp", "enabled": True, "store_pcap": False} for i in range(128)],
            internal_networks=[f"10.{i // 256}.{i % 256}.0/24" for i in range(1024)],
        ).model_dump(mode="json")
        created = client.post('/api/v1/sensor-enrollments', json={**configuration, "name": "Maximum synthetic sensor", "expires_in_seconds": 3600})
        assert created.status_code == 201, created.text
        claimed = client.post('/api/v1/sensor-enrollments/' + created.json()['enrollment_token'] + '/claim', json={"hostname": "synthetic.invalid", "agent_version": "synthetic-agent-1", "os_version": "Linux", "kernel_version": "synthetic", "discovered_interfaces": [{"name": f"eth{i}"} for i in range(128)]})
        assert claimed.status_code == 201, claimed.text
        sensor_id = claimed.json()['sensor_id']
        heartbeat = schemas.Heartbeat(reported_at=datetime.now(UTC), status="ERROR", cpu_percent=10, memory_percent=20, disk_percent=30, active_job_ids=[], received_packets=128, dropped_packets=128, pending_bytes=0, interfaces=[{"interface": f"eth{i}", "direction": "OUTBOUND", "status": "ERROR", "received_packets": i, "dropped_packets": 1, "last_error": f"synthetic-error-{i}"} for i in range(128)])
        observed = client.post(f'/api/v1/sensors/{sensor_id}/heartbeat', headers={"X-Sensor-Token": claimed.json()['agent_token']}, json=heartbeat.model_dump(mode="json"))
        assert observed.status_code == 200, observed.text
        maximum = client.get(f'/api/v1/sensors/{sensor_id}').json()
        request = schemas.SensorConfigurationUpdate(config_version=1, **configuration).model_dump(mode="json")
        saved = client.put(f'/api/v1/sensors/{sensor_id}/configuration', json=request)
        assert saved.status_code == 200, saved.text
        schemas.SensorConfigurationResponse.model_validate(saved.json())
        assert saved.json()['config_version'] == 2
        now = datetime.now(UTC)
        for i in range(250):
            sid = f"synthetic-{i:03}"
            repo.upsert_sensor({"sensor_id": sid, "name": f"Synthetic sensor {i}", "derived_status": "ONLINE", "interfaces": [], "agent_version": "synthetic", "last_heartbeat_at": now.isoformat()})
            repo.create_enrollment({"enrollment_id": f"enrollment-{i:03}", "name": f"Synthetic enrollment {i}", "created_at": (now - timedelta(seconds=i)).isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(), "claimed_at": None, "revoked_at": None, "sensor_id": None})
        for i in range(251):
            metadata = schemas.SensorPcapMetadata(id=f"pcap-{i:03}", sensor_id=sensor_id, sensor_name="Maximum synthetic sensor", analysis_job_id="synthetic-job", filename=f"synthetic-{i:03}.pcap", size_bytes=24, sha256=hashlib.sha256(bytes(24)).hexdigest(), uploaded_at=now - timedelta(seconds=i)).model_dump(mode="json")
            repo.save_sensor_pcap(metadata, bytes(24))
        paths = {}
        for endpoint, filters in [("sensors", ""), ("sensor-enrollments", ""), ("sensor-pcaps", ""), ("sensor-pcaps", "analysis_job_id=synthetic-job&"), ("sensor-pcaps", f"sensor_id={sensor_id}&analysis_job_id=synthetic-job&")]:
            seen = []
            for page in range(1, 7):
                path = f'/api/v1/{endpoint}?{filters}page={page}&page_size=50'
                response = client.get(path)
                assert response.status_code == 200, response.text
                body = response.json()
                assert body['page'] == page and body['page_size'] == 50 and body['total'] == 251
                seen.extend(body['items'])
                paths[path] = body
            assert len(seen) == 251
        path = '/api/v1/sensors?status=ERROR&page=1&page_size=50'
        paths[path] = client.get(path).json()
        assert paths[path]['total'] == 1
        origins = {}
        for module in (app_module, schemas):
            path = Path(module.__file__).resolve()
            assert path.is_relative_to(ROOT)
            origins[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert not DENIED
        return {"provenance": "Synthetic model-valid input; real public TestClient responses. No physical sensor or valid packet capture claim.", "maximum": maximum, "request": request, "ack": saved.json(), "pages": paths, "producer_origins": origins, "denied_operations": DENIED}
    finally:
        client.close()
        repo.close()


if __name__ == '__main__':
    print(json.dumps(generate()))
