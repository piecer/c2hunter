from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


def test_dashboard_prioritizes_operational_health_and_recent_threats() -> None:
    now = datetime.now(UTC)
    repository = MemoryRepository()
    repository.upsert_sensor(
        {
            "sensor_id": "sensor-online",
            "name": "Core sensor",
            "derived_status": "ONLINE",
            "dropped_packets": 7,
        }
    )
    repository.upsert_sensor(
        {
            "sensor_id": "sensor-offline",
            "name": "Branch sensor",
            "derived_status": "OFFLINE",
            "last_heartbeat_at": (now - timedelta(hours=3)).isoformat(),
            "dropped_packets": 3,
        }
    )
    repository.upsert_sensor(
        {
            "sensor_id": "sensor-stale",
            "name": "Stale sensor",
            "derived_status": "ONLINE",
            "last_heartbeat_at": (now - timedelta(minutes=5)).isoformat(),
            "received_packets": 90,
            "dropped_packets": 10,
        }
    )
    repository.jobs = {
        "job-complete": {
            "id": "job-complete",
            "idempotency_key": "complete",
            "name": "Morning hunt",
            "status": "COMPLETED",
            "created_at": (now - timedelta(hours=2)).isoformat(),
            "completed_at": (now - timedelta(hours=1)).isoformat(),
            "candidate_count": 2,
            "packet_count": 1000,
            "flow_count": 100,
        },
        "job-failed": {
            "id": "job-failed",
            "idempotency_key": "failed",
            "name": "Remote sensor hunt",
            "status": "FAILED",
            "created_at": (now - timedelta(hours=4)).isoformat(),
            "completed_at": (now - timedelta(hours=3)).isoformat(),
            "candidate_count": 0,
            "error": "sensor upload failed",
        },
        "job-active": {
            "id": "job-active",
            "idempotency_key": "active",
            "name": "Live hunt",
            "status": "ANALYZING",
            "created_at": (now - timedelta(minutes=20)).isoformat(),
            "candidate_count": 0,
        },
        "job-partial": {
            "id": "job-partial",
            "idempotency_key": "partial",
            "name": "Partial analysis",
            "status": "PARTIALLY_COMPLETED",
            "created_at": (now - timedelta(hours=4)).isoformat(),
            "completed_at": (now - timedelta(hours=3)).isoformat(),
            "candidate_count": 0,
            "error": "One sensor did not upload",
        },
    }
    repository.candidates = {
        "job-complete": [
            {
                "id": "candidate-critical",
                "candidate_ip": "203.0.113.10",
                "score": 91,
                "severity": "CRITICAL",
                "first_seen": (now - timedelta(minutes=40)).isoformat(),
                "last_seen": (now - timedelta(minutes=10)).isoformat(),
                "evidence": [{"type": "PERIODIC_BEACON"}],
            },
            {
                "id": "candidate-low",
                "candidate_ip": "198.51.100.7",
                "score": 24,
                "severity": "LOW",
                "first_seen": (now - timedelta(days=2)).isoformat(),
                "last_seen": (now - timedelta(days=2)).isoformat(),
            },
        ]
    }
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.get("/api/v1/dashboard")

    assert response.status_code == 200, response.text
    dashboard = response.json()
    assert dashboard["fleet"] == {
        "total": 3,
        "online": 1,
        "offline": 2,
        "degraded": 0,
        "dropped_packets": 20,
    }
    assert dashboard["analyses"]["active"] == 1
    assert dashboard["analyses"]["completed_24h"] == 1
    assert dashboard["analyses"]["failed_24h"] == 1
    assert dashboard["analyses"]["partially_completed_24h"] == 1
    assert dashboard["analyses"]["by_status"]["ANALYZING"] == 1
    assert dashboard["analyses"]["by_status"]["WAITING_FOR_SENSOR"] == 0
    assert dashboard["candidates"]["critical"] == 1
    assert dashboard["candidates"]["high"] == 0
    assert dashboard["candidates"]["new_24h"] == 1
    assert sum(bucket["count"] for bucket in dashboard["candidate_trend"]) == 1
    assert len(dashboard["candidate_trend"]) == 24
    assert dashboard["priority_candidates"][0]["id"] == "candidate-critical"
    assert set(dashboard["priority_candidates"][0]) == {
        "id",
        "job_id",
        "candidate_ip",
        "score",
        "severity",
        "last_seen",
        "evidence_count",
    }
    assert dashboard["recent_analyses"][0]["id"] == "job-active"
    assert "transitions" not in dashboard["recent_analyses"][0]
    stale_quality = next(
        sensor for sensor in dashboard["sensor_quality"] if sensor["sensor_id"] == "sensor-stale"
    )
    assert stale_quality == {
        "sensor_id": "sensor-stale",
        "name": "Stale sensor",
        "status": "OFFLINE",
        "received_packets": 90,
        "dropped_packets": 10,
        "drop_rate_percent": 10.0,
        "last_heartbeat_at": repository.sensors["sensor-stale"]["last_heartbeat_at"],
        "last_error": None,
    }
    assert {item["kind"] for item in dashboard["attention"]} == {
        "OFFLINE_SENSOR",
        "PARTIALLY_COMPLETED_ANALYSIS",
        "FAILED_ANALYSIS",
        "CRITICAL_CANDIDATE",
    }


def test_dashboard_attention_preserves_each_operational_category() -> None:
    now = datetime.now(UTC)
    repository = MemoryRepository()
    for index in range(9):
        repository.upsert_sensor(
            {
                "sensor_id": f"offline-{index}",
                "name": f"Offline sensor {index}",
                "derived_status": "OFFLINE",
            }
        )
    repository.jobs = {
        "failed-job": {
            "id": "failed-job",
            "name": "Failed analysis",
            "status": "FAILED",
            "created_at": now.isoformat(),
            "completed_at": now.isoformat(),
        }
    }
    repository.candidates = {
        "failed-job": [
            {
                "id": "critical-candidate",
                "candidate_ip": "203.0.113.20",
                "score": 95,
                "severity": "CRITICAL",
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
            }
        ]
    }
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.get("/api/v1/dashboard")

    assert response.status_code == 200, response.text
    attention_kinds = {item["kind"] for item in response.json()["attention"]}
    assert "OFFLINE_SENSOR" in attention_kinds
    assert "FAILED_ANALYSIS" in attention_kinds
    assert "CRITICAL_CANDIDATE" in attention_kinds
