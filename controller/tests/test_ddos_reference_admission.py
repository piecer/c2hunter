import struct
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient
from test_analysis_history_pcap_api import _udp_packet
from test_ddos_attack_api import ddos_payload

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def capture(offset=0):
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for sample in range(12):
        packet = _udp_packet(f"10.0.0.{sample + 1}", "203.0.113.77", 50000 + sample, sample + 1)
        content.extend(
            struct.pack("<IIII", 1784505600 + sample + offset, 0, len(packet), len(packet))
        )
        content.extend(packet)
    return bytes(content)


def test_real_offline_pcap_reference_and_query_selection():
    repo = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repo))
    url = (
        "/api/v1/pcap-analysis-jobs?name=offline&filename=offline.pcap"
        "&analysis_module=ddos_attack&ddos_min_source_count=3&ddos_min_packet_count=6"
        "&ddos_min_packets_per_second=1&ddos_min_bits_per_second=1"
    )
    headers = {"content-type": "application/vnd.tcpdump.pcap"}
    normal = client.post(url, content=capture(), headers=headers)
    assert normal.status_code == 201, normal.text
    normal = normal.json()
    selected = (
        url
        + f"&ddos_normal_reference_job_id={normal['id']}"
        + f"&ddos_normal_reference_dataset_id={normal['dataset_id']}"
    )
    attack = client.post(selected, content=capture(60), headers=headers)
    assert attack.status_code == 201, attack.text
    evaluation = attack.json()["ddos_attack"]["findings"][0]["signature_candidates"][0][
        "evaluation"
    ]
    assert evaluation["normal"]["status"] == "MEASURED"
    assert evaluation["normal"]["result"]["matched_packets"] == 12
    assert evaluation["normal"]["result"]["eligible_packets"] == 12
    assert "ddos_reference_snapshot" not in str(client.get("/api/v1/analysis-jobs").json())


@pytest.mark.parametrize("sqlite", [False, True])
@pytest.mark.parametrize(
    "fault", ["missing", "foreign", "unfinished", "partial", "too_many", "same"]
)
def test_reference_rejection_before_job_admission(tmp_path, sqlite, fault):
    repo = SQLiteRepository(tmp_path / "db") if sqlite else MemoryRepository()
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    source = client.post("/api/v1/analysis-jobs", json=ddos_payload("source")).json()
    stored = repo.get_job(source["id"])
    selection = {"job_id": source["id"], "dataset_id": source["dataset_id"]}
    if fault == "missing":
        selection["job_id"] = "missing"
    elif fault == "foreign":
        selection["dataset_id"] = "not-that-dataset"
    elif fault == "unfinished":
        stored["status"] = "ANALYZING"
    elif fault == "partial":
        stored["ddos_coverage_context"]["capture_partial"] = True
    elif fault == "too_many":
        stored["flow_records"] = [deepcopy(stored["flow_records"][0]) for _ in range(513)]
    repo.save_job(stored)
    before = len(repo.list_jobs())
    if fault == "same":
        response = client.post(
            f"/api/v1/analysis-jobs/{source['id']}/reanalyze",
            json={"idempotency_key": "new", "ddos_normal_reference": selection},
        )
    else:
        response = client.post(
            "/api/v1/analysis-jobs",
            json={**ddos_payload("new"), "ddos_normal_reference": selection},
        )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"].startswith("DDOS_REFERENCE_")
    assert len(repo.list_jobs()) == before
    if sqlite:
        repo.close()


def test_rbac_denies_reference_acquisition_before_repository_read(monkeypatch):
    import hashlib

    repo = MemoryRepository()
    repo.upsert_sensor({"sensor_id": "s1"})
    settings = Settings(
        environment="test",
        api_auth_required=True,
        viewer_token_sha256=hashlib.sha256(b"viewer-test").hexdigest(),
        analyst_token_sha256=hashlib.sha256(b"analyst-test").hexdigest(),
    )
    client = TestClient(create_app(settings, repo))
    calls = []

    def spy(*args):
        calls.append(args)
        raise ValueError("must not acquire")

    monkeypatch.setattr(repo, "read_ddos_reference", spy)
    request = {
        **ddos_payload("auth"),
        "ddos_normal_reference": {"job_id": "source", "dataset_id": "dataset"},
    }
    for headers, code in [({}, 401), ({"Authorization": "Bearer viewer-test"}, 403)]:
        response = client.post("/api/v1/analysis-jobs", json=request, headers=headers)
        assert response.status_code == code
        assert not calls and not repo.list_jobs()
    monkeypatch.undo()
    source = client.post(
        "/api/v1/analysis-jobs",
        json=ddos_payload("source"),
        headers={"Authorization": "Bearer analyst-test"},
    )
    assert source.status_code == 201, source.text
    source = source.json()
    request["ddos_normal_reference"] = {"job_id": source["id"], "dataset_id": source["dataset_id"]}
    response = client.post(
        "/api/v1/analysis-jobs", json=request, headers={"Authorization": "Bearer analyst-test"}
    )
    assert response.status_code == 201, response.text
    assert (
        response.json()["ddos_attack"]["findings"][0]["signature_candidates"][0]["evaluation"][
            "normal"
        ]["reference"]["selected_by"]
        != "system"
    )


def test_sqlite_byte_limit_precedes_body_hydration(tmp_path):
    from c2hunter_controller.ddos_reference import MAX_SOURCE_BYTES, ReferenceError

    repo = SQLiteRepository(tmp_path / "bounds.db")
    job = {
        "id": "source",
        "dataset_id": "dataset",
        "status": "COMPLETED",
        "flow_records": [{"packet_count": 1}],
    }
    repo.save_job(job)
    import json

    raw = json.dumps(job["flow_records"])
    # Exact SQL transfer boundary, including whitespace (valid source JSON).
    exact = raw + " " * (MAX_SOURCE_BYTES - len(raw))
    with repo.connection:
        repo.connection.execute(
            "UPDATE job_flow_records SET data=? WHERE job_id='source'", (exact,)
        )
    assert len(repo.read_ddos_reference("source", "dataset")["records"]) == 1
    with repo.connection:
        repo.connection.execute(
            "UPDATE job_flow_records SET data=? WHERE job_id='source'", (exact + " ",)
        )
    statements = []
    repo.connection.set_trace_callback(statements.append)
    with pytest.raises(ReferenceError, match="BYTE_LIMIT"):
        repo.read_ddos_reference("source", "dataset")
    assert not any(q.startswith("SELECT data FROM job_flow_records") for q in statements)
    repo.close()


def test_idempotency_cannot_silently_discard_requested_reference():
    repo = MemoryRepository()
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    source = client.post("/api/v1/analysis-jobs", json=ddos_payload("source")).json()
    client.post("/api/v1/analysis-jobs", json=ddos_payload("same-key"))
    request = {
        **ddos_payload("same-key"),
        "ddos_normal_reference": {"job_id": source["id"], "dataset_id": source["dataset_id"]},
    }
    response = client.post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 409, response.text
    assert len(repo.list_jobs()) == 2


def test_c2_never_silently_ignores_reference():
    repo = MemoryRepository()
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    request = ddos_payload()
    request["analysis"] = {"module": "c2"}
    request["ddos_normal_reference"] = None
    response = client.post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 422
    assert repo.list_jobs() == []
    response = client.post(
        "/api/v1/pcap-analysis-jobs?name=a&filename=a.pcap&ddos_normal_reference_job_id=x&ddos_normal_reference_dataset_id=y",
        content=capture(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 422
    assert repo.list_jobs() == []
