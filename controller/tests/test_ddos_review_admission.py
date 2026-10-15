import hashlib
import json
from copy import deepcopy

import pytest
from c2hunter_analysis.ddos_signatures import load_reference
from fastapi.testclient import TestClient
from starlette.requests import Request
from test_ddos_attack_api import ddos_payload
from test_ddos_reference_admission import capture
from test_durable_pipeline import QueueStub

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def setup(tmp_path):
    repo = SQLiteRepository(tmp_path / "additional.db")
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    r = client.post("/api/v1/analysis-jobs", json=ddos_payload("normal"))
    assert r.status_code == 201, r.text
    normal = r.json()
    selection = {"job_id": normal["id"], "dataset_id": normal["dataset_id"]}
    return repo, client, normal, selection


def test_same_reference_idempotent_after_source_delete(tmp_path):
    repo, client, normal, selection = setup(tmp_path)
    payload = {**ddos_payload("attack"), "ddos_normal_reference": selection}
    first = client.post("/api/v1/analysis-jobs", json=payload)
    assert first.status_code == 201
    saved = repo.get_job(first.json()["id"])
    duplicate = client.post("/api/v1/analysis-jobs", json=payload)
    assert duplicate.status_code == 201 and duplicate.json()["id"] == first.json()["id"]
    assert repo.get_job(saved["id"])["ddos_reference_snapshot"] == saved["ddos_reference_snapshot"]
    repo.delete_job(normal["id"])
    after = client.post("/api/v1/analysis-jobs", json=payload)
    assert repo.get_job(saved["id"])["ddos_reference_snapshot"] == saved["ddos_reference_snapshot"]
    repo.close()
    assert after.status_code == 201, after.text
    assert after.json()["id"] == first.json()["id"]


@pytest.mark.parametrize("offset", [0, 60])
def test_staged_upload_same_dataset_admission(tmp_path, offset, monkeypatch):
    repo = SQLiteRepository(tmp_path / "staged.db")
    client = TestClient(create_app(Settings(environment="test"), repo))
    response = client.post(
        "/api/v1/pcap-analysis-jobs?name=normal&filename=normal.pcap&analysis_module=ddos_attack",
        content=capture(),
        headers={"content-type": "application/octet-stream"},
    )
    assert response.status_code == 201, response.text
    normal = response.json()
    queue = QueueStub()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False), repo, queue=queue
        )
    )
    accepted = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "attack",
            "filename": "attack.pcap",
            "idempotency_key": "staged",
            "analysis_module": "ddos_attack",
            "analysis": {"module": "ddos_attack"},
            "internal_networks": ["10.0.0.0/8"],
            "ddos_normal_reference": {"job_id": normal["id"], "dataset_id": normal["dataset_id"]},
        },
    )
    assert accepted.status_code == 201, accepted.text
    job_id = accepted.json()["id"]
    before = deepcopy(repo.get_job(job_id))
    published = []
    original = repo.publish_job_capture

    def publish(*args, **kwargs):
        published.append(args[0]["id"])
        return original(*args, **kwargs)

    monkeypatch.setattr(repo, "publish_job_capture", publish)
    uploaded = client.put(
        f"/api/v1/pcap-analysis-jobs/{job_id}/capture",
        content=capture(offset),
        headers={"content-type": "application/octet-stream"},
    )
    if uploaded.status_code == 202:
        assert client.app.state.process_pcap_preparations_once()
    saved = repo.get_job(job_id)
    if offset:
        assert uploaded.status_code == 202 and len(queue.jobs) == 1
        assert load_reference(saved)["reference"]["dataset_id"] != saved["dataset_id"]
    else:
        assert uploaded.status_code == 422, uploaded.text
        assert uploaded.json()["error"]["code"] == "DDOS_REFERENCE_SAME_DATASET"
        assert published == [] and saved == before
        assert repo.open_job_capture(job_id) is None
        assert not queue.jobs, (
            "Same dataset reached production ID-only queue before worker rejection"
        )
    assert repo.get_job(normal["id"])["source"]["packet_bytes_retained"] is True
    repo.close()


@pytest.mark.parametrize("route", ["ordinary", "binary", "initiate", "upload", "reanalyze"])
def test_rbac_before_request_body_or_acquisition(tmp_path, monkeypatch, route):
    repo = MemoryRepository()
    config = Settings(
        environment="test",
        api_auth_required=True,
        viewer_token_sha256=hashlib.sha256(b"viewer").hexdigest(),
    )
    client = TestClient(create_app(config, repo))

    async def denied_body(*args, **kwargs):
        raise AssertionError("unauthorized request body consumed")
        yield b""

    def denied_read(*args):
        raise AssertionError("unauthorized reference acquired")

    monkeypatch.setattr(Request, "stream", denied_body)
    monkeypatch.setattr(repo, "read_ddos_reference", denied_read)
    paths = {
        "ordinary": ("/api/v1/analysis-jobs", "POST"),
        "binary": ("/api/v1/pcap-analysis-jobs?name=n&filename=n.pcap", "POST"),
        "initiate": ("/api/v1/pcap-analysis-jobs/initiate", "POST"),
        "upload": ("/api/v1/pcap-analysis-jobs/x/capture", "PUT"),
        "reanalyze": ("/api/v1/analysis-jobs/x/reanalyze", "POST"),
    }
    path, method = paths[route]
    for token, status in [(None, 401), ("viewer", 403)]:
        response = client.request(
            method,
            path,
            content=b"not-json",
            headers={"Authorization": "Bearer " + token} if token else {},
        )
        assert response.status_code == status, response.text
    assert repo.list_jobs() == []


@pytest.mark.parametrize("sqlite", [False, True])
def test_projection_budget_and_minimal_route(tmp_path, monkeypatch, sqlite):
    repo = SQLiteRepository(tmp_path / "projection.db") if sqlite else MemoryRepository()
    # 512 legal-size records, total projected encoding greater than 256KiB.
    row = {
        "packet_count": 1,
        "sensor_id": "s" * 128,
        "timestamp": "t" * 128,
        "source_ip": "2001:db8:abcd:abcd:abcd:abcd:abcd:abcd",
        "destination_ip": "2001:db8:abcd:abcd:abcd:abcd:abcd:abce",
        "source_port": 65535,
        "destination_port": 65535,
        "protocol": "TCP",
        "direction": "INBOUND",
        "total_bytes": 1500,
        "tcp_flags": {"syn": 1, "ack": 0, "rst": 0, "fin": 0},
    }
    repo.save_job(
        {
            "id": "large",
            "dataset_id": "large-dataset",
            "status": "COMPLETED",
            "flow_records": [deepcopy(row) for _ in range(512)],
        }
    )
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))

    def forbidden(*args, **kwargs):
        raise AssertionError("full reference get_job before bounded acquisition")

    monkeypatch.setattr(repo, "get_job", forbidden)
    response = client.post(
        "/api/v1/analysis-jobs",
        json={
            **ddos_payload("bounds"),
            "ddos_normal_reference": {"job_id": "large", "dataset_id": "large-dataset"},
        },
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "DDOS_REFERENCE_BYTE_LIMIT"
    if sqlite:
        repo.close()


def test_reference_zero_finding_report_control(tmp_path):
    repo, client, normal, selection = setup(tmp_path)
    request = {**ddos_payload("no-findings"), "ddos_normal_reference": selection}
    request["analysis"]["ddos_min_packet_count"] = 10000000
    response = client.post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "COMPLETED"
    assert response.json()["ddos_attack"]["findings"] == []
    repo.close()


@pytest.mark.parametrize("offset", [0, 60])
def test_binary_same_dataset_admission(tmp_path, offset):
    repo = SQLiteRepository(tmp_path / "binary.db")
    client = TestClient(create_app(Settings(environment="test"), repo))
    first = client.post(
        "/api/v1/pcap-analysis-jobs?name=normal&filename=normal.pcap&analysis_module=ddos_attack",
        content=capture(),
        headers={"content-type": "application/octet-stream"},
    )
    assert first.status_code == 201, first.text
    normal = first.json()
    result = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={
            "name": "attack",
            "filename": "attack.pcap",
            "analysis_module": "ddos_attack",
            "ddos_normal_reference_job_id": normal["id"],
            "ddos_normal_reference_dataset_id": normal["dataset_id"],
        },
        content=capture(offset),
        headers={"content-type": "application/octet-stream"},
    )
    assert result.status_code == (201 if offset else 422), result.text
    assert len(repo.list_jobs()) == (2 if offset else 1)
    assert repo.open_job_capture(normal["id"]) is not None
    repo.close()


@pytest.mark.parametrize("pending", [False, True])
def test_preparation_rechecks_derived_dataset_before_queue(tmp_path, pending):
    repo = SQLiteRepository(tmp_path / "prepare-binding.db")
    client = TestClient(create_app(Settings(environment="test"), repo))
    normal = client.post(
        "/api/v1/pcap-analysis-jobs?name=normal&filename=normal.pcap&analysis_module=ddos_attack",
        content=capture(),
        headers={"content-type": "application/octet-stream"},
    ).json()
    queue = QueueStub()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False), repo, queue=queue
        )
    )
    accepted = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "attack",
            "filename": "attack.pcap",
            "idempotency_key": "prepare",
            "analysis_module": "ddos_attack",
            "analysis": {"module": "ddos_attack"},
            "internal_networks": ["10.0.0.0/8"],
            "ddos_normal_reference": {"job_id": normal["id"], "dataset_id": normal["dataset_id"]},
        },
    )
    assert accepted.status_code == 201, accepted.text
    # Simulate an upload accepted by the predecessor; actual repository publication,
    # parser, preparation lease and enqueue path remain production implementations.
    job = repo.get_job(accepted.json()["id"])
    job["status"] = "INGESTING"
    job["source"].update(
        size_bytes=len(capture()),
        sha256=hashlib.sha256(capture()).hexdigest(),
        packet_bytes_retained=True,
    )
    job["processing"]["phase"] = "UPLOAD_STORED"
    assert repo.publish_job_capture(job, capture()) is not None
    if pending:
        job = repo.get_job(job["id"])
        job["dataset_id"] = normal["dataset_id"]
        job["status"] = "ANALYZING"
        job["processing"].update(
            phase="ANALYSIS_ENQUEUE_PENDING",
            attempt=1,
            lease_expires_at="2000-01-01T00:00:00+00:00",
            lease_token="old",
        )
        repo.save_job(job)
    assert client.app.state.process_pcap_preparations_once()
    saved = repo.get_job(job["id"])
    assert not queue.jobs
    assert saved["status"] == "FAILED"
    assert saved["error_code"] == "DDOS_REFERENCE_INVALID"
    repo.close()


@pytest.mark.parametrize("route", ["ordinary", "initiate", "binary"])
@pytest.mark.parametrize("change", ["delete", "mutate"])
def test_frozen_admission_replay_before_live_acquisition(tmp_path, monkeypatch, route, change):
    repo, client, normal, selection = setup(tmp_path)
    payload = {**ddos_payload("replay"), "ddos_normal_reference": selection}
    staged = {
        "name": "attack",
        "filename": "attack.pcap",
        "idempotency_key": "replay",
        "analysis_module": "ddos_attack",
        "analysis": {"module": "ddos_attack"},
        "internal_networks": ["10.0.0.0/8"],
        "ddos_normal_reference": selection,
    }
    params = {
        "name": "attack",
        "filename": "attack.pcap",
        "idempotency_key": "replay",
        "analysis_module": "ddos_attack",
        "ddos_normal_reference_job_id": selection["job_id"],
        "ddos_normal_reference_dataset_id": selection["dataset_id"],
    }

    def submit(changed=None):
        if route == "ordinary":
            return client.post("/api/v1/analysis-jobs", json={**payload, **(changed or {})})
        if route == "initiate":
            return client.post(
                "/api/v1/pcap-analysis-jobs/initiate", json={**staged, **(changed or {})}
            )
        return client.post(
            "/api/v1/pcap-analysis-jobs",
            params={**params, **(changed or {})},
            content=capture(60),
            headers={"content-type": "application/octet-stream"},
        )

    first = submit()
    assert first.status_code == 201, first.text
    saved = deepcopy(repo.get_job(first.json()["id"]))
    if change == "delete":
        assert repo.delete_job(normal["id"])
    else:
        source = repo.get_job(normal["id"])
        source["flow_records"] = []
        repo.save_job(source)

    def forbidden(*args, **kwargs):
        raise AssertionError("idempotent replay reacquired live normal source")

    monkeypatch.setattr(repo, "read_ddos_reference", forbidden)
    again = submit()
    assert again.status_code == 201 and again.json()["id"] == saved["id"], again.text
    assert repo.get_job(saved["id"]) == saved
    conflict = submit({"name": "different-payload"})
    assert conflict.status_code == 409, conflict.text
    changed_selection = {"job_id": "missing-foreign", "dataset_id": "foreign"}
    conflict = submit(
        {"ddos_normal_reference": changed_selection}
        if route != "binary"
        else {
            "ddos_normal_reference_job_id": "missing-foreign",
            "ddos_normal_reference_dataset_id": "foreign",
        }
    )
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error"]["code"] == "DDOS_REFERENCE_IDEMPOTENCY_CONFLICT"
    assert repo.get_job(saved["id"]) == saved
    assert "ddos_request_binding" not in json.dumps(again.json())
    repo.close()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("different", [False, True])
def test_reference_idempotency_atomic_race(tmp_path, monkeypatch, backend, different):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    repo = MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "race.db")
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    normal = client.post("/api/v1/analysis-jobs", json=ddos_payload("normal")).json()
    selection = {"job_id": normal["id"], "dataset_id": normal["dataset_id"]}
    barrier = Barrier(2)
    original = repo.read_ddos_reference
    acquisitions = []

    def acquire(*args):
        result = original(*args)
        acquisitions.append(args)
        barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(repo, "read_ddos_reference", acquire)

    def submit(index):
        payload = {**ddos_payload("race"), "ddos_normal_reference": selection}
        if different and index:
            payload["name"] = "different"
        return client.post("/api/v1/analysis-jobs", json=payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(submit, [0, 1]))
    assert len(acquisitions) == 2
    assert sorted(r.status_code for r in responses) == ([201, 409] if different else [201, 201])
    assert len(repo.list_jobs()) == 2
    accepted = [r.json() for r in responses if r.status_code == 201]
    assert len({job["id"] for job in accepted}) == 1
    winner = repo.get_job(accepted[0]["id"])
    assert load_reference(winner)["reference"]["job_id"] == normal["id"]
    if backend == "sqlite":
        repo.close()


def test_reanalysis_replay_does_not_reacquire_deleted_reference(tmp_path, monkeypatch):
    repo, client, normal, selection = setup(tmp_path)
    parent = client.post("/api/v1/analysis-jobs", json=ddos_payload("parent")).json()
    request = {"idempotency_key": "reanalyze-replay", "ddos_normal_reference": selection}
    endpoint = f"/api/v1/analysis-jobs/{parent['id']}/reanalyze"
    first = client.post(endpoint, json=request)
    assert first.status_code == 201, first.text
    saved = deepcopy(repo.get_job(first.json()["id"]))
    assert repo.delete_job(normal["id"])

    def forbidden(*args):
        raise AssertionError("reanalysis reacquired deleted reference")

    monkeypatch.setattr(repo, "read_ddos_reference", forbidden)
    replay = client.post(endpoint, json=request)
    assert replay.status_code == 201 and replay.json()["id"] == saved["id"], replay.text
    conflict = client.post(endpoint, json={**request, "ddos_min_source_count": 50})
    assert conflict.status_code == 409, conflict.text
    assert repo.get_job(saved["id"]) == saved
    repo.close()
