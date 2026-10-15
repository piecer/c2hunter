"""Real HTTP/SQLite request-intent regression controls (R4-N1 and R4-N2)."""

import json
from copy import deepcopy

import pytest
from c2hunter_analysis.scoring import DEFAULT_DETECTOR_WEIGHTS
from fastapi.testclient import TestClient
from test_ddos_attack_api import ddos_payload
from test_ddos_reference_admission import capture

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository

HEADERS = {"content-type": "application/octet-stream"}


def new_world(tmp_path):
    repo = SQLiteRepository(tmp_path / "db")
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    normal = client.post("/api/v1/analysis-jobs", json=ddos_payload("normal"))
    assert normal.status_code == 201, normal.text
    normal = normal.json()
    return repo, client, normal, {"job_id": normal["id"], "dataset_id": normal["dataset_id"]}


def binary(key, selection):
    return {
        "name": "attack",
        "filename": "attack.pcap",
        "analysis_module": "ddos_attack",
        "idempotency_key": key,
        "ddos_normal_reference_job_id": selection["job_id"],
        "ddos_normal_reference_dataset_id": selection["dataset_id"],
    }


@pytest.mark.parametrize("case", ["cidr", "numeric-weight"])
def test_binary_normalized_replay(tmp_path, monkeypatch, case):
    repo, client, normal, selection = new_world(tmp_path)
    p = binary("request", selection)
    if case == "cidr":
        field = "internal_networks"
        initial = "10.0.0.0/8"
        equivalent = "10.1.2.3/8"
        different = "10.0.0.0/9"
    else:
        field = "detector_weights"
        key = next(iter(DEFAULT_DETECTOR_WEIGHTS))
        initial = json.dumps({key: 1})
        equivalent = json.dumps({key: 1.0})
        different = json.dumps({key: 0.5})
    p[field] = initial

    def send(params):
        return client.post(
            "/api/v1/pcap-analysis-jobs", params=params, content=capture(60), headers=HEADERS
        )

    first = send(p)
    assert first.status_code == 201, first.text
    saved = deepcopy(repo.get_job(first.json()["id"]))
    exact = send(p)
    assert exact.status_code == 201 and exact.json()["id"] == saved["id"]
    # Independently accepted normal-form twin validates that the canonical payload really agrees.
    twin = send({**p, "idempotency_key": "control", field: equivalent})
    assert twin.status_code == 201, twin.text
    other = repo.get_job(twin.json()["id"])
    for key in ("analysis", "internal_networks", "flow_records", "dataset_id"):
        assert saved[key] == other[key], key
    original_reference = deepcopy(saved["ddos_reference_snapshot"])
    twin_reference = deepcopy(other["ddos_reference_snapshot"])
    # Independent admissions intentionally have different selection timestamps.
    assert original_reference["reference"].pop("selected_at")
    assert twin_reference["reference"].pop("selected_at")
    assert original_reference == twin_reference
    changed = send({**p, field: different})
    assert changed.status_code == 409, changed.text
    assert repo.get_job(saved["id"]) == saved
    assert repo.delete_job(normal["id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("replay/conflict reacquired deleted source")

    monkeypatch.setattr(repo, "read_ddos_reference", forbidden)
    after = send(p)
    assert after.status_code == 201 and after.json()["id"] == saved["id"]
    normalized = send({**p, field: equivalent})
    assert repo.get_job(saved["id"]) == saved
    repo.close()
    assert normalized.status_code == 201 and normalized.json()["id"] == saved["id"], normalized.text


def test_ordinary_explicit_weights_conflict_not_erased_by_early_replay(tmp_path, monkeypatch):
    repo, client, normal, selection = new_world(tmp_path)
    preset = client.post(
        "/api/v1/detector-weight-presets",
        json={
            "name": "closure-preset",
            "detector_weights": {"periodic_beacon": 1.5},
            "set_as_default": True,
        },
    )
    assert preset.status_code == 201, preset.text
    payload = {**ddos_payload("preset-winner"), "ddos_normal_reference": selection}
    first = client.post("/api/v1/analysis-jobs", json=payload)
    assert first.status_code == 201, first.text
    saved = deepcopy(repo.get_job(first.json()["id"]))
    assert saved["analysis"]["detector_weights"]["periodic_beacon"] == 1.5
    changed = deepcopy(payload)
    changed["analysis"]["detector_weights"] = {}
    control = client.post(
        "/api/v1/analysis-jobs", json={**changed, "idempotency_key": "explicit-control"}
    )
    assert control.status_code == 201, control.text
    assert (
        repo.get_job(control.json()["id"])["analysis"]["detector_weights"]["periodic_beacon"] == 1.0
    )
    assert repo.delete_job(normal["id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("replay reacquired deleted source")

    monkeypatch.setattr(repo, "read_ddos_reference", forbidden)
    exact = client.post("/api/v1/analysis-jobs", json=payload)
    assert exact.status_code == 201 and exact.json()["id"] == saved["id"]
    conflict = client.post("/api/v1/analysis-jobs", json=changed)
    assert repo.get_job(saved["id"]) == saved
    repo.close()
    assert conflict.status_code == 409, conflict.text


def route_payload(route, key, selection):
    if route == "ordinary":
        return {**ddos_payload(key), "ddos_normal_reference": selection}
    if route == "binary":
        return binary(key, selection)
    return {
        "name": "attack",
        "filename": "attack.pcap",
        "analysis_module": "ddos_attack",
        "idempotency_key": key,
        "analysis": {"module": "ddos_attack"},
        "internal_networks": ["10.0.0.0/8"],
        "ddos_normal_reference": selection,
    }


def send_request(client, route, payload, content=None):
    if route == "binary":
        return client.post(
            "/api/v1/pcap-analysis-jobs",
            params=payload,
            content=capture(60) if content is None else content,
            headers=HEADERS,
        )
    url = "/api/v1/analysis-jobs" if route == "ordinary" else "/api/v1/pcap-analysis-jobs/initiate"
    return client.post(url, json=payload)


def with_weights(route, payload, value):
    payload = deepcopy(payload)
    if route == "binary":
        payload["detector_weights"] = json.dumps(value)
    else:
        payload["analysis"]["detector_weights"] = value
    return payload


def configure_default(client, name, weight):
    response = client.post(
        "/api/v1/detector-weight-presets",
        json={
            "name": name,
            "detector_weights": {"periodic_beacon": weight},
            "set_as_default": True,
        },
    )
    assert response.status_code == 201, response.text


@pytest.mark.parametrize("route", ["ordinary", "initiate", "binary"])
def test_weight_intent_survives_preset_change_source_deletion_and_reopen(
    tmp_path, monkeypatch, route
):
    repo, client, normal, selection = new_world(tmp_path)
    configure_default(client, "first", 1.5)
    payload = route_payload(route, "omitted", selection)
    first = send_request(client, route, payload)
    assert first.status_code == 201, first.text
    saved = deepcopy(repo.get_job(first.json()["id"]))
    # Staged DDoS deliberately uses built-ins, not the configured C2 preset.
    assert saved["analysis"]["detector_weights"]["periodic_beacon"] == (
        1.0 if route == "initiate" else 1.5
    )
    explicit = with_weights(route, {**payload, "idempotency_key": "explicit"}, {})
    control = send_request(client, route, explicit)
    assert control.status_code == 201, control.text
    explicit_saved = deepcopy(repo.get_job(control.json()["id"]))
    assert explicit_saved["analysis"]["detector_weights"]["periodic_beacon"] == 1.0
    configure_default(client, "later", 0.5)
    later = send_request(client, route, {**payload, "idempotency_key": "later"})
    assert later.status_code == 201, later.text
    assert later.json()["analysis"]["detector_weights"]["periodic_beacon"] == (
        1.0 if route == "initiate" else 0.5
    )
    assert repo.delete_job(normal["id"])
    configure_default(client, "after-source-deletion", 0.75)
    repo.close()
    repo = SQLiteRepository(tmp_path / "db")
    client = TestClient(create_app(Settings(environment="test"), repo))
    before = len(repo.list_jobs())

    def forbidden(*args, **kwargs):
        raise AssertionError("replay/conflict acquired mutable defaults/source or allocated a job")

    with monkeypatch.context() as guard:
        for method in ("read_ddos_reference", "list_detector_weight_presets", "create_job"):
            guard.setattr(repo, method, forbidden)
        guard.setattr("c2hunter_controller.app.parse_pcap", forbidden)
        exact = send_request(client, route, payload)
        assert exact.status_code == 201 and exact.json()["id"] == saved["id"], exact.text
        changed = send_request(client, route, with_weights(route, payload, {}))
        assert changed.status_code == (201 if route == "initiate" else 409), changed.text
        reverse = send_request(client, route, {**payload, "idempotency_key": "explicit"})
        assert reverse.status_code == (201 if route == "initiate" else 409), reverse.text
        for weights in (
            {},
            {"periodic_beacon": 1},
            {"periodic_beacon": 1.0},
            DEFAULT_DETECTOR_WEIGHTS,
        ):
            equivalent = send_request(client, route, with_weights(route, explicit, weights))
            assert (
                equivalent.status_code == 201 and equivalent.json()["id"] == explicit_saved["id"]
            ), equivalent.text
        conflict = send_request(
            client, route, with_weights(route, explicit, {"periodic_beacon": 0.5})
        )
        assert conflict.status_code == 409, conflict.text
        assert conflict.json()["error"]["code"] == "DDOS_REQUEST_IDEMPOTENCY_CONFLICT"
    assert repo.get_job(saved["id"]) == saved
    assert repo.get_job(explicit_saved["id"]) == explicit_saved
    assert len(repo.list_jobs()) == before
    for response, stored in ((first, saved), (control, explicit_saved), (exact, saved)):
        binding = stored["ddos_request_binding"]
        assert isinstance(binding, str) and len(binding) == 64
        assert set(binding) <= set("0123456789abcdef")
        for private in (
            "ddos_request_binding",
            "ddos_reference_binding",
            "ddos_reference_snapshot",
        ):
            assert private not in response.json()
    repo.close()


@pytest.mark.parametrize("route", ["ordinary", "initiate", "binary"])
@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        True,
        {"periodic_beacon": True},
        {"periodic_beacon": "1"},
        {"periodic_beacon": float("inf")},
        {"periodic_beacon": float("nan")},
    ],
)
def test_invalid_weight_intent_fails_closed_before_allocation(tmp_path, monkeypatch, route, value):
    repo, client, normal, selection = new_world(tmp_path)
    payload = with_weights(route, route_payload(route, "invalid", selection), value)
    before = repo.list_jobs()

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid intent reached source acquisition/allocation")

    monkeypatch.setattr(repo, "read_ddos_reference", forbidden)
    monkeypatch.setattr(repo, "create_job", forbidden)
    if route == "binary":
        response = send_request(client, route, payload)
    else:
        url = (
            "/api/v1/analysis-jobs"
            if route == "ordinary"
            else "/api/v1/pcap-analysis-jobs/initiate"
        )
        # Raw JSON carries nonfinite negatives through the real server decoder.
        response = client.post(
            url, content=json.dumps(payload), headers={"content-type": "application/json"}
        )
    assert response.status_code == 422, response.text
    assert repo.list_jobs() == before
    repo.close()


@pytest.mark.parametrize(
    "networks",
    [
        "invalid",
        " , ",
        "10.0.0.0/8,10.1.2.3/8",
        ",".join(f"10.{i // 256}.{i % 256}.0/24" for i in range(257)),
    ],
)
def test_binary_invalid_cidr_intent_fails_closed(tmp_path, monkeypatch, networks):
    repo, client, normal, selection = new_world(tmp_path)
    before = repo.list_jobs()

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid CIDR intent acquired source or allocated")

    monkeypatch.setattr(repo, "read_ddos_reference", forbidden)
    monkeypatch.setattr(repo, "create_job", forbidden)
    response = send_request(
        client, "binary", {**binary("invalid", selection), "internal_networks": networks}
    )
    assert response.status_code == 422, response.text
    assert repo.list_jobs() == before
    repo.close()


def test_binary_all_fields_body_and_route_collisions_keep_winner(tmp_path, monkeypatch):
    repo, client, normal, selection = new_world(tmp_path)
    payload = binary("winner", selection)
    first = send_request(client, "binary", payload)
    assert first.status_code == 201, first.text
    saved = deepcopy(repo.get_job(first.json()["id"]))
    assert repo.delete_job(normal["id"])
    before = len(repo.list_jobs())
    changes = {
        "name": "changed",
        "filename": "changed.pcap",
        "description": "changed",
        "internal_networks": "10.0.0.0/9",
        "minimum_candidate_score": 1,
        "minimum_distinct_clients": 4,
        "periodicity_min_samples": 6,
        "detector_weights": "{}",
        "ml_anomaly_enabled": True,
        "ml_anomaly_allow_standalone": True,
        "ml_anomaly_min_population": 31,
        "ml_anomaly_min_candidate_samples": 6,
        "ml_anomaly_z_threshold": 4.0,
        "ml_anomaly_feature_z_floor": 2.0,
        "ml_anomaly_min_directional_features": 3,
        "ml_anomaly_contribution_cap": 4.0,
        "ddos_min_source_count": 21,
        "ddos_min_packet_count": 1001,
        "ddos_min_packets_per_second": 101,
        "ddos_min_bits_per_second": 1000001,
        "ddos_bucket_seconds": 2,
        "ddos_min_duration_seconds": 4,
        "ddos_baseline_min_buckets": 21,
        "ddos_baseline_ratio": 6.0,
        "ddos_mad_z_threshold": 7.0,
        "ddos_protocol_share_threshold": 0.9,
        "ddos_tcp_flag_share_threshold": 0.9,
        "ddos_response_ratio_max": 0.3,
        "ddos_reflection_port_share_threshold": 0.7,
        "ddos_reflection_min_average_packet_bytes": 257,
        "ddos_overlap_window_seconds": 11,
        "ddos_normal_reference_job_id": "different",
        "ddos_normal_reference_dataset_id": "different",
    }

    def forbidden(*args, **kwargs):
        raise AssertionError("conflict acquired defaults/source, parsed capture or allocated")

    for method in ("read_ddos_reference", "list_detector_weight_presets", "create_job"):
        monkeypatch.setattr(repo, method, forbidden)
    monkeypatch.setattr("c2hunter_controller.app.parse_pcap", forbidden)
    for field, value in changes.items():
        response = send_request(client, "binary", {**payload, field: value})
        assert response.status_code == 409, (field, response.text)
    changed_body = send_request(client, "binary", payload, content=capture(61))
    assert changed_body.status_code == 409, changed_body.text
    for route in ("ordinary", "initiate"):
        response = send_request(client, route, route_payload(route, "winner", selection))
        assert response.status_code == 409, response.text
    response = client.post(
        f"/api/v1/analysis-jobs/{saved['id']}/reanalyze", json={"idempotency_key": "winner"}
    )
    assert response.status_code == 409, response.text
    assert repo.get_job(saved["id"]) == saved and len(repo.list_jobs()) == before
    repo.close()


def test_reanalysis_null_inherits_but_explicit_weights_do_not_bypass_validation(
    tmp_path, monkeypatch
):
    repo, client, normal, selection = new_world(tmp_path)
    parent = send_request(client, "ordinary", route_payload("ordinary", "parent", selection))
    assert parent.status_code == 201, parent.text
    url = f"/api/v1/analysis-jobs/{parent.json()['id']}/reanalyze"
    invalid = client.post(url, json={"idempotency_key": "invalid", "detector_weights": {}})
    assert invalid.status_code == 422, invalid.text
    first = client.post(url, json={"idempotency_key": "child"})
    assert first.status_code == 201, first.text
    saved = deepcopy(repo.get_job(first.json()["id"]))
    assert repo.delete_job(normal["id"]) and repo.delete_job(parent.json()["id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("reanalysis replay acquired deleted parent/reference")

    with monkeypatch.context() as guard:
        guard.setattr(repo, "read_ddos_reference", forbidden)
        guard.setattr(repo, "get_job", forbidden)
        for payload in (
            {"idempotency_key": "child"},
            {"idempotency_key": "child", "detector_weights": None},
        ):
            exact = client.post(url, json=payload)
            assert exact.status_code == 201 and exact.json()["id"] == saved["id"], exact.text
        for changes in (
            {"detector_weights": {}},
            {"ddos_min_packet_count": 999},
            {"ddos_normal_reference": None},
        ):
            conflict = client.post(url, json={"idempotency_key": "child", **changes})
            assert conflict.status_code == 409, conflict.text
    assert repo.get_job(saved["id"]) == saved
    repo.close()
