"""Historical AI public projections and real existing route composition."""

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.ai_analysis import FakeGateway
from c2hunter_controller.ai_queueing import MemoryAIAnalysisTaskQueue
from c2hunter_controller.app import _public_ai_run, create_app
from c2hunter_controller.historical_ai_builder import build_historical_target_snapshot
from c2hunter_controller.historical_ai_storage import OWNER_KEY, materialize_historical_run
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_baseline_http_routes import headers, settings
from tests.test_historical_ai_storage import prepared


@pytest.fixture(params=["memory", "sqlite"])
def repo(request, tmp_path):
    value = (
        MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "api.db")
    )
    yield value
    value.close()


def api(repo, *, auth=True):
    queue = MemoryAIAnalysisTaskQueue()
    app = create_app(
        settings(auth).model_copy(update={"ai_analysis_enabled": True}),
        repo,
        ai_gateway=FakeGateway(),
        ai_task_queue=queue,
    )
    return TestClient(app), queue


def test_historical_run_projection_is_closed_compact_and_nonmutating(repo):
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    original = repr(run)
    public = _public_ai_run(run)
    view, _ = materialize_historical_run(run)
    expected = {
        "id",
        "analysis_job_id",
        "dataset_id",
        "idempotency_key",
        "status",
        "progress_percent",
        "candidate_limit",
        "candidate_ids",
        "provider",
        "model_name",
        "prompt_name",
        "prompt_version",
        "prompt_hash",
        "input_schema_version",
        "output_schema_version",
        "created_by",
        "created_at",
        "updated_at",
        "transitions",
        "analysis_kind",
        "language",
        "discovery_mode",
        "baseline_mode",
        "selection_summary",
        "baseline_summary",
        "candidate_count",
    }
    assert set(public) == expected
    assert public["candidate_count"] == len(view["candidate_ids"])
    assert public["baseline_summary"] == view["baseline_summary"]
    assert OWNER_KEY not in public
    assert repr(run) == original
    public["baseline_summary"]["warnings"].clear()
    assert repr(run) == original


def test_historical_get_and_list_work_without_current_source_or_owner_leak(repo, monkeypatch):
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    client, _ = api(repo, auth=False)

    def forbidden(*args):
        pytest.fail("compact saved historical reads must not inspect current source")

    monkeypatch.setattr(repo, "get_job_summary", forbidden)
    for path in (
        f"/api/v1/ai-runs/{run['id']}",
        f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
    ):
        response = client.get(path)
        assert response.status_code == 200, response.text
        public = response.json().get("items", [response.json()])[0]
        assert public["candidate_count"] == 1
        assert OWNER_KEY not in public
        assert "candidate_snapshots" not in public
        assert "baseline_request" not in public
        assert public["baseline_mode"] == "historical"


def test_historical_post_enqueues_once_and_replays_before_current_source(repo, monkeypatch):
    request, _, _ = prepared(repo)
    client, queue = api(repo)
    path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
    payload = request.payload.to_mapping()
    response = client.post(path, json=payload, headers=headers("analyst"))
    assert response.status_code == 201, response.text
    public = response.json()
    assert public["baseline_mode"] == "historical"
    assert public["candidate_count"] == 1
    assert OWNER_KEY not in public
    assert queue.depth() == 1
    stored = repo.get_ai_run(public["id"])
    assert OWNER_KEY in stored

    def forbidden(*args):
        pytest.fail("replay must precede current source, scope and candidate reads")

    for name in ("get_job", "get_job_summary", "get_candidates", "get_baseline_scope"):
        monkeypatch.setattr(repo, name, forbidden)
    replay = client.post(path, json=payload, headers=headers("analyst"))
    assert replay.status_code == 200, replay.text
    assert replay.json() == public
    assert queue.depth() == 1
    conflict = client.post(path, json={**payload, "language": "en"}, headers=headers("analyst"))
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error"]["code"] == "BASELINE_IDEMPOTENCY_CONFLICT"
    assert queue.depth() == 1


def test_historical_create_rejects_auth_disabled_before_repository(repo, monkeypatch):
    request, _, _ = prepared(repo)
    client, queue = api(repo, auth=False)
    monkeypatch.setattr(repo, "get_job_summary", lambda *_: pytest.fail("source read before auth"))
    response = client.post(
        f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
        json=request.payload.to_mapping(),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "BASELINE_AUTH_REQUIRED"
    assert queue.depth() == 0


@pytest.mark.parametrize("field", ["baseline_comparisons", "baseline_sources"])
def test_saved_baseline_pages_use_saved_snapshot_and_authorize_first(repo, monkeypatch, field):
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    view, _ = materialize_historical_run(run)
    client, _ = api(repo)
    path = f"/api/v1/ai-runs/{run['id']}/{field.replace('_', '-')}"
    response = client.get(path + "?offset=0&limit=1", headers=headers("analyst"))
    assert response.status_code == 200, response.text
    assert response.json() == {
        "items": view[field][:1],
        "total": len(view[field]),
        "offset": 0,
        "limit": 1,
        "next_offset": 1 if len(view[field]) > 1 else None,
    }
    monkeypatch.setattr(repo, "get_ai_run", lambda *_: pytest.fail("read before role"))
    denied = client.get(path, headers=headers("viewer"))
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "INSUFFICIENT_ROLE"
    no_auth, _ = api(repo, auth=False)
    denied = no_auth.get(path)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "BASELINE_AUTH_REQUIRED"


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"analysis_kind": "DDOS_ATTACK"}, "BASELINE_MODE_NOT_ALLOWED"),
        ({"discovery_mode": "legacy"}, "BASELINE_MODE_NOT_ALLOWED"),
        ({"baseline_mode": None}, "VALIDATION_ERROR"),
        ({"candidate_limit": True}, "VALIDATION_ERROR"),
        ({"candidate_limit": "1"}, "VALIDATION_ERROR"),
        ({"baseline_reference": None}, "VALIDATION_ERROR"),
    ],
)
def test_historical_invalid_request_has_no_source_reads_or_enqueue(
    repo, monkeypatch, changes, code
):
    request, _, _ = prepared(repo)
    client, queue = api(repo)
    monkeypatch.setattr(repo, "get_job_summary", lambda *_: pytest.fail("invalid source read"))
    response = client.post(
        f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
        json={**request.payload.to_mapping(), **changes},
        headers=headers("analyst"),
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == code
    assert queue.depth() == 0


@pytest.mark.parametrize(
    "body,status,code",
    [
        (b'{"idempotency_key":"one","idempotency_key":"two"}', 422, "VALIDATION_ERROR"),
        (b'{"baseline_mode":"off","baseline_\\u006dode":"historical"}', 422, "VALIDATION_ERROR"),
        (b'{"unknown":NaN}', 422, "VALIDATION_ERROR"),
        (b'{"unknown":' + b"[" * 17 + b"0" + b"]" * 17 + b"}", 422, "VALIDATION_ERROR"),
        (b" " * 16385, 413, "BASELINE_BODY_LIMIT"),
    ],
)
def test_create_raw_body_is_bounded_before_repository(repo, monkeypatch, body, status, code):
    client, queue = api(repo)
    monkeypatch.setattr(repo, "get_job_summary", lambda *_: pytest.fail("invalid source read"))
    response = client.post(
        "/api/v1/analysis-jobs/missing/ai-runs",
        content=body,
        headers={**headers("analyst"), "Content-Type": "application/json"},
    )
    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert queue.depth() == 0


def test_baseline_only_pages_authorize_before_query_validation(repo):
    client, _ = api(repo)
    path = "/api/v1/ai-runs/missing/baseline-sources?limit=garbage"
    response = client.get(path, headers=headers("viewer"))
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"
    client, _ = api(repo, auth=False)
    response = client.get(path)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "BASELINE_AUTH_REQUIRED"


@pytest.mark.parametrize("surface", ["get", "list"])
def test_compact_reads_map_corrupt_owner_to_fixed_error(repo, monkeypatch, surface):
    from copy import deepcopy

    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    corrupt = deepcopy(run)
    corrupt[OWNER_KEY]["expected_snapshot_sha256"] = "f" * 64
    monkeypatch.setattr(repo, "get_ai_run", lambda *_: corrupt)
    monkeypatch.setattr(repo, "list_ai_runs", lambda *_: [corrupt])
    client, _ = api(repo, auth=False)
    path = (
        f"/api/v1/ai-runs/{run['id']}"
        if surface == "get"
        else f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
    )
    response = client.get(path)
    assert response.status_code == 503, response.text
    error = response.json()["error"]
    assert error["code"] == "BASELINE_STORAGE_UNAVAILABLE"
    assert error["message"] == "기준선 저장소를 사용할 수 없습니다"
    assert error["details"] is None
    assert "snapshot" not in response.text


@pytest.mark.parametrize(
    "code,status",
    [
        ("BASELINE_RUN_SNAPSHOT_LIMIT", 413),
        ("BASELINE_SOURCE_CHANGED", 409),
        ("BASELINE_BUSY", 503),
        ("BASELINE_STORAGE_UNAVAILABLE", 503),
    ],
)
def test_admission_domain_error_never_enqueues_or_audits_success(repo, monkeypatch, code, status):
    from c2hunter_controller.historical_ai import HistoricalAIError

    request, _, _ = prepared(repo)
    client, queue = api(repo)

    def fail(*args, **kwargs):
        raise HistoricalAIError(code)

    monkeypatch.setattr(repo, "admit_historical_ai_run", fail)
    response = client.post(
        f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
        json=request.payload.to_mapping(),
        headers=headers("analyst"),
    )
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code
    assert queue.depth() == 0
    assert repo.list_ai_runs(request.analysis_job_id) == []


def test_create_exact_raw_byte_limit_and_explicit_off_compatibility(repo):
    import json

    request, _, _ = prepared(repo)
    client, queue = api(repo)
    body = json.dumps(request.payload.to_mapping()).encode()
    body += b" " * (16384 - len(body))
    response = client.post(
        f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
        content=body,
        headers={**headers("analyst"), "Content-Type": "application/json"},
    )
    assert response.status_code == 201, response.text
    assert queue.depth() == 1
    off = client.post(
        f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
        json={"idempotency_key": "off-key", "baseline_mode": "off", "baseline_reference": None},
        headers=headers("analyst"),
    )
    assert off.status_code == 201, off.text
    assert "baseline_mode" not in off.json()
    assert "baseline_summary" not in off.json()
    assert queue.depth() == 2


def test_storage_unavailable_keeps_fixed_http_message(repo, monkeypatch):
    from c2hunter_controller._baseline_storage import BaselineStorageError

    request, _, _ = prepared(repo)
    client, queue = api(repo)

    def fail(*args, **kwargs):
        raise BaselineStorageError("BASELINE_STORAGE_UNAVAILABLE")

    monkeypatch.setattr(repo, "admit_historical_ai_run", fail)
    response = client.post(
        f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
        json=request.payload.to_mapping(),
        headers=headers("analyst"),
    )
    assert response.status_code == 503
    assert response.json()["error"]["message"] == "기준선 저장소를 사용할 수 없습니다"
    assert queue.depth() == 0


def test_historical_http_uses_shared_two_slot_transport(repo, monkeypatch):
    import asyncio
    import threading

    import httpx

    from tests.test_baseline_http_transport import reached

    request, _, _ = prepared(repo)
    client, queue = api(repo)
    first, second, release = threading.Event(), threading.Event(), threading.Event()
    calls = []
    original = repo.get_ai_run_by_request

    def blocked(*args):
        calls.append(True)
        if len(calls) <= 2:
            (first if len(calls) == 1 else second).set()
            assert release.wait(10)
        return original(*args)

    monkeypatch.setattr(repo, "get_ai_run_by_request", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=client.app),
            base_url="http://test",
            headers=headers("analyst"),
        ) as http:
            path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
            a = asyncio.create_task(http.post(path, json=request.payload.to_mapping()))
            b = asyncio.create_task(http.post(path, json=request.payload.to_mapping()))
            try:
                await reached(first)
                await reached(second)
                denied = await asyncio.wait_for(
                    http.post(path, json=request.payload.to_mapping()), 1
                )
                assert denied.status_code == 503
                assert denied.json()["error"]["code"] == "BASELINE_BUSY"
                assert len(calls) == 2
                health = await asyncio.wait_for(http.get("/api/v1/health"), 1)
                assert health.status_code == 200
            finally:
                release.set()
                results = await asyncio.gather(a, b)
            assert any(result.status_code == 201 for result in results)
            assert all(result.status_code in {200, 201, 503} for result in results)
            assert queue.depth() == 1
        await client.app.state.baseline_transport.shutdown()
        assert not client.app.state.baseline_transport._pending

    asyncio.run(run())


def test_http_created_run_crosses_real_worker_and_saved_result_routes(repo, monkeypatch):
    from copy import deepcopy

    from c2hunter_controller.ai_analysis import AIAnalysisService
    from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
    from c2hunter_controller.ai_worker import AIAnalysisWorker
    from tests.test_historical_ai_execution import RecordingGateway

    request, _, _ = prepared(repo)
    original_job = deepcopy(repo.get_job(request.analysis_job_id))
    original_candidates = deepcopy(repo.get_candidates(request.analysis_job_id))
    client, tasks = api(repo)
    response = client.post(
        f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs",
        json=request.payload.to_mapping(),
        headers=headers("analyst"),
    )
    assert response.status_code == 201
    run_id = response.json()["id"]
    internal = repo.get_ai_run(run_id)
    _, bundles = materialize_historical_run(internal)
    original_owner = deepcopy(internal[OWNER_KEY])
    gateway = RecordingGateway()
    queue = MemoryAIAnalysisWorkerQueue(
        [{"ai_run_id": value, "receipt": "http-handoff"} for value in tasks.run_ids]
    )
    with monkeypatch.context() as protected:
        for method in ("get_job", "get_job_summary", "get_candidates", "get_baseline_scope"):
            protected.setattr(
                repo, method, lambda *_: pytest.fail("saved execution read current source")
            )
        assert AIAnalysisWorker(queue, AIAnalysisService(repo, gateway)).run_once(timeout=0)
        summary = client.get(f"/api/v1/ai-runs/{run_id}", headers=headers("viewer"))
        assessments = client.get(
            f"/api/v1/ai-runs/{run_id}/assessments", headers=headers("analyst")
        )
    assert summary.status_code == assessments.status_code == 200
    assert summary.json()["status"] == "COMPLETED"
    assert OWNER_KEY not in summary.json()
    assessment = assessments.json()["items"][0]
    evidence = client.get(
        f"/api/v1/ai-assessments/{assessment['id']}/evidence-bundle", headers=headers("analyst")
    )
    artifacts = client.get(
        f"/api/v1/ai-assessments/{assessment['id']}/artifacts", headers=headers("analyst")
    )
    assert evidence.status_code == artifacts.status_code == 200
    assert evidence.json() == bundles[0].model_dump(mode="json", by_alias=True)
    assert gateway.calls == [evidence.json()]
    assert artifacts.json()["total"] == 3
    assert queue.acked == ["http-handoff"]
    assert repo.get_ai_run(run_id)[OWNER_KEY] == original_owner
    assert repo.get_job(request.analysis_job_id) == original_job
    assert repo.get_candidates(request.analysis_job_id) == original_candidates
