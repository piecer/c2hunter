"""Fresh seam-wired regression; not the predecessor placement diagnostic."""

from __future__ import annotations

import importlib
import inspect
import threading
from typing import Any

import pytest
from fastapi import Request

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as reader
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_source import START, config, review, stored


@pytest.fixture(params=["memory", "sqlite"])
def repo(request: Any, tmp_path: Any) -> Any:
    value = (
        MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "seam.db")
    )
    yield value
    value.close()


def seed(repo: Any) -> g.ApprovalRequest:
    repo.create_baseline_scope(config(), "static-admin", START)
    repo.save_job(stored())
    preview = repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
    return g.ApprovalRequest(
        expected_revision=0,
        idempotency_key="seam",
        source_job_id="root",
        source_binding_sha256=preview.source_binding_sha256,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="Synthetic review",
    )


def permit_types() -> Any:
    # Before the feature exists, run the real old publisher unchanged. This
    # fallback is diagnostic setup, not an implementation or fake result.
    try:
        return importlib.import_module("c2hunter_controller.baseline_admission")
    except ModuleNotFoundError as error:
        if error.name != "c2hunter_controller.baseline_admission":
            raise
        return None


def test_busy_new_has_no_acquisition_or_publication(repo: Any, monkeypatch: Any) -> None:
    request = seed(repo)
    module = permit_types()
    permit = module.BaselineAdmission() if module else threading.Lock()
    lease = module.BaselineLease(permit) if module else None
    assert lease.acquire() if lease else permit.acquire(blocking=False)
    calls = []
    name = "_sqlite_acquire" if isinstance(repo, SQLiteRepository) else "_memory_acquire"
    original = getattr(reader, name)

    def observe(*args: Any, **kwargs: Any) -> Any:
        calls.append("source")
        return original(*args, **kwargs)

    monkeypatch.setattr(reader, name, observe)
    before = repo.get_baseline_scope(config().scope_id)
    try:
        options = (
            {"admission": permit}
            if "admission" in inspect.signature(repo.publish_baseline_source).parameters
            else {}
        )
        code = None
        try:
            repo.publish_baseline_source(
                config().scope_id, request, "static-admin", START, **options
            )
        except bs.BaselineStorageError as error:
            code = error.code
        assert (
            code,
            calls,
            repo.get_baseline_scope(config().scope_id),
            repo.page_baseline_control_events(config().scope_id).total,
        ) == ("BASELINE_BUSY", [], before, 0)
    finally:
        lease.close() if lease else permit.release()


def test_default_four_argument_caller_control(repo: Any) -> None:
    request = seed(repo)
    first = repo.publish_baseline_source(config().scope_id, request, "static-admin", START)
    replay = repo.publish_baseline_source(config().scope_id, request, "static-admin", START)
    assert first.created and not replay.created and replay.receipt == first.receipt


@pytest.mark.parametrize("changed", [False, True])
def test_busy_retained_http_witness_source_gone_current_scope(
    repo: Any, monkeypatch: Any, changed: bool
) -> None:
    """Explicit rebind: a scratch HTTP witness, not the product router."""
    import hashlib

    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings

    request = seed(repo)
    first = repo.publish_baseline_source(config().scope_id, request, "static-admin", START)
    repo.control_baseline_scope(
        config().scope_id,
        g.ControlRequest(
            expected_revision=1,
            idempotency_key="retire",
            action="RETIRE",
            reason="fixture",
            generation_id=None,
        ),
        "static-admin",
        START,
    )
    repo.delete_job("root")
    reopened = isinstance(repo, SQLiteRepository)
    if reopened:
        path = repo._path
        repo.close()
        repo = SQLiteRepository(path)
    module = permit_types()
    permit = module.BaselineAdmission()
    owner = module.BaselineLease(permit)
    assert owner.acquire()
    calls = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        calls.append(True)
        raise AssertionError("source/producer forbidden")

    for name in ("_memory_acquire", "_sqlite_acquire", "_postgres_acquire"):
        monkeypatch.setattr(reader, name, forbidden)
    monkeypatch.setattr(g, "produce_generation", forbidden)
    token = "isolated-synthetic-token"
    app = create_app(
        Settings(
            environment="test",
            api_auth_required=True,
            admin_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            ai_analysis_enabled=False,
            database_url="memory://",
            redis_url="memory://",
            clickhouse_url="memory://",
            s3_endpoint="memory://",
        ),
        repository=repo,
    )

    @app.post("/seam-witness")
    async def witness(http_request: Request) -> Any:
        value = g.ApprovalRequest.from_mapping(await http_request.json())
        try:
            result = repo.publish_baseline_source(
                config().scope_id, value, "static-admin", START, admission=permit
            )
            return JSONResponse(
                {"scope": result.scope.to_mapping(), "receipt": result.receipt.to_mapping()},
                status_code=201 if result.created else 200,
            )
        except bs.BaselineStorageError as error:
            return JSONResponse(
                {"code": error.code},
                status_code=409 if error.code == "BASELINE_IDEMPOTENCY_CONFLICT" else 503,
            )

    payload = request.to_mapping()
    if changed:
        payload["reason"] = "changed"
    try:
        with TestClient(app) as client:
            response = client.post(
                "/seam-witness", json=payload, headers={"Authorization": "Bearer " + token}
            )
        assert response.status_code == (409 if changed else 200)
        if changed:
            assert response.json() == {"code": "BASELINE_IDEMPOTENCY_CONFLICT"}
        else:
            assert response.json()["receipt"] == first.receipt.to_mapping()
            assert response.json()["scope"]["control_revision"] == 2
            assert response.json()["scope"]["state"] == "RETIRED"
        assert calls == []
        with pytest.raises(AssertionError, match="forbidden"):
            forbidden()
        assert calls == [True]
    finally:
        owner.close()
        if reopened:
            repo.close()
