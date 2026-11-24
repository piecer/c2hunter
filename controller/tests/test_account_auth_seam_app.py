"""Actual create_app binds all available services without inventing disabled AI."""

import importlib

import pytest
from test_account_auth_job_investigations import authority

from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_export_queue import PcapExportQueue
from c2hunter_controller.repositories import MemoryRepository


@pytest.mark.parametrize("ai_enabled", [False, True])
@pytest.mark.parametrize("inject_store", [False, True])
def test_create_app_binds_effective_store_without_startup_reconciliation(
    tmp_path, monkeypatch, ai_enabled, inject_store
):
    module = importlib.import_module("c2hunter_controller.app")
    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    with authority(auth) as context:
        context.reserve("analysis", "a" * 32)
    pending = auth.pending_job_links()["items"]
    queues = []

    class ObservedQueue(PcapExportQueue):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            queues.append(self)

    monkeypatch.setattr(module, "PcapExportQueue", ObservedQueue)
    settings = Settings(
        environment="test",
        account_auth_enabled=True,
        api_auth_required=True,
        auth_database_path=str(auth.sqlite_path),
        auth_public_origin="https://example.test",
        ai_analysis_enabled=ai_enabled,
        ai_model_provider="fake",
        ai_job_investigation_enabled=True,
        ai_investigation_inline_enabled=False,
    )
    repo = MemoryRepository()
    app = module.create_app(settings, repo, auth_store=auth if inject_store else None)
    effective = app.state.auth_store
    assert effective is not None and effective.sqlite_path == auth.sqlite_path
    if inject_store:
        assert effective is auth
    else:
        assert effective is not auth
    ai = app.state.ai_analysis_service
    if ai_enabled:
        assert ai is not None and ai.auth_store is effective
    else:
        assert ai is None
    ip = app.state.investigation_service
    job = app.state.job_investigation_service
    assert ip is not None and ip.store.auth_store is effective
    assert job is not None and job.store.auth_store is effective
    assert len(queues) == 1 and queues[0].auth_store is effective
    assert queues[0].claim() is None
    assert repo.list_jobs() == []
    assert auth.pending_job_links()["items"] == pending
    assert auth.job_audit_status("analysis", "a" * 32) == "pending"
