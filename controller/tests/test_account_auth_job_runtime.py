"""Frozen application binding port does not admit, dispatch or reconcile work."""

from test_account_auth_job_investigations import authority

from c2hunter_controller import auth_job_runtime
from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway
from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.ai_job_investigation import JobInvestigationService
from c2hunter_controller.ai_job_investigation_store import (
    JobInvestigationRunStore,
    initialize_job_investigation_store,
)
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.pcap_export_queue import PcapExportQueue
from c2hunter_controller.repositories import MemoryRepository


def test_bind_only_leaves_live_pending_links_untouched(tmp_path):
    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    with authority(auth) as context:
        context.reserve("analysis", "a" * 32)
    repo = MemoryRepository()
    initialize_investigation_store(repo)
    initialize_job_investigation_store(repo)
    ai = AIAnalysisService(repo, FakeGateway())
    ip = InvestigationService(repo, InvestigationRunStore(repo), None)
    job = JobInvestigationService(repo, JobInvestigationRunStore(repo), None)
    queue = PcapExportQueue(repo)
    assert hasattr(auth_job_runtime, "wire_job_audit")
    auth_job_runtime.wire_job_audit(
        auth,
        ai_service=ai,
        investigation_service=ip,
        job_investigation_service=job,
        pcap_export_queue=queue,
    )
    assert ai.auth_store is auth
    assert ip.store.auth_store is auth
    assert job.store.auth_store is auth
    assert queue.auth_store is auth
    assert auth.job_audit_status("analysis", "a" * 32) == "pending"
    assert repo.list_jobs() == []
    assert queue.claim() is None


def test_disabled_ai_still_binds_investigations_and_export(tmp_path):
    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    repo = MemoryRepository()
    initialize_investigation_store(repo)
    initialize_job_investigation_store(repo)
    ip = InvestigationService(repo, InvestigationRunStore(repo), None)
    job = JobInvestigationService(repo, JobInvestigationRunStore(repo), None)
    queue = PcapExportQueue(repo)
    auth_job_runtime.wire_job_audit(
        auth,
        ai_service=None,
        investigation_service=ip,
        job_investigation_service=job,
        pcap_export_queue=queue,
    )
    assert ip.store.auth_store is auth
    assert job.store.auth_store is auth
    assert queue.auth_store is auth
    assert repo.list_jobs() == []
    assert queue.claim() is None


def test_controller_worker_factories_propagate_auth_without_initialization(tmp_path):
    from c2hunter_controller.ai_investigation_worker import configured_service
    from c2hunter_controller.ai_job_investigation_http import configured_job_service
    from c2hunter_controller.ai_worker import configured_ai_service
    from c2hunter_controller.config import Settings

    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    repo = MemoryRepository()
    initialize_investigation_store(repo)
    initialize_job_investigation_store(repo)
    settings = Settings(
        environment="test",
        account_auth_enabled=True,
        api_auth_required=True,
        auth_database_path=str(auth.sqlite_path),
        auth_public_origin="https://example.test",
    )
    ai = configured_ai_service(repo, FakeGateway(), settings)
    assert ai.auth_store is not None and ai.auth_store.sqlite_path == auth.sqlite_path
    ip, _ = configured_service(repo, FakeGateway(), auth_store=auth)
    job, _ = configured_job_service(repo, FakeGateway(), enabled=True, auth_store=auth)
    assert ip.store.auth_store is auth
    assert job.store.auth_store is auth


def test_pending_scan_is_bounded_and_preserves_unknown_outcomes(tmp_path, monkeypatch, caplog):
    from uuid import uuid4

    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    with authority(auth) as context:
        for _ in range(101):
            context.reserve("analysis", uuid4().hex)
    seen = []

    def missing(identifier):
        seen.append(identifier)
        return None

    cursor = auth_job_runtime.repair_pending_page(auth, "analysis", missing)
    assert len(seen) == 100 and cursor is not None
    assert auth_job_runtime.repair_pending_page(auth, "analysis", missing, cursor=cursor) is None
    assert len(seen) == 101
    assert auth_job_runtime.repair_pending_page(None, "analysis", missing, cursor=cursor) == cursor
    assert len(auth.pending_job_links(limit=1000)["items"]) == 101

    def unavailable(*args, **kwargs):
        raise RuntimeError("credential-secret-must-not-be-logged")

    monkeypatch.setattr(auth, "pending_job_links", unavailable)
    assert auth_job_runtime.repair_pending_page(auth, "analysis", missing, cursor=cursor) == cursor
    assert (
        auth_job_runtime.repair_job_audit(auth, "analysis", seen[0], lambda: unavailable())
        == "pending"
    )
    assert "credential-secret-must-not-be-logged" not in caplog.text
    auth_job_runtime.wire_job_audit(
        None,
        ai_service=AIAnalysisService(MemoryRepository(), FakeGateway()),
        investigation_service=None,
        job_investigation_service=None,
        pcap_export_queue=PcapExportQueue(MemoryRepository()),
    )
