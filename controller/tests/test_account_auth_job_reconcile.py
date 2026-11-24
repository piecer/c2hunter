"""Audit-only CLI reads actual persisted domains, never runs their workers."""

from uuid import uuid4

import pytest
from test_account_auth_job_investigations import admit, authority
from test_pcap_export_queue import _job

from c2hunter_controller import auth_cli
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.ai_job_investigation_store import (
    JobInvestigationRunStore,
    initialize_job_investigation_store,
)
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.pcap_export_queue import PcapExportQueue
from c2hunter_controller.repositories import SQLiteRepository


def test_cli_refuses_process_local_memory(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("C2HUNTER_DATABASE_URL", "memory://")
    monkeypatch.setenv("C2HUNTER_AUTH_DATABASE_PATH", str(tmp_path / "private" / "auth.sqlite"))
    assert auth_cli.main(["reconcile-audit"]) == 2
    assert "AUDIT_RECONCILE_UNSUPPORTED" in capsys.readouterr().err


@pytest.mark.parametrize("terminal", [False, True])
def test_five_family_persistent_readers_repair_bounded_page(tmp_path, terminal):
    from c2hunter_controller import auth_reconcile

    repo = SQLiteRepository(tmp_path / "domain.sqlite")
    try:
        auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
        auth.initialize()
        initialize_investigation_store(repo)
        initialize_job_investigation_store(repo)
        ip = InvestigationRunStore(repo)
        job = JobInvestigationRunStore(repo)
        with authority(auth) as context:
            analysis_id, ai_id, export_id = (uuid4().hex for _ in range(3))
            context.reserve("analysis", analysis_id)
            repo.create_job(
                {
                    "id": analysis_id,
                    "idempotency_key": "analysis",
                    "status": "COMPLETED" if terminal else "ANALYZING",
                }
            )
            context.reserve("ai_run", ai_id)
            repo.create_ai_run(
                {
                    "id": ai_id,
                    "analysis_job_id": analysis_id,
                    "idempotency_key": "ai",
                    "created_at": "2026-11-23T00:00:00Z",
                    "status": "FAILED" if terminal else "QUEUED",
                }
            )
            queue = PcapExportQueue(repo)
            queue.enqueue(_job(export_id), capacity=2, per_principal_limit=2)
            ip_row, _ = admit(ip)
            job_row, _ = admit(job)
        if terminal:
            queue.cancel(export_id)
            ip.cancel("alice", "job", ip_row["id"])
            job.cancel("alice", "job", job_row["id"])
        reader = auth_reconcile.RepositoryJobReader(repo)
        assert len(auth.pending_job_links()["items"]) == 5
        result = auth_cli.reconcile(auth, reader, limit=2)
        assert result["examined"] == 2
        assert result["completed"] == (2 if terminal else 0)
        assert result["next_cursor"] is not None
        result = auth_cli.reconcile(auth, reader, limit=3, cursor=result["next_cursor"])
        assert result["examined"] == 3
        assert result["completed"] == (3 if terminal else 0)
        assert len(auth.pending_job_links()["items"]) == (0 if terminal else 5)
    finally:
        repo.close()


def test_configured_reader_uses_metadata_adapter_and_closes_it(tmp_path, monkeypatch):
    from c2hunter_controller import auth_reconcile, production

    # Factory composition test, not PostgreSQL backend acceptance.
    repo = SQLiteRepository(tmp_path / "metadata.sqlite")
    captured = []

    def factory(dsn, blobs):
        captured.append((dsn, blobs))
        return repo

    monkeypatch.setattr(production, "PostgresRepository", factory)
    monkeypatch.setenv("C2HUNTER_DATABASE_URL", "postgresql://owned-test-adapter")
    with auth_reconcile.configured_reader() as reader:
        assert reader.repository is repo
    assert captured == [("postgresql://owned-test-adapter", None)]
    import sqlite3

    with pytest.raises(sqlite3.ProgrammingError):
        repo.connection.execute("SELECT 1")


def test_reader_missing_schema_and_missing_resource_do_not_invent_outcome(tmp_path):
    from dataclasses import replace

    from c2hunter_controller.auth_models import AuthError
    from c2hunter_controller.auth_reconcile import RepositoryJobReader

    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    repo = SQLiteRepository(tmp_path / "domain.sqlite")
    try:
        with authority(auth) as context:
            link = context.reserve("analysis", uuid4().hex)
        reader = RepositoryJobReader(repo)
        assert reader(link) is None
        with pytest.raises(AuthError, match="AUDIT_RECONCILE_UNAVAILABLE"):
            reader(replace(link, family="ip_investigation"))
        with pytest.raises(AuthError, match="AUDIT_RECONCILE_UNSUPPORTED"):
            reader(replace(link, family="invalid"))
        assert auth.job_audit_status("analysis", link.resource_id) == "pending"
    finally:
        repo.close()
