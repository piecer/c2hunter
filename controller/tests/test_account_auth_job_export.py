"""Real export queue publication and audit-only recovery."""

from uuid import uuid4

import pytest
from test_account_auth_job_investigations import assert_one_terminal, authority
from test_pcap_export_queue import _job

from c2hunter_controller.auth_models import AuthError
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.pcap_export_queue import PcapExportQueue
from c2hunter_controller.repositories import SQLiteRepository


@pytest.fixture
def domain(tmp_path):
    repo = SQLiteRepository(tmp_path / "domain.sqlite")
    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    queue = PcapExportQueue(repo)
    queue.auth_store = auth
    yield queue, auth
    repo.connection.close()


def test_reservation_outage_prevents_export_claim(domain, monkeypatch):
    queue, auth = domain

    def unavailable(*args):
        raise AuthError("SECURITY_UNAVAILABLE", 503)

    monkeypatch.setattr(auth, "reserve_job", unavailable)
    with authority(auth), pytest.raises(AuthError):
        queue.enqueue(_job(uuid4().hex), capacity=2, per_principal_limit=2)
    assert queue.claim() is None


def test_export_native_handoff_reserves_before_competing_claim(domain, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from functools import partial

    queue, auth = domain
    observer = SQLiteRepository(queue.repository._path)
    original = queue.repository.enqueue_pcap_export_job
    identifier = uuid4().hex

    def publish(job, **kwargs):
        assert observer.claim_pcap_export_job() is None
        assert auth.job_audit_status("pcap_export", identifier) == "pending"
        return original(job, **kwargs)

    monkeypatch.setattr(queue.repository, "enqueue_pcap_export_job", publish)
    try:
        with authority(auth) as context:
            callback = partial(context.reserve, "pcap_export")
        with ThreadPoolExecutor(max_workers=1) as executor:
            row, created = executor.submit(
                queue.enqueue,
                _job(identifier),
                capacity=2,
                per_principal_limit=2,
                before_publish=callback,
            ).result(5)
        assert created and row["id"] == identifier
        assert observer.claim_pcap_export_job()["id"] == identifier
    finally:
        observer.close()


def test_terminal_winner_repair_and_retry_are_distinct(domain, monkeypatch):
    queue, auth = domain
    identifier = uuid4().hex
    with authority(auth):
        queue.enqueue(_job(identifier), capacity=2, per_principal_limit=2)
    original = auth.pending_job_links()["items"][0]
    with authority(auth, "bob"):
        replay, created = queue.enqueue(_job(uuid4().hex), capacity=2, per_principal_limit=2)
    assert not created and replay["id"] == identifier
    assert (
        next(x for x in auth.pending_job_links()["items"] if x.resource_id == identifier)
        == original
    )
    claim = queue.claim()
    assert queue.retry_or_fail(
        identifier,
        attempt=claim["attempt"],
        lease_token=claim["lease_token"],
        transient=True,
        error_code="STORAGE",
        error="retry",
        retry_base_seconds=0,
    )
    assert auth.job_audit_status("pcap_export", identifier) == "pending"
    claim = queue.claim()
    assert claim is not None
    real_finish = auth.finish_job

    def unavailable(*args):
        raise AuthError("SECURITY_UNAVAILABLE", 503)

    monkeypatch.setattr(auth, "finish_job", unavailable)
    assert queue.complete(
        identifier,
        attempt=claim["attempt"],
        lease_token=claim["lease_token"],
        artifact={"id": identifier, "sha256": "b" * 64, "size_bytes": 1},
    )
    assert queue.get(identifier)["status"] == "COMPLETED"
    assert auth.job_audit_status("pcap_export", identifier) == "pending"
    monkeypatch.setattr(auth, "finish_job", real_finish)
    # A losing cancelled attempt must repair the committed success, not record cancellation.
    queue.cancel(identifier)
    assert auth.job_audit_status("pcap_export", identifier) == "complete"
    queue.cancel(identifier)
    assert queue.get(identifier)["status"] == "COMPLETED"
    assert_one_terminal(auth, identifier)


def test_expired_final_attempt_repairs_without_executor(domain):
    from datetime import UTC, datetime, timedelta

    queue, auth = domain
    identifier = uuid4().hex
    with authority(auth):
        queue.enqueue({**_job(identifier), "max_attempts": 1}, capacity=2, per_principal_limit=2)
    claim = queue.claim(lease_seconds=1)
    assert claim is not None
    queue.recover_expired(now=datetime.now(UTC) + timedelta(seconds=2))
    assert queue.get(identifier)["status"] == "FAILED"
    assert auth.job_audit_status("pcap_export", identifier) == "complete"


def test_export_factory_binds_configured_persistent_auth_store(domain):
    from c2hunter_controller.config import Settings
    from c2hunter_controller.pcap_export_worker import create_pcap_export_worker

    queue, auth = domain
    settings = Settings(
        environment="test",
        account_auth_enabled=True,
        auth_database_path=str(auth.sqlite_path),
        api_auth_required=True,
        auth_public_origin="https://example.test",
    )
    worker = create_pcap_export_worker(queue.repository, settings)
    assert worker.queue.auth_store is not None
    assert worker.queue.auth_store.sqlite_path == auth.sqlite_path
