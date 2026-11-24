"""Controller preparation failure repairs analysis audit after fenced commit."""

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

from test_account_auth_job_investigations import assert_one_terminal, authority

from c2hunter_controller.auth_models import AuthError
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.pcap_preparation_worker import PcapPreparationWorker
from c2hunter_controller.repositories import SQLiteRepository


def test_preparation_failure_is_terminal_and_crash_gap_is_repair_only(tmp_path, monkeypatch):
    repo = SQLiteRepository(tmp_path / "domain.sqlite")
    try:
        auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
        auth.initialize()
        identifier = uuid4().hex
        raw = b"not a capture"
        with authority(auth) as context:
            context.reserve("analysis", identifier)
            repo.create_job(
                {
                    "id": identifier,
                    "idempotency_key": "prepare",
                    "status": "ANALYZING",
                    "mode": "PCAP_UPLOAD",
                    "created_at": datetime.now(UTC).isoformat(),
                    "internal_networks": ["10.0.0.0/8"],
                    "transitions": [],
                    "processing": {"phase": "UPLOAD_STORED"},
                    "source": {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                }
            )
            repo.save_job_capture(identifier, raw)
        enqueued = []
        worker = PcapPreparationWorker(
            repo, enqueue=enqueued.append, lease_seconds=30, max_packets=100
        )
        worker.auth_store = auth
        finish = auth.finish_job

        def unavailable(*args):
            raise AuthError("SECURITY_UNAVAILABLE", 503)

        monkeypatch.setattr(auth, "finish_job", unavailable)
        assert worker.run_once()
        assert repo.get_job(identifier)["status"] == "FAILED"
        assert auth.job_audit_status("analysis", identifier) == "pending"
        monkeypatch.setattr(auth, "finish_job", finish)
        assert not worker.run_once()
        assert auth.job_audit_status("analysis", identifier) == "complete"
        assert enqueued == []
        assert not worker.run_once()
        assert_one_terminal(auth, identifier)
    finally:
        repo.close()
