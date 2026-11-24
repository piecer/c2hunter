import secrets
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import test_account_auth_store as support

module = support.module
store = support.store
admin = support.admin

FAMILIES = ["analysis", "pcap_export", "ai_run", "ip_investigation", "job_investigation"]


@pytest.mark.parametrize("family", FAMILIES)
def test_job_reservation_winner_terminal_idempotency_and_audit_repair(store, admin, family):
    from c2hunter_controller.auth_models import Actor

    resource = str(uuid.uuid4())
    request = str(uuid.uuid4())
    intent = secrets.token_hex(16)
    assert store.job_audit_status(family, resource) == "unknown"
    link = store.reserve_job(family, resource, admin.actor, request, intent)
    assert store.job_audit_status(family, resource) == "pending"
    assert (
        store.reserve_job(family, resource, Actor(), str(uuid.uuid4()), secrets.token_hex(16))
        == link
    )
    assert link.actor == admin.actor
    assert store.pending_job_links(limit=1)["items"] == [link]
    store.logout(admin.token)
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute(
            "CREATE TRIGGER deny_audit BEFORE INSERT ON auth_audit BEGIN "
            "SELECT RAISE(ABORT,'denied'); END"
        )
    with pytest.raises(module().AuthError, match="SECURITY_UNAVAILABLE"):
        store.finish_job(family, resource, "COMPLETED")
    restarted = module().AuthStore(sqlite_path=store.sqlite_path)
    assert restarted.job_audit_status(family, resource) == "pending"
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute("DROP TRIGGER deny_audit")
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(
            pool.map(lambda _: restarted.finish_job(family, resource, "COMPLETED"), [1, 2])
        ) == ["complete", "complete"]
    with pytest.raises(module().AuthError, match="AUDIT_TERMINAL_CONFLICT"):
        restarted.finish_job(family, resource, "FAILED")
    assert restarted.pending_job_links()["items"] == []
    with sqlite3.connect(store.sqlite_path) as db:
        rows = db.execute(
            "SELECT actor_id,request_id,outcome FROM auth_audit WHERE job_id=? ORDER BY timestamp",
            (resource,),
        ).fetchall()
    assert rows == [(admin.user.id, request, "started"), (admin.user.id, request, "succeeded")]


@pytest.mark.parametrize("family", FAMILIES)
def test_job_nonterminal_unknown_and_reservation_outage(store, admin, family):
    resource = str(uuid.uuid4())
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute(
            "CREATE TRIGGER deny_audit BEFORE INSERT ON auth_audit BEGIN "
            "SELECT RAISE(ABORT,'denied'); END"
        )
    with pytest.raises(module().AuthError):
        store.reserve_job(family, resource, admin.actor, str(uuid.uuid4()), secrets.token_hex(16))
    assert store.job_audit_status(family, resource) == "unknown"
    with sqlite3.connect(store.sqlite_path) as db:
        db.execute("DROP TRIGGER deny_audit")
    store.reserve_job(family, resource, admin.actor, str(uuid.uuid4()), secrets.token_hex(16))
    state = "ANALYZING" if family == "analysis" else "QUEUED"
    assert store.finish_job(family, resource, state) == "pending"
    with pytest.raises(module().AuthError, match="INVALID_DOMAIN_STATUS"):
        store.finish_job(family, resource, "ERROR")  # attempt error, not resource status
    assert store.finish_job(family, str(uuid.uuid4()), "COMPLETED") == "unknown"


def test_terminal_mapping_matches_actual_domain_enums():
    from typing import get_args

    from c2hunter_controller.ai_analysis import TERMINAL_STATES, AIAnalysisState
    from c2hunter_controller.ai_investigation_schema import Status
    from c2hunter_controller.auth_store_jobs import STATES, TERMINALS, terminal_outcome
    from c2hunter_controller.jobs import TERMINAL, JobState
    from c2hunter_controller.pcap_export_store import ACTIVE_EXPORT_STATES, TERMINAL_EXPORT_STATES

    assert STATES["analysis"] == {x.value for x in JobState}
    assert set(TERMINALS["analysis"]) == {x.value for x in TERMINAL}
    assert STATES["ai_run"] == {x.value for x in AIAnalysisState}
    assert set(TERMINALS["ai_run"]) == {x.value for x in TERMINAL_STATES}
    assert STATES["pcap_export"] == ACTIVE_EXPORT_STATES | TERMINAL_EXPORT_STATES
    assert STATES["ip_investigation"] == STATES["job_investigation"] == set(get_args(Status))
    assert terminal_outcome("analysis", "PARTIALLY_COMPLETED") == "succeeded"
    assert terminal_outcome("ip_investigation", "PARTIAL") == "succeeded"
    assert terminal_outcome("job_investigation", "PARTIAL") == "succeeded"
    assert terminal_outcome("ai_run", "CANCELLED") == "cancelled"


@pytest.mark.parametrize("family", ["ip_investigation", "job_investigation"])
def test_investigation_real_sha256_identity_links(store, admin, family):
    from c2hunter_controller.ai_investigation_store import InvestigationRunStore

    resource = InvestigationRunStore._identity("user:" + admin.user.id, "server-test-idempotency")
    assert len(resource) == 64
    link = store.reserve_job(
        family, resource, admin.actor, str(uuid.uuid4()), secrets.token_hex(16)
    )
    assert link.resource_id == resource
    assert store.finish_job(family, resource, "PARTIAL") == "complete"
