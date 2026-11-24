"""Real SQL custody admission must precede runnable publication."""

from uuid import uuid4

import pytest

from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.ai_job_investigation_store import (
    JobInvestigationRunStore,
    initialize_job_investigation_store,
)
from c2hunter_controller.auth_job_context import bind_job_audit
from c2hunter_controller.auth_models import Actor, AuthError
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.repositories import SQLiteRepository
from c2hunter_controller.security import Role


@pytest.fixture(params=["ip_investigation", "job_investigation"])
def domain(request, tmp_path):
    repository = SQLiteRepository(tmp_path / "domain.sqlite")
    auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    auth.initialize()
    clock = [1000.0]
    if request.param == "ip_investigation":
        initialize_investigation_store(repository)
        store = InvestigationRunStore(repository, clock=lambda: clock[0])
    else:
        initialize_job_investigation_store(repository)
        store = JobInvestigationRunStore(repository, clock=lambda: clock[0])
    yield request.param, store, auth, clock
    repository.connection.close()


def admit(store, key="key", **kwargs):
    return store.admit(
        owner_id="alice",
        job_id="job",
        idempotency_key=key,
        request_json=b"{}",
        binding_json=b"{}",
        snapshot_json=b"{}",
        **kwargs,
    )


def authority(auth, name="alice"):
    return bind_job_audit(
        auth,
        Actor(
            id="a" * 32 if name == "alice" else "b" * 32,
            name=name,
            role=Role.ANALYST,
            auth_kind="session",
        ),
        str(uuid4()),
        uuid4().hex,
    )


def assert_one_terminal(auth, resource_id, actor_id="a" * 32):
    with auth.db.transaction() as sql:
        rows = sql.execute(
            "SELECT actor_id,outcome FROM auth_audit WHERE action='job.lifecycle' "
            "AND job_id=? AND outcome<>'started'",
            (resource_id,),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["actor_id"] == actor_id


def test_reservation_failure_publishes_no_runnable(domain, monkeypatch):
    _, store, auth, _ = domain

    def unavailable(*args):
        raise AuthError("SECURITY_UNAVAILABLE", 503)

    monkeypatch.setattr(auth, "reserve_job", unavailable)
    with authority(auth), pytest.raises(AuthError):
        admit(store)
    assert store.claim("worker") is None
    assert store.page("alice", "job") == []


def test_terminal_crash_gap_replay_preserves_actor(domain, monkeypatch):
    family, store, auth, _ = domain
    store.auth_store = auth
    with authority(auth):
        row, created = admit(store)
    assert created
    original = auth.pending_job_links()["items"][0]
    with authority(auth, "bob"):
        replay, created = admit(store)
    assert not created and replay["id"] == row["id"]
    assert auth.pending_job_links()["items"][0] == original
    real_finish = auth.finish_job

    def unavailable(*args):
        raise AuthError("SECURITY_UNAVAILABLE", 503)

    monkeypatch.setattr(auth, "finish_job", unavailable)
    cancelled = store.cancel("alice", "job", row["id"])
    assert cancelled["status"] == "CANCELLED"
    assert auth.job_audit_status(family, row["id"]) == "pending"
    monkeypatch.setattr(auth, "finish_job", real_finish)
    store.cancel("alice", "job", row["id"])
    assert auth.job_audit_status(family, row["id"]) == "complete"
    store.cancel("alice", "job", row["id"])
    assert auth.pending_job_links()["items"] == []
    assert_one_terminal(auth, row["id"])


def test_explicit_capture_survives_native_thread_handoff(domain):
    from concurrent.futures import ThreadPoolExecutor
    from functools import partial

    family, store, auth, _ = domain
    with authority(auth) as context:
        before_publish = partial(context.reserve, family)
    with ThreadPoolExecutor(max_workers=1) as executor:
        row, created = executor.submit(admit, store, before_publish=before_publish).result(5)
    assert created
    assert auth.job_audit_status(family, row["id"]) == "pending"


def test_independent_reader_never_observes_runnable_before_link(domain, monkeypatch):
    import sqlite3

    family, store, auth, _ = domain
    observer = sqlite3.connect(store.repository._path)
    original = store._write
    observed = []

    def before_commit(tx, kind, identifier, value):
        original(tx, kind, identifier, value)
        if kind == store._profile.state:
            assert (
                observer.execute(
                    "SELECT data FROM objects WHERE kind=? AND id=?", (kind, identifier)
                ).fetchone()
                is None
            )
            assert auth.job_audit_status(family, identifier) == "pending"
            observed.append(identifier)

    monkeypatch.setattr(store, "_write", before_commit)
    try:
        with authority(auth):
            row, _ = admit(store)
        assert observed == [row["id"]]
        monkeypatch.setattr(store, "_write", original)
        claimed = store.claim("worker")
        assert claimed["id"] == row["id"]
        assert auth.job_audit_status(family, claimed["id"]) == "pending"
    finally:
        observer.close()


@pytest.mark.parametrize("terminal_path", ["publish", "worker_exited", "reconcile", "claim"])
def test_terminal_lifecycle_paths(domain, terminal_path):
    family, store, auth, clock = domain
    store.auth_store = auth
    with authority(auth):
        row, _ = admit(store)
    if terminal_path in {"publish", "worker_exited"}:
        claim = store.claim("worker")
        if terminal_path == "publish":
            store.publish(claim, "FAILED", b"{}")
        else:
            store.worker_exited(claim)
    else:
        clock[0] += 61
        getattr(store, terminal_path)(*(["worker"] if terminal_path == "claim" else []))
    assert store.get("alice", "job", row["id"])["status"] == "FAILED"
    assert auth.job_audit_status(family, row["id"]) == "complete"
