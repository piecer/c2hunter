import json
import uuid

import pytest
import test_account_auth_store as support

PASSWORD = support.PASSWORD
module = support.module
store = support.store
admin = support.admin


def test_closed_audit_schema_filters_pagination_export_and_own_activity(store, admin):
    from c2hunter_controller.auth_models import Actor
    from c2hunter_controller.security import Role

    request_id = str(uuid.uuid4())
    event = store.record_event(
        admin.actor, "http.operation", "/api/v1/jobs/{job_id}", "started", request_id=request_id
    )
    page = store.list_audit(admin.token, action="http.operation", limit=1)
    assert page["total"] == 1
    assert page["items"][0] == dict(
        id=event,
        timestamp=page["items"][0]["timestamp"],
        actor_id=admin.user.id,
        actor_name="admin",
        actor_role="ADMIN",
        auth_kind="session",
        action="http.operation",
        target="/api/v1/jobs/{job_id}",
        outcome="started",
        request_id=request_id,
        source_ip=None,
        status=None,
        job_id=None,
        details={},
    )
    for kwargs in [
        dict(limit=1001),
        dict(offset=-1),
        dict(since=float("nan")),
        dict(outcome="secret"),
        dict(action="unregistered"),
    ]:
        with pytest.raises(module().AuthError):
            store.list_audit(admin.token, **kwargs)
    for details in [
        dict(password=PASSWORD),
        dict(reason=PASSWORD),
        dict(count=True),
        dict(role="ROOT"),
        dict(active="true"),
    ]:
        with pytest.raises(module().AuthError, match="INVALID_AUDIT"):
            store.record_event(
                admin.actor, "http.operation", "/api/v1/jobs", "failed", details=details
            )
    for target in ["https://evil.test/?token=secret", "/enrollment/secret-token?x=y", PASSWORD]:
        with pytest.raises(module().AuthError, match="INVALID_AUDIT"):
            store.record_event(Actor(), "http.operation", target, "failed")
    export = store.export_audit(admin.token, limit=2)
    assert len(export.content.splitlines()) == 2
    assert export.next_offset == 2
    assert export.total >= 3
    assert any(e["action"] == "audit.export" for e in store.list_audit(admin.token)["items"])
    store.create_user(admin.token, "alice", PASSWORD, Role.VIEWER)
    alice = store.login("alice", PASSWORD)
    store.change_password(alice.token, PASSWORD, PASSWORD + " changed")
    alice = store.login("alice", PASSWORD + " changed")
    with pytest.raises(module().AuthError, match="INSUFFICIENT_ROLE"):
        store.list_audit(alice.token)
    own = store.list_audit(alice.token, own=True, user_id=admin.user.id)
    assert all(item["actor_id"] == alice.user.id for item in own["items"])
    assert PASSWORD not in json.dumps(own)


def test_audit_export_outage_does_not_publish(store, admin):
    import sqlite3

    with sqlite3.connect(store.sqlite_path) as db:
        db.execute(
            "CREATE TRIGGER deny_audit BEFORE INSERT ON auth_audit BEGIN "
            "SELECT RAISE(ABORT,'denied'); END"
        )
    with pytest.raises(module().AuthError, match="SECURITY_UNAVAILABLE"):
        store.export_audit(admin.token)
