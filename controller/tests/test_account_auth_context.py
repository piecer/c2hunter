"""Server-only admitted identity survives explicit background handoff."""

from concurrent.futures import ThreadPoolExecutor
from importlib import import_module, util
from uuid import uuid4

from c2hunter_controller.auth_models import Actor
from c2hunter_controller.auth_store import AuthStore
from c2hunter_controller.security import Role


def test_captured_reservation_keeps_actor_after_request_scope_retires(tmp_path):
    name = "c2hunter_controller.auth_job_context"
    assert util.find_spec(name) is not None, "server-only job audit context must exist"
    module = import_module(name)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    store = AuthStore(sqlite_path=private / "auth.sqlite3")
    store.initialize()
    first = Actor(uuid4().hex, "first-user", Role.ANALYST, "session")
    second = Actor(uuid4().hex, "second-user", Role.ANALYST, "session")
    request_id, intent_id, job_id = str(uuid4()), uuid4().hex, str(uuid4())
    assert module.current_job_audit() is None
    with module.bind_job_audit(store, first, request_id, intent_id) as admitted:
        assert module.current_job_audit() is admitted
        reservation = admitted.reserve
    assert module.current_job_audit() is None
    with module.bind_job_audit(store, second, str(uuid4()), uuid4().hex):
        with ThreadPoolExecutor(max_workers=1) as executor:
            assert executor.submit(module.current_job_audit).result(timeout=5) is None
            link = executor.submit(reservation, "analysis", job_id).result(timeout=5)
        assert module.current_job_audit().actor == second
    assert module.current_job_audit() is None
    assert link.actor == first
    assert (link.request_id, link.intent_id, link.resource_id) == (request_id, intent_id, job_id)
    assert store.job_audit_status("analysis", job_id) == "pending"
