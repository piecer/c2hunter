"""Storage custody fixtures only: not JOB producer/model/wire witnesses."""

import base64
import hashlib
import importlib
import json
import zlib

import pytest

from c2hunter_controller import ai_investigation_store as ip_api
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def job_api():
    name = "c2hunter_controller.ai_job_investigation_store"
    assert importlib.util.find_spec(name) is not None, "JOB custody facade is missing"
    return importlib.import_module(name)


def raw(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def admit(store, owner="alice", key="key", job="job", **documents):
    return store.admit(
        owner_id=owner,
        job_id=job,
        idempotency_key=key,
        request_json=documents.get("request_json", raw({"custody": "request"})),
        binding_json=documents.get("binding_json", raw({"custody": "binding"})),
        snapshot_json=documents.get("snapshot_json", raw({"custody": "preparation"})),
    )


@pytest.fixture(params=["memory", "sqlite"])
def pair(request, tmp_path):
    api = job_api()
    repo = (
        MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "runs.db")
    )
    clock = [1000.0]
    try:
        ip_api.initialize_investigation_store(repo)
        with pytest.raises(ip_api.InvestigationStoreError, match="STORE_NOT_INITIALIZED"):
            api.JobInvestigationRunStore(repo)
        api.initialize_job_investigation_store(repo)
        yield (
            ip_api.InvestigationRunStore(repo, clock=lambda: clock[0]),
            api.JobInvestigationRunStore(repo, clock=lambda: clock[0]),
            repo,
            clock,
        )
    finally:
        if isinstance(repo, SQLiteRepository):
            repo.connection.close()


def test_sealed_profile_identity_reads_claims_and_initialization(pair):
    ip, job, repo, _ = pair
    ip_run, _ = admit(ip)
    job_run, _ = admit(job)
    assert ip_run["id"] == hashlib.sha256(raw(["alice", "key"])).hexdigest()
    assert job_run["id"] != ip_run["id"]
    assert set(ip_run) == {
        "id",
        "owner_id",
        "job_id",
        "status",
        "revision",
        "created_at",
        "progress",
    }
    for store, own, other in ((ip, ip_run, job_run), (job, job_run, ip_run)):
        assert store.page("alice", "job") == [own]
        assert store.get("alice", "job", other["id"]) is None
        assert store.saved_input("alice", "job", other["id"]) is None
        assert store.get("bob", "job", own["id"]) is None
        assert store.get("alice", "else", own["id"]) is None
        claim = store.claim("worker")
        assert claim["id"] == own["id"]
        if store is job:
            claim = select(job, claim)
        claim = store.append_step(claim, raw({"kind": "custody"}))
        claim = store.save_evidence(claim, "ev", raw({"kind": "custody"}))
        assert store.steps("alice", "job", other["id"]) == []
        assert store.evidence("alice", "job", other["id"], "ev") is None
        assert store.evidence("bob", "job", own["id"], "ev") is None
        assert store.worker_exited(claim)
    assert ip.claim("next") is None and job.claim("next") is None
    assert ip.page("alice", "job")[0]["status"] == "FAILED"
    assert job.page("alice", "job")[0]["status"] == "FAILED"
    if isinstance(repo, SQLiteRepository):
        kinds = {r[0] for r in repo.connection.execute("SELECT DISTINCT kind FROM objects")}
        assert {
            f"ai_job_investigation_{name}_v1" for name in ("run", "state", "step", "evidence")
        } <= kinds
        assert "ai_job_investigation_schema" in kinds
        indexes = {
            r[0]
            for r in repo.connection.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
        assert {f"job_investigation_{name}_v1" for name in ("queue", "owner", "slot")} <= indexes


def test_frozen_predecessor_claims_only_ip_in_real_mixed_sqlite_queue(tmp_path):
    import sys

    api = job_api()
    frozen = zlib.decompress(base64.b85decode(_FROZEN_IP_ZLIB_BASE85))
    assert hashlib.sha256(frozen).hexdigest() == _FROZEN_IP_SHA256
    spec = importlib.util.spec_from_loader("c2hunter_controller._frozen_ip_custody", loader=None)
    old = importlib.util.module_from_spec(spec)
    old.__file__ = __file__  # The frozen source is embedded in this test module.
    sys.modules[spec.name] = old
    exec(compile(frozen, __file__ + "::frozen_ip_custody", "exec"), old.__dict__)
    repo = SQLiteRepository(tmp_path / "mixed.db")
    try:
        old.initialize_investigation_store(repo)
        api.initialize_job_investigation_store(repo)
        predecessor = old.InvestigationRunStore(repo, clock=lambda: 1000.0)
        job = api.JobInvestigationRunStore(repo, clock=lambda: 1000.0)
        job_run, _ = admit(job)
        ip_run, _ = admit(predecessor)
        capable_ip = ip_api.InvestigationRunStore(repo, clock=lambda: 1000.0)
        before = repo.connection.execute(
            "SELECT kind,id,data FROM objects WHERE kind IN (?,?) ORDER BY kind,id",
            (ip_api.RUN_KIND, ip_api.STATE_KIND),
        ).fetchall()
        assert admit(capable_ip) == (ip_run, False)
        assert capable_ip.saved_input("alice", "job", ip_run["id"]) == predecessor.saved_input(
            "alice", "job", ip_run["id"]
        )
        assert (
            repo.connection.execute(
                "SELECT kind,id,data FROM objects WHERE kind IN (?,?) ORDER BY kind,id",
                (ip_api.RUN_KIND, ip_api.STATE_KIND),
            ).fetchall()
            == before
        )
        claim = predecessor.claim("old-worker")
        assert claim["id"] == ip_run["id"] != job_run["id"]
        assert predecessor.worker_exited(claim)
        assert predecessor.claim("old-worker") is None
        assert job.get("alice", "job", job_run["id"])["status"] == "QUEUED"
        assert job.claim("capable-worker")["id"] == job_run["id"]
    finally:
        repo.connection.close()
        sys.modules.pop(spec.name)


def test_new_capable_profiles_share_owner_queue_and_global_queue(pair):
    ip, job, _, _ = pair
    first, _ = admit(ip)
    admit(ip, key="ip2")
    admit(job)
    admit(job, key="job2")
    for store in (ip, job):
        with pytest.raises(ip_api.InvestigationStoreError, match="OWNER_QUEUE_FULL"):
            admit(store, key="overflow")
    assert admit(ip) == (first, False)
    for owner in ("bob", "carol", "dave"):
        for i in range(4):
            admit((ip, job)[i % 2], owner=owner, key=str(i))
    for store in (ip, job):
        with pytest.raises(ip_api.InvestigationStoreError, match="^QUEUE_FULL$"):
            admit(store, owner="eve")
    assert len(ip.page("alice", "job")) == len(job.page("alice", "job")) == 2


def test_new_capable_profiles_share_retention_without_evicting_replay(pair):
    ip, job, _, _ = pair
    first = None
    for i in range(256):
        store = (ip, job)[i % 2]
        run, _ = admit(store, key=str(i))
        cancelled = store.cancel("alice", "job", run["id"])
        if i == 0:
            first = cancelled
    for store in (ip, job):
        with pytest.raises(ip_api.InvestigationStoreError, match="RETENTION_FULL"):
            admit(store, key="overflow")
    assert admit(ip, key="0") == (first, False)


@pytest.mark.parametrize("first_kind", ["ip", "job"])
def test_shared_physical_slots_survive_cancel_expiry_until_actual_exit(pair, first_kind):
    ip, job, _, clock = pair
    first, second = (ip, job) if first_kind == "ip" else (job, ip)
    run, _ = admit(first)
    held = first.claim("one")
    admit(second)
    assert second.claim("same-owner") is None
    first.cancel("alice", "job", run["id"])
    assert second.claim("cancel-is-not-exit") is None
    admit(second, owner="bob")
    other = second.claim("two")
    assert other["owner_id"] == "bob"
    admit(first, owner="carol")
    assert first.claim("global-full") is None
    clock[0] += 31
    second.reconcile()
    assert first.claim("expired-is-not-exit") is None
    assert second.claim("expired-is-not-replay") is None
    assert first.worker_exited(held)
    assert second.claim("replacement")["owner_id"] == "alice"
    assert first.claim("still-global-full") is None
    assert second.worker_exited(other)
    assert first.claim("now-free")["owner_id"] == "carol"


def select(store, claim, peer_ids=("a" * 64,)):
    charged = store.reserve_selection(claim)
    return store.commit_selection(
        charged, selected_peer_ids=peer_ids, commitment=charged["commitment"]
    )


def test_selection_is_charged_claim_fenced_once_and_precedes_seed_custody(pair):
    _, job, _, _ = pair
    run, _ = admit(job)
    assert run["selection"] == {"state": "PENDING", "peer_ids": []}
    saved = job.saved_input("alice", "job", run["id"])
    claim = job.claim("worker")
    with pytest.raises(ip_api.InvestigationStoreError, match="SELECTION_REQUIRED"):
        job.save_evidence(claim, "seed", raw({}))
    with pytest.raises(ip_api.InvestigationStoreError, match="SELECTION_NOT_RESERVED"):
        job.commit_selection(claim, selected_peer_ids=("a" * 64,), commitment=saved["commitment"])
    charged = job.reserve_selection(claim)
    assert charged["budgets"]["tool_calls"] == 1
    assert job.get("alice", "job", run["id"])["progress"]["tool_calls"] == 1
    with pytest.raises(ip_api.InvestigationStoreError, match="STALE_CLAIM"):
        job.commit_selection(claim, selected_peer_ids=("a" * 64,), commitment=saved["commitment"])
    with pytest.raises(ip_api.InvestigationStoreError, match="COMMITMENT_MISMATCH"):
        job.commit_selection(charged, selected_peer_ids=("a" * 64,), commitment="0" * 64)
    committed = job.commit_selection(
        charged, selected_peer_ids=("a" * 64, "b" * 64), commitment=saved["commitment"]
    )
    public = job.get("alice", "job", run["id"])
    assert public["selection"] == {"state": "COMMITTED", "peer_ids": ["a" * 64, "b" * 64]}
    assert public["revision"] == committed["revision"] == charged["revision"] + 1
    assert public["progress"]["tool_calls"] == 1
    assert job.saved_input("alice", "job", run["id"]) == saved
    # Invalid reselection costs another unit before the later broker decides membership/state.
    charged_again = job.reserve_selection(committed)
    with pytest.raises(ip_api.InvestigationStoreError, match="INVALID_SELECTION_STATE"):
        job.commit_selection(
            charged_again, selected_peer_ids=("c" * 64,), commitment=saved["commitment"]
        )
    assert job.get("alice", "job", run["id"])["progress"]["tool_calls"] == 2
    claim = job.reserve(charged_again, tool_calls=1)
    claim = job.save_evidence(claim, "seed", raw({"custody": "not-semantic-evidence"}))
    assert claim["budgets"]["tool_calls"] == 3
    assert admit(job)[0]["selection"] == public["selection"]


@pytest.mark.parametrize(
    "ids", [(), ("a" * 64,) * 2, ("a" * 64,) * 4, ("A" * 64,), (True,), ["a" * 64]]
)
def test_selection_rejects_invalid_scalar_ids_without_refunding_charge(pair, ids):
    _, job, _, _ = pair
    run, _ = admit(job)
    claim = job.reserve_selection(job.claim("worker"))
    with pytest.raises(ip_api.InvestigationStoreError, match="INVALID_SELECTION"):
        job.commit_selection(claim, selected_peer_ids=ids, commitment=claim["commitment"])
    public = job.get("alice", "job", run["id"])
    assert public["selection"]["state"] == "PENDING"
    assert public["progress"]["tool_calls"] == 1


@pytest.mark.parametrize(
    "fence", ["cancel", "generation", "token", "revision", "deadline", "lease"]
)
def test_selection_never_bypasses_owner_fences(pair, fence):
    _, job, _, clock = pair
    run, _ = admit(job)
    claim = job.reserve_selection(job.claim("worker"))
    if fence == "cancel":
        job.cancel("alice", "job", run["id"])
    elif fence in {"generation", "revision"}:
        claim[fence] += 1
    elif fence == "token":
        claim["lease_token"] = "forged"
    else:
        clock[0] = claim["deadline" if fence == "deadline" else "lease_expires_at"]
    with pytest.raises(ip_api.InvestigationStoreError, match="STALE_CLAIM"):
        job.commit_selection(claim, selected_peer_ids=("a" * 64,), commitment=claim["commitment"])
    assert job.get("alice", "job", run["id"])["selection"]["state"] == "PENDING"


def sized_document(size):
    document = raw({"x": "x" * (size - len(raw({"x": ""})))})
    assert len(document) == size
    return document


def test_job_preparation_limit_is_not_the_wider_ip_infrastructure_limit(pair):
    ip, job, _, _ = pair
    with pytest.raises(ip_api.InvestigationStoreError, match="INVALID_DOCUMENT"):
        admit(job, snapshot_json=sized_document(131073))
    assert admit(ip, snapshot_json=sized_document(131073))[1]
    assert admit(job, snapshot_json=sized_document(131072))[1]


@pytest.mark.parametrize("preparation_size", [2, 131072])
def test_job_retained_evidence_and_combined_bytes_are_bounded(pair, preparation_size):
    _, job, _, _ = pair
    snapshot = b"{}" if preparation_size == 2 else sized_document(preparation_size)
    run, _ = admit(job, snapshot_json=snapshot)
    claim = select(job, job.claim("worker"))
    for i in range(4):
        claim = job.save_evidence(claim, str(i), sized_document(32768))
    assert claim["observations_bytes"] == preparation_size + 131072
    with pytest.raises(ip_api.InvestigationStoreError, match="EVIDENCE_BYTES_LIMIT"):
        job.save_evidence(claim, "overflow", b"{}")
    assert job.evidence("alice", "job", run["id"], "overflow") is None
    assert job.get("alice", "job", run["id"])["revision"] == claim["revision"]


@pytest.mark.parametrize(("counter", "cap"), [("source_bytes", 8650752), ("source_records", 8192)])
def test_job_source_reservations_do_not_inherit_wider_infrastructure_caps(pair, counter, cap):
    _, job, _, _ = pair
    admit(job)
    claim = job.claim("worker")
    claim = job.reserve(claim, **{counter: cap})
    with pytest.raises(ip_api.InvestigationStoreError, match="BUDGET_EXHAUSTED"):
        job.reserve(claim, **{counter: 1})


def test_selection_and_seeds_share_all_twelve_tool_units(pair):
    _, job, _, _ = pair
    run, _ = admit(job)
    claim = job.reserve(job.claim("worker"), tool_calls=11)
    claim = select(job, claim)
    assert claim["budgets"]["tool_calls"] == 12
    for operation in (
        lambda: job.reserve_selection(claim),
        lambda: job.reserve(claim, tool_calls=1),
    ):
        with pytest.raises(ip_api.InvestigationStoreError, match="BUDGET_EXHAUSTED"):
            operation()
    assert job.get("alice", "job", run["id"])["progress"]["tool_calls"] == 12


def test_job_final_and_step_limits_are_unchanged_storage_ceilings(pair):
    _, job, _, _ = pair
    admit(job)
    claim = select(job, job.claim("worker"))
    for i in range(24):
        claim = job.append_step(claim, raw({"custody_step": i}))
    with pytest.raises(ip_api.InvestigationStoreError, match="STEP_LIMIT"):
        job.append_step(claim, b"{}")
    claim = job.transition(claim, "INVESTIGATING")
    claim = job.transition(claim, "VALIDATING")
    with pytest.raises(ip_api.InvestigationStoreError, match="INVALID_DOCUMENT"):
        job.publish(claim, "PARTIAL", sized_document(16385))
    assert job.publish(claim, "PARTIAL", sized_document(16384))["status"] == "PARTIAL"


def test_sealed_generic_job_constructor_cannot_reuse_ip_identity(pair):
    ip, _, repo, clock = pair
    generic_job = ip_api.InvestigationRunStore(
        repo, clock=lambda: clock[0], _profile=ip_api._JOB_PROFILE
    )
    original, _ = admit(ip)
    other, _ = admit(generic_job)
    assert original["id"] != other["id"]
    assert other["selection"] == {"state": "PENDING", "peer_ids": []}
    with pytest.raises(AttributeError):
        generic_job._profile = ip_api._IP_PROFILE
    with pytest.raises(ip_api.InvestigationStoreError, match="INVALID_PROFILE"):
        ip_api.InvestigationRunStore(repo, _profile="client-kind")
    with pytest.raises(ip_api.InvestigationStoreError, match="INVALID_PROFILE"):
        ip_api._initialize_profile(repo, "client-kind")
    with pytest.raises(ip_api.InvestigationStoreError, match="INVALID_PROFILE"):
        ip.reserve_selection({})


def durable_job_state(repo, identifier):
    import sqlite3

    with sqlite3.connect(f"file:{repo._path}?mode=ro", uri=True) as observer:
        return json.loads(
            observer.execute(
                "SELECT data FROM objects WHERE kind=? AND id=?",
                ("ai_job_investigation_state_v1", identifier),
            ).fetchone()[0]
        )


def test_selection_sqlite_reopen_replay_and_owner_isolation(tmp_path):
    api = job_api()
    repo = SQLiteRepository(tmp_path / "selection-reopen.db")
    api.initialize_job_investigation_store(repo)
    try:
        store = api.JobInvestigationRunStore(repo, clock=lambda: 1000.0)
        run, _ = admit(store)
        original = store.saved_input("alice", "job", run["id"])
        claim = select(store, store.claim("worker"))
        claim = store.save_evidence(claim, "seed", raw({"custody": "saved"}))
        public = store.get("alice", "job", run["id"])
    finally:
        repo.connection.close()
    reopened_repo = SQLiteRepository(repo._path)
    try:
        reopened = api.JobInvestigationRunStore(reopened_repo, clock=lambda: 1000.0)
        assert admit(reopened) == (public, False)
        assert reopened.saved_input("alice", "job", run["id"]) == original
        assert reopened.evidence("alice", "job", run["id"], "seed") == {"custody": "saved"}
        assert reopened.page("bob", "job") == []
        assert reopened.evidence("alice", "other", run["id"], "seed") is None
        assert reopened.cancel("bob", "job", run["id"]) is None
        assert reopened.claim("no-implicit-replay") is None
        with pytest.raises(ip_api.InvestigationStoreError, match="IDEMPOTENCY_CONFLICT"):
            admit(reopened, job="other")
        assert reopened.worker_exited(claim)
    finally:
        reopened_repo.connection.close()


@pytest.mark.parametrize("operation", ["selection", "evidence", "exit"])
def test_ambiguous_job_writes_quarantine_both_profiles_without_ack(tmp_path, operation):
    from test_ai_investigation_store import CommitThenRaise

    api = job_api()
    repo = SQLiteRepository(tmp_path / "ambiguous.db")
    ip_api.initialize_investigation_store(repo)
    api.initialize_job_investigation_store(repo)
    store = api.JobInvestigationRunStore(repo, clock=lambda: 1000.0)
    ip = ip_api.InvestigationRunStore(repo, clock=lambda: 1000.0)
    run, _ = admit(store)
    claim = store.reserve_selection(store.claim("worker"))
    if operation != "selection":
        claim = store.commit_selection(
            claim, selected_peer_ids=("a" * 64,), commitment=claim["commitment"]
        )
    repo.connection = CommitThenRaise(repo.connection)
    try:
        with pytest.raises(ip_api.InvestigationOutcomeUnknown):
            if operation == "selection":
                store.commit_selection(
                    claim, selected_peer_ids=("a" * 64,), commitment=claim["commitment"]
                )
            elif operation == "evidence":
                store.save_evidence(claim, "ev", raw({"custody": "saved"}))
            else:
                store.worker_exited(claim)
        for blocked in (lambda: store.get("alice", "job", run["id"]), lambda: ip.claim("worker")):
            with pytest.raises(ip_api.InvestigationOutcomeUnknown):
                blocked()
        durable = durable_job_state(repo, run["id"])
        assert durable["selected_peer_ids"] == ["a" * 64]
        assert durable["slot"] == ("FREE" if operation == "exit" else "HELD")
        independent = SQLiteRepository(repo._path)
        try:
            reopened = api.JobInvestigationRunStore(independent, clock=lambda: 1000.0)
            assert admit(reopened)[1] is False
            if operation == "evidence":
                assert reopened.evidence("alice", "job", run["id"], "ev") == {"custody": "saved"}
            assert reopened.claim("no-replay") is None
        finally:
            independent.connection.close()
    finally:
        repo.connection.close()


def test_selection_sqlite_fault_rolls_back_revision_and_keeps_charge(tmp_path):
    api = job_api()
    repo = SQLiteRepository(tmp_path / "selection-fault.db")
    api.initialize_job_investigation_store(repo)
    store = api.JobInvestigationRunStore(repo, clock=lambda: 1000.0)
    run, _ = admit(store)
    claim = store.reserve_selection(store.claim("worker"))
    calls = []
    repo.connection.create_function("selection_fault_seen", 0, lambda: calls.append(True) or 1)
    repo.connection.execute(
        "CREATE TEMP TRIGGER selection_fault BEFORE UPDATE ON objects "
        "WHEN NEW.kind='ai_job_investigation_state_v1' "
        "BEGIN SELECT selection_fault_seen(); SELECT RAISE(ABORT,'owned fault'); END"
    )
    try:
        with pytest.raises(ip_api.InvestigationStorageError):
            store.commit_selection(
                claim, selected_peer_ids=("a" * 64,), commitment=claim["commitment"]
            )
        assert calls == [True]
        state = durable_job_state(repo, run["id"])
        assert state["selected_peer_ids"] is None and state["revision"] == claim["revision"]
        assert state["budgets"]["tool_calls"] == 1 and state["selection_reserved"] is True
        assert not repo.connection.in_transaction
        repo.connection.execute("DROP TRIGGER selection_fault")
        assert store.commit_selection(
            claim, selected_peer_ids=("a" * 64,), commitment=claim["commitment"]
        )["selected_peer_ids"] == ["a" * 64]
    finally:
        repo.connection.close()


def test_selection_final_write_rechecks_deadline(pair, monkeypatch):
    _, job, _, clock = pair
    run, _ = admit(job)
    claim = job.reserve_selection(job.claim("worker"))
    save = job._save_state
    entered = []

    def delayed(tx, state, **kwargs):
        entered.append(True)
        clock[0] = claim["deadline"]
        return save(tx, state, **kwargs)

    monkeypatch.setattr(job, "_save_state", delayed)
    with pytest.raises(ip_api.InvestigationStoreError, match="STALE_CLAIM"):
        job.commit_selection(claim, selected_peer_ids=("a" * 64,), commitment=claim["commitment"])
    assert entered == [True]
    public = job.get("alice", "job", run["id"])
    assert public["revision"] == claim["revision"] and public["selection"]["state"] == "PENDING"


def test_job_operations_and_initialization_do_not_commit_borrowed_transaction(tmp_path):
    import sqlite3

    api = job_api()
    repo = SQLiteRepository(tmp_path / "borrowed.db")
    api.initialize_job_investigation_store(repo)
    store = api.JobInvestigationRunStore(repo, clock=lambda: 1000.0)
    repo.connection.execute("BEGIN IMMEDIATE")
    repo.connection.execute("INSERT INTO objects VALUES('caller','uncommitted','{}')")
    try:
        for operation in (
            lambda: api.initialize_job_investigation_store(repo),
            lambda: api.JobInvestigationRunStore(repo),
            lambda: admit(store),
            lambda: store.page("alice", "job"),
        ):
            with pytest.raises(ip_api.InvestigationStoreError, match="STORE_BUSY"):
                operation()
            assert repo.connection.in_transaction
            assert repo.connection.execute(
                "SELECT count(*) FROM objects WHERE kind='caller'"
            ).fetchone() == (1,)
        with sqlite3.connect(f"file:{repo._path}?mode=ro", uri=True) as observer:
            assert observer.execute(
                "SELECT count(*) FROM objects WHERE kind='caller'"
            ).fetchone() == (0,)
        repo.connection.commit()
        assert admit(store)[1]
    finally:
        repo.connection.close()


@pytest.mark.parametrize("ceiling", ["owner_queue", "queue", "retention", "owner_held", "held"])
def test_sqlite_independent_profiles_race_for_last_shared_capacity(tmp_path, ceiling):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    api = job_api()
    path = tmp_path / "capacity-race.db"
    repos = [SQLiteRepository(path), SQLiteRepository(path)]
    ip_api.initialize_investigation_store(repos[0])
    api.initialize_job_investigation_store(repos[0])
    stores = [
        ip_api.InvestigationRunStore(repos[0], clock=lambda: 1000.0),
        api.JobInvestigationRunStore(repos[1], clock=lambda: 1000.0),
    ]
    try:
        count = {"owner_queue": 3, "queue": 15, "retention": 255, "owner_held": 0, "held": 0}[
            ceiling
        ]
        for i in range(count):
            store = stores[i % 2]
            owner = "alice" if ceiling == "owner_queue" else f"owner-{i}"
            run, _ = admit(store, owner=owner, key=str(i))
            if ceiling == "retention":
                store.cancel(owner, "job", run["id"])
        if ceiling == "held":
            admit(stores[0], owner="already-held")
            assert stores[0].claim("existing") is not None
        if ceiling in {"held", "owner_held"}:
            for i, store in enumerate(stores):
                admit(store, owner="alice" if ceiling == "owner_held" else f"contender-{i}")
        barrier = Barrier(2)

        def attempt(index):
            barrier.wait(timeout=10)
            store = stores[index]
            try:
                if ceiling in {"held", "owner_held"}:
                    return store.claim(f"worker-{index}") is not None
                admit(
                    store,
                    owner="alice" if ceiling == "owner_queue" else f"last-{index}",
                    key="last",
                )
                return True
            except ip_api.InvestigationStoreError as error:
                assert (
                    error.code
                    == {
                        "owner_queue": "OWNER_QUEUE_FULL",
                        "queue": "QUEUE_FULL",
                        "retention": "RETENTION_FULL",
                    }[ceiling]
                )
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(attempt, (0, 1))) == [False, True]
    finally:
        for repo in repos:
            repo.connection.close()


def test_sqlite_selection_has_exactly_one_cross_connection_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    api = job_api()
    path = tmp_path / "selection-race.db"
    repos = [SQLiteRepository(path), SQLiteRepository(path)]
    api.initialize_job_investigation_store(repos[0])
    stores = [api.JobInvestigationRunStore(repo, clock=lambda: 1000.0) for repo in repos]
    run, _ = admit(stores[0])
    claim = stores[0].reserve_selection(stores[0].claim("worker"))
    barrier = Barrier(2)

    def commit(index):
        barrier.wait(timeout=10)
        try:
            stores[index].commit_selection(
                claim, selected_peer_ids=(str(index) * 64,), commitment=claim["commitment"]
            )
            return index
        except ip_api.InvestigationStoreError as error:
            assert error.code == "STALE_CLAIM"
            return None

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(commit, (0, 1)))
        winners = [outcome for outcome in outcomes if outcome is not None]
        assert len(winners) == 1
        state = durable_job_state(repos[0], run["id"])
        assert state["selected_peer_ids"] == [str(winners[0]) * 64]
        assert state["revision"] == claim["revision"] + 1
        assert state["budgets"]["tool_calls"] == 1
    finally:
        for repo in repos:
            repo.connection.close()


def test_job_initialization_is_explicit_and_profile_local(pair):
    _, job, repo, _ = pair
    before = job.page("alice", "job")
    ip_api.initialize_investigation_store(repo)
    assert job.page("alice", "job") == before
    if isinstance(repo, SQLiteRepository):
        statements = []
        repo.connection.set_trace_callback(statements.append)
        job_api().JobInvestigationRunStore(repo)
        run, _ = admit(job)
        job.get("alice", "job", run["id"])
        job.lookup(
            owner_id="alice",
            job_id="job",
            idempotency_key="key",
            request_json=raw({"custody": "request"}),
        )
        assert not any("CREATE" in sql for sql in statements)
        plan = repo.connection.execute(
            "EXPLAIN QUERY PLAN SELECT data FROM objects WHERE kind=? "
            "AND json_extract(data,'$.slot')='HELD' ORDER BY id LIMIT 2",
            ("ai_job_investigation_state_v1",),
        ).fetchall()
        assert any("job_investigation_slot_v1" in str(row) for row in plan)


def test_job_postgres_sql_path_uses_shared_lock_not_live_postgres():
    from test_ai_investigation_store import PostgresConnectionModel

    from c2hunter_controller.production import PostgresRepository

    api = job_api()
    repo = PostgresRepository("not-used", None)
    connection = PostgresConnectionModel()
    repo._connection = connection
    try:
        ip_api.initialize_investigation_store(repo)
        api.initialize_job_investigation_store(repo)
        ip = ip_api.InvestigationRunStore(repo, clock=lambda: 1000.0)
        job = api.JobInvestigationRunStore(repo, clock=lambda: 1000.0)
        admit(ip)
        run, _ = admit(job)
        connection.statements.clear()
        claim = select(job, job.claim("capable"))
        assert ip.claim("blocked-same-owner") is None
        assert job.get("alice", "job", run["id"])["selection"]["state"] == "COMMITTED"
        assert job.worker_exited(claim)
        assert any("pg_try_advisory_xact_lock(2026110501)" in s for s in connection.statements)
        assert any("%s::jsonb" in s for s in connection.statements)
        assert not any("CREATE" in s for s in connection.statements)
        connection.lock_available = False
        with pytest.raises(ip_api.InvestigationStoreError, match="STORE_BUSY"):
            admit(job, key="blocked")
    finally:
        connection.database.close()


# Exact IP predecessor at d7870a4; independent module, not a new-profile simulation.
# Embedded to keep the regression runnable after source-only export/integration.
_FROZEN_IP_SHA256 = "32f23ce9dc4b17979d1ec79c3c03336a7c825038d367fc0bc1d82023265a5aab"
_FROZEN_IP_ZLIB_BASE85 = (
    "c-rk<|99IqlK)+Q1&(|BBBrcryQ!O1t8^8cY4ze*URiFp=kwE}Mc8IdkqSx4_WJz4-weKx00B~R((b-{w`pG@k-z"
    "|$8O(fU@I{W}oYG~G1qCJHDhn=SN=C_==0$WJ6j7Rx$tof9RbHgw!*?V}$?#<4kvv^xb13=Mn4}q5q#=#TJc#4G*"
    "XfLssEC3%`UfTSei=vesE8j(P>_r+(>yBD?1AJ(kQJ+Ck4$eUxeDe%NJ&E1G$ZqjLSJ%{&u{1=AZgMG!bOzl&=p?"
    "#16=@xNkuCNgJl6Vqns?WbWZd9%Q%J3cqGX2VR56i-Rn4x)9GAg>4MB=SF2)`(b<edi)ES>BuJ99U<1!P9r5fY$Z"
    "z84Qhxm{hfayli=eoXpK}U*FLL>{h!&K$GEd`}&Kb>Ka5<Mv9RR<O-yRu3_XFsgES?nfzJL~GN%3S6B*8TmrNW>H"
    "=5dhcz$;O#eB_a<h{ho=Slj?d!zj6y#U@AT{8qesSSl}u$pe3UM}ympUdiXbz}NTm;V@!j2(kyky<W-GsOm&rJRU"
    "jy+fh`|>Pe?FIXj-c9~~c(0daz87ODC+%T~#3z3X&Nr^Bh=Tnsd*pse83pL`e{509W2bn729$!XDjbPmQJPLBMkf"
    "9QC`IT=o-qu~*LJQyAy_(w<l`Mco=KRvn7oPW~R8eOu+{GUgMJ`iXwO4m_HlR59(+q1(T{pl$beC!bT<FKhRV^hW"
    "HlYNgrEz-1lxVtBxW<io8Q)fX@(8aRQ-ts9pyL^Dzf~3CP-Ff|b|CRnWqw_QiS-l<n<8_`ooz7oNP3f?|$xKKsz0"
    "3Qoeuke&2ogVsX&Te>yvShI7uf~>8+nZ?)(z=Zu!@Tr%wd%60IRr+M3jW|zL5qk@ax4ULY>a+ga2VX`L%Cq;kl`5"
    "$~cg+QKjojdb6YP!FwpeCIdeH+u3k3Jf4n@{X<(@FgHAM31VuZ+YzkPjOQtIi~3oXX5F8Ic*Q@uoW(F;us;zP%h{"
    "}()A-7Rc^=X}a>ylLz9GkHLU~dAgC%-c0NTfYsu!yz&AM){q=j!=`U56}_XrF-+9<V8U>Q$nmPerOpuu36qnL&u!"
    "xRiZ*v9#7lHS3SYw#5`j=)?$p!o;$1RufTrNR?nJ+P`hW@v5w7_W+Xx}awX5=^>{eXP25kS-Qc@zp%0L9$wsJ236"
    "R;xf8krK`M0CNy2rgxp2N4GF-J+^N3il3sxn@JSpzh(0mqXY}JL$|x`_2_tN}&m`O|hv<s&p(<YrAq%3MHp*T~gt"
    "ZEsg|FQ;>O&uGE^7oD6Ely3LrR#F>4mGsGVhj+uqqw_1BWgv$mdZsco)PuMSl!d;+8(-gK36ka_-a9EFW|o4=r8a"
    "als+Rae6mPf`r#&l*^7?f_!Nbb}QCdy2lMa_}Os9lwX?tlQb``Gn%VrUa&06qXeuqD3n6lGaQAhaFg@ES+F9`210"
    "fJVj+}&jG@RTLgpAOq?V!(C)O@^=j{0O?BrxT0WUP0_$TAj(G+ZtQ|ZF}5=bGo=`t(Gl+Giv4X%$?{kU?_hJX3y&"
    "5K7?^XY|yBa<}=1@S^5R3m5wJjuN1Vh!)bfA(Yz*QxqJ=c|Hti+d(=(4UX7><j48f&xH+-f%O{3iNut3u{N=Z8=%"
    "W*OjsQ7=!(Szk6&tf&iTK@;3lSIqE3loD9KIHj_`?s^AY;<j?S^joQz{qci`s`{&$a|GQYH_N?DWu3Wl;P;uXr!v"
    "{+0fL)d0#XUOC8WLm7gIY7@sslD7>hs6SC5iZunHQWr%y=m<bp{~zw&EPHQ?Y4LLNt$67Hd$-n!$BWK@W#N`m^!b"
    "6mXJ1J3D@VJpSca;cbyU=u~0o2}iNObETiv^RhU-pVMVQeD;rKCtK!B>6gmRogEK<27ESrd*nMVw>)TzRhF0<RvM"
    "{g{xDCM*S+OOX``l<kWK+TuJVpntMmujQ~V>0z8GdNSQY7<`6Hubkc4W<D7i{|if%B}y2{C5V0NZAIy~|{gCgUGK"
    "YM$2`m3YAtz?Chy>A~&t?N;us;Z|^ujtKJ88{RWv&L>d<QWUyXb5jBA7WP+NkwU&KkK?$!A3b&RLUvpy!C$^se0N"
    "}?$n<Wz<3ZA;5?ck(n(jv;Keuji>+!O`3F<7yaskX%z|(o!Rv?FJ@Adq%kJLJ-u~|H&Nn-|u7z9$EjZmPTFh^Nmt"
    "7Y{-(^19ZQ{ONqK&*DqYoea!x02aH5w0S<wYHfV0!a7&1p>(cF9|%kArA15ItU4p)D-J+aRZ<Rlx8Zp4XIy1H2iB"
    "o`#ZH6|L4ddJx1iwV~O%V4+iQ-xwxntKd?UGs~dk^wwT(;QsdA+`g;2*buF2)lAZ=UpcSr{DrLn6Hh_+y~^;r_MU"
    "%^gR=O6hF&zFGE1LWe>$HrsNc<{RlVWJEGlzpMnVF{V}<IKIzp)9iv*lZxRFJ4odw+X58qAw2`O%<;>};=1lTW=Z"
    ")IT?H6ck6BY-Yg!Ub32zOvMy#PAi*7|v0n@S5l1Z+bZ`L`p!z=t_j&b=?{|XJ1PQJka`~<96POX5?0ZHW$ql;Nr3"
    "=2qsAa2vH>2a>QafWav5{S9C=IdUhS|@Ey-}y;>RIGtF2T_GuP{h*f_}FY%LEJde|YQ)D010yTxKf(qmTM1Q^C(g"
    "*?!r~9Y{9LgA<T!)Pd6;2FGw@hV(VA{ER6SG`72NNG05*ZyI`hO>*cjS0HCH~(>r_)oS>+vJ9@@cl-CF5fvKtFLT"
    "6uY-k5_*ry;GVoFbjdG2`4gYu%fXAsDrX4sklC-UYd(`aXu?+Zk=IA<jE+zJ$rJ`W9m`?x9!H^vahFR(6!L=y|G7"
    "BYgYogZqY<Et!!h#br_u3`PF?C|B9hHa)Rgru{{8sm)COe^s0=s5biP{91ZGrl2f+wt4m}b_;2`=SmO>9SOAJ#yE"
    "GgD-(c!U54Cd~T?@3G({^t7ur{f_fV5FnN+2Q!$?1O(im0_0Z4>5+qC?dG)g_Na3oK<o4<!c4Ouw)06VTq794Z^&"
    "OwG_c<{bR*h4>57r+zrMdunCy<9+2~{$f@kO7nOm!0mmo{=~F8z=)xl*_<<X!EsFG(>9Xd?%f9iVz@5EU?R_$xj%"
    "W+hp#5fm8N_kd`S1Ik9fx5Nn7+4cCg0*mB;jsuw>|ig0nj68M)%eQS=?d1QE%l5A`1+eIRvv4!9R~qu#7NKg}MuI"
    ")J>X2|6rPp50*im-=!HdguxtFa%M#e7978W{?ohQVFp0&D!O)_tW8+vx0szZ2AJhcmPqk})}f#4uBGI^AiI3{YdQ"
    "QLQzOkIaTIS8X&mJ?kv^ljZCb(XWsBbEI>W29=}B2p%U`-Z@r}hbFrC|p$W#gpv7=yJB{%Movm`=_;@gBGTn6>1L"
    "$?iyH?tE8*b>(8h6W*M@=GqezA)Q03}wy>oN>A@VD^XE9$<Q>o(|Y$#t{tVnwiPHogJgdx)<dvom(>__zs)<dJk+"
    "Z%!}?ENRZvVZ<#vGQF3d&MyV!zP#w#}D0%afKRom&Vk$H&7)(~2t&K|-MzZUr2N4EluFCbz^YaV9N?^hZj3F=(@8"
    "MsTHI6ONWw{ihB*WBnRBgQkdx9AV{8xW9<G{3r64i`zRdg#zDJ-~3T%Ug%fUl-)wNxLkR3;1nEzCy8BV5rO{g;2}"
    "v}J-eBVB!r2HxGyLo@@#HlSD~xp=;1m%N*dKa@C7!FE58;qf7f;DgglW)og=o2%+fu$Oa{JdU-1k`QQcM0WYvyb*"
    "g;&o`HoP?aTiy(y_&YCvty)U(SQl~-ggGC+?wJ-I@j*Qj1JIW<<L3f!!`L8Q|aP4sa68Ia2(m=RpfUkkY5apNXSu"
    "_fjnIxld&Pg}Tjo)QzCGBvzmR29_QB1dPRZ#9xzPr9npxc*RzKS}Q@u`|<JRfTuBC{migZWCmNf-VbQ83B(+0O)d"
    "XQww;cD>U??7(PbAZw6#X@$m;}#!Ls#2(pSwpW$5)B{T#Cw}KFayAQG8#Kr;b_qVg8q8W6m#l6siYfzJ}gSG-DyW"
    "C*nvYiG1%akrM_B2Lyr71cXpB+!TFWqK~gweQc$aCu=?X+4AF@gwVvGneI=R)UH5Oy^eR2c}lLRUV(zVM~GigzJQ"
    "jtIi|toGt%^^xTq*lY4X%wUO}Z&l*A^s@0ilNa0B!PW@T-iTsKo+OGfBEYRLFpJmP1nz1{5BAZ;+=j@0c-Xk>q7t"
    "lCqx!U+dcaHM3i@be6A=Sb$%AQpDt1XYtSc3Ex>O`>7-ERh0_hn9OO}ue-AMR}Xc$^WvnLwG+=0?Hx6Q{dGYZ0B+"
    "vWh4l=&X!GPRt~tzmecK#!|XP7FvNN!yHRa_oO12Wh-oBw8{m$SAaMPeBfs>6(6r*p}@Y1kQ83%8FDAu)R(bP{5S"
    "RHdq0Ir;0fq_A5z027Pk6zw_Em57n6tXjY224Digcwn2wR$RINyZ1S_kUEnfXwAa)F2(Dr*Sj#Z7>U!9Rk3_zJ6R"
    "KxU*nHv@t0`q^)38$An(@Uh)hC?js7hHzFZ>l#>suBluG=P&xeiwEU1ccmGIUUyC-D@6Xc$5wHr?o!%MyqP>FBYp"
    "=|-6Yf}&*<%p$z*KHF-inxS&TBOA}R_*yRi;i|yV=)*{jlUuDD=<_;CaS?fIi_vHlO&gWQp`LV;%`xpM+iuq&H5$"
    "F8EQGOUx#5${j}xBPZdfparm<tK3vQJ;;>P<NTK2FSez>^kg;72aAcj^r)M=})u0V7dEv5#HTImjYLD)=Di08a68"
    "5Rc197t=k63^g2o7=Q(19+Cv{+uMXEazI1_s-#%oShuvf&i|{Bc%bopU10^hCTddOVyjUm>IEWnqS3Ounoic*0}0"
    "-!%D0zrseHLK>b?_1XqRZ1v>faMU}uOm|jv48fF^Lbz^s71!x-65Um+WrDq{Gb>T~l-L00c*icRDq#?cX<+hNo)R"
    "UYAKSe`eP?<hUXrP!ZG1)Etso#Phb1e%#TP;DkX{{#}@rE7<r+aR+qxy4US*qb^_QkbYVg={IuyDsH1v|oDu_Um<"
    "LxdLO4c9sMyw6ljkM65)e;oS6F}4M39UXFxllVaZOtyw;fKMi!Wg0_Y!|w#-{ECgO6?i@ibiS#9PWa-G@#N5-khj"
    "0Wd%~PO!RWCWjdoSRG9g%?s93tInZzb@D3B-uG6Ue9S1?rF8p|FwK}r#}GU*|91^J=4E-H(=46bR-+!AR!1Rmp7L"
    "wtGZ88)tN+qN}rGPf_AlPy^=oSDk!Tt#by%~mOVrY9_e&mOX}e1eG7KYNUrP&|dQ@;ru-d_Mu)=Xe&(U1jUE1d=s"
    "F)MzS%609!cXx`22=73uPR#3P`On)$r4K%(DIPZjX20|SfI|iIrHN(JDmq;|4!+g3)!^#VDBU3zdYnlMh7t0in9X"
    "#OjV72?cT#r@;EDmJ#@|$4qoBeW0>b&Z9jod}GQ04Y+=zSPn(;WAwwRKgnk1@v@Gw6?$WsFq_rk*(>tjp}aBOdA~"
    "pXrcz<4XUBWVhNet8OmxX9wfS<m|+{W~UJo&GqoK0AIHghm^z<>k5>KAC;b;-(G0bWd}9CdWYZU!BWBq{0N#S8@1"
    "+6YLiAEpl#N0S(#9VYZ3^7!S+s5aAHDM#4_g73i_DuBmy$uNGN2!!Eh>Pi{Iuueh@O81%<sP2G#aAL2ghqV?jQ0#"
    "v2RR`V*Pn;9d$^1oIo_PuKKImbeA<u*}lm#7^)_8mGy1jz@oRBUujqlhY)0na*!|H36MFP#67D?p(0MAj+rI6p)Z"
    "A6`>(d_1Vu!Dabxf)7#au?rO?}Kn35u5~zDpH8Nbn{0RQE5F28)&TlGkN~GIs#*MY1`dU1SSC(Z-UbMJn3Rw$w6g"
    "%wdX8;%#kc}Ay+wzNc8^EcYOP#$yD*&I_?3M2XTW09<c?t1EZrQ2N($S&+;bc7Zj}LyG$*|BmS-FB3jIe`QJuAX$"
    "+6Vt>Hj?*YO|$6gL7bNC@_%^bLJhE_`BqV+)J3~0zHA3RHs4pOCFB2db<=U23C+`ZEswpCxBfd|0Fg(5gXDoMRs}"
    "omEtmE9k<oIiXB&<(`m8veYLl5V0FUhMfBpK^XTcm^T5!0;Ds8>enW%^fkCYcpsepRqUkXYM_sxe^DJsfiNV9r*8"
    "L`zx`^!8DmibL;sme5gpUKkoL7Y_We~uhwhh-{sJF&`<7`4<PdgRs4U-n&dghnlG>>k<M-`joliAr=AC5d9HKSzy"
    "fu2fKNO->3G=0!crp@z~<OQWbQmKOK8@dvQ3N1TZdCU!a+AJ5*M9UVCh8xJuIF~B_sA_M1dXZ{&G|IR`D?!L?R6("
    "M!@s+F=aw(Xj#2Nt~PSFGh%78o=B<=CIhl<u?wnoYjAUDq}D%=RHzk~{;&J)3EB(MUBwGkwF9O9oRG4XIRYpiVxs"
    "s5+Mh>Ws4_N7V^5&?Z_NKP3j>r$=xqGQ8Fhck$9qA(qx1;rahXJgzIHMF<>^4|dFV6&@dO4Z}?swtRG)76a$q#P="
    "-?T+@W|BNetLVu0?HZ+RWqHxb>X*)3;+{e2~{flY=Mre5YWTk{J~_+1hMHlJ0!u?-TTRj5>G)CKYdU+=Qfpi6GwY"
    "`iG1(P%6o;)VfkFW9NFh%#(w({C<7zI@n>!NpiwYuZ7pfgRiNqsLEHmGA@;2AlI`cu|V@vJEC|#sHkqr@7TFuskQ"
    "<mRd4gs)qCN&>Cmdc@=<P2o_f{j7$DwK+KHa_S-PF!S{Kv2DOip<?0WR5Z=C#MQa>7pXXnRYnI9zj<8)%T$B{Zq{"
    "r}Ngv;+sn8Dkk_kT-#%aFXzs4b%K&j?1J8IUSNd$i<_D!bn&+c|@mFCVQ-;<qJ%+ly+)e`#^MdaeLaq>513+P>;e"
    "ET>Ou#`>u>FKgpXJwGdWwZ&GC%QSqj?os1}Wqy+7%uwG{7CvoAvozo(Y_b6@@iYr-m}QNX#<on%Dz*7;n<@u=tI3"
    "S-zp(GhXl!=-%xo#Ic^pIwVJu7d@+mfv5$eHvT-O6$ha4~AEaV1pRiq147~snT@Zn3bY#3UNV%e2Xw1UE7%+q8Z#"
    "fSxTM%~c3GAwFb#L(eS{!tZv?HT3;0TmK(alh@}_V$bklP&0Hs^P4bdyuHUPnw-nwfD3!STxe;!g!a9%A6?6e-7e"
    "caTx|A>ys{YN=a(N9EAtWj@uU1uZZCQumwKEh6C{_z^}w|L|xeu%~89BqnI==3$X#PJ0oWN4fjSKVSAb_eHHaLZc"
    "yTrQEUv592S?*d4kG-|6|{sB*X+Tgv+WF6?LD-lQfI2qa=uBG}b^v>u}?ca1<vK|718Z53%ZT5!ZZcfhx8sKiLba"
    "VUoCXvB$p6R#}_}SG4=}Uc*rjCH~sAmk7Z;#8E;As5D=YuWgY_)d_BiatsP(`E8CCHcQbHGjbs1<F-r<v9QFF^9u"
    "hPE?p4tR$K9@Taz}w+b}6i*9)BJ^D_W)1=n0Wxnh&@d$I`bCDPMvgR*oQ2LLT{3i1sKr$m8j@wx?(mvyo83A4%g="
    ";-b6;Js6C{>{Kf45YZfW2eW{QU2dgMiZE@okkAw4QG{jx7~DRXQ(YR&75K1?mdmIV_c=SDQy8rk#OP7#*J(96-Mh"
    "EKeO^~XS4YQ+QI=f68{r<PwA4aE|w-s)VWMoNthG7#xQ0DuGm}DP+;U@`4tP(do^-H5Em|A0)aW8s0b|^S*-Fx#8"
    "pdv0U{{?{lGL>%V11ig4^pn%W+6wXn2k-y#}8Lcxg-4-C&+&Q``C#q5I_`G-&>S?ABjvvk$X?Fp|zT=@3z03EkA~"
    "nCQsE`rd7;R=4i8(2q26#Zztpfc_i-K0O+aKByZb1P0`YlGzx%b3?SxAC#~|e_Y<r(YBgt94b=T!iY(>@CaEvQbS"
    "z~mBnKj?pjt-?O{h5OB=f>W#l0J2kyt@-h=t&?IH{<pco7k?%djU8r`;S055$#JLF%wXZ)u4`Fa>)^t2Mc@EK}dx"
    "k1YaUMl6Vty6#Ig0oHYG$&k524Ootdp790$fww|404M?DR4s^lad!NH>sCmSTr@MUbszFYewh$fq)C*wFGI-g+V|"
    "oR|jeJq{l`Tu*(a~M^;<{VvzUtK3h<qo^We+v#QND#troskzA)^GUs5`<fttjWk;&4{eh(ycCN93M&)tX2DW+XX8"
    "C^!51UsyyS0f>Zf-X*dO{w%YDmO(e)^}=(T~F^K4AOd^+)`s($S$P@MJxp!FP{NC&S~@5iSC^E{hsrg6QubC1IA3"
    "&TqCBuP2U;saqRbMP43<Q@10O6pY;n)uKATb`z!2crU!X3f{A_+5P9KU3EvO>=ThWmRiWCsLQ5aHzgnVKT;3_b%Q"
    "s1;{J~2plxAAzyNw56{RC=HmkV3MavPM;w9+pl1_qm<>y6CKrSnY29V-+^0y`Mz$pOkIqq+dWB&UV%B|+8P+GF^("
    "`DW0dmAG7noI3>J}GnL{4$=r_a_jcj;7kZAX`Fy)o2K8Ncd9r){CGv)NfG+eZi9p<lk$a|MV5G-%S(MU)7Mxcy<b"
    "^SiN{o8tnN7M9IZ(xLTqa{myTK<eFu}cRKd`_V!6~fLB^+BPO)11T<agXc1GZh^$%PGF4&I0tGg2opkFrr_mcTZ~"
    "UBULkd%HQN3+syZoHqc0-oVXu1~tS{EVoZd53_DaR`NaOe*Yk4DGXjRW65toNhri%#Ff?VH-++vJYMr&H(CvrC`2"
    "9`T&D2syPhcO&MtcvsD3eJYzX7+mzQAd56F0P)Fe;1^_%uez}#@kHDtEZ4-|`~C^$2&0Tmy!?~hyk?8^^*^QmxT%"
    "V^<KUMsqXg6%F-KlqzuAO*t6yf3Te%T2^~gJRi}P3IZ=n#pJ}|>HDEm1f0emugwSqatcTDNaq4qOEfUmk$_bg#Lm"
    "<Z)P2IyOyB2sS3lV^q2<c-+8#cww(X*S)sQNmo_-e;eodk#crThVfD#q7L1*mbe#Ah9yG#<Rq{1%4C;rV6Xua=W}"
    "zx{?6<4)Fm03I^z>;n}GP2kYHu7xg2(KPoz$&2OSuV*7@rBixv}Ir10u&0VA%b`4Yv+OcjSHKA3<vX8Wew!BWmR!"
    "ixm8aLPAj*o%4>6Y&c8Pv9k=r@X}yF;w|D`r6$3fBHk%S_L?Qi?U)Ov-NinwFYMOi*nu<q?Xy!<4nCY@e}5`z9Hf"
    "AiF!SUVroLe#^}(^~lD&g@QNVdG`FM&YmpsGCB5(a+?w*bh&kA#5_77YkTDN?qBx)$@vS$e!0CDna?jkW<Ro5=eZ"
    "_%rH&byvR+u!z3oyHE(_yv`E!4^+shw$cV0x{i;Jhe{8n}D#YKN-FMM*EE+Y|!j%z`~wIz&$?R)TTMwDrq+#6j#X"
    "V#!d<yPu4j4q#Sak$KkrWJZ_vjS>uc;xH7Z}(sS@mi>z1TiG3^!&+bKYt^FdhPcfwR4FwR0p*#3-K%No%V^L?`&t"
    "2V|P!b(lSBJ?fR90)EM601uGf6+JGIfg1(I3LhSzYkR3B>>5eg!jdNBpkBzMLnx_$YCfb;x=WT}^Ru8t_nzIga0p"
    "K!Pc;sE~yTs2Mmq69smL_oKG#w6Y9EG%_EegxxH83G+BO9EH<~^sP7_VemCEIlVUPWX|4q0p6Rh(dx1=}+BXWF!_"
    "kH&6F32LPO-{%LJ0L`J)rY_i7KA^gZZAs&)(^J4DhOF3rBi3qluUzH*zy;@@tTWXGGyFc8o!|X_88ffka?eb4cZ_"
    "y%27AnZGNRhqu=!4!Kk}ZL|GNr(eqp)05`Xx^ybC19GYt5vx48Eo6H;72`11=MUpqH3s!%8>BLsxM)nJM0?X#%Dp"
    "xO+Q9pM<$y8n|CY&?GQnMY76PW5=O(tUJfr<{JtC_LwZhP}UGMn74tfVf8Ve*vl+C3*"
)
