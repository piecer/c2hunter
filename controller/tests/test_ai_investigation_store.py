import importlib
import json

import pytest

from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def api():
    assert importlib.util.find_spec("c2hunter_controller.ai_investigation_store") is not None
    return importlib.import_module("c2hunter_controller.ai_investigation_store")


def raw(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    module = api()
    repository = (
        MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "runs.db")
    )
    module.initialize_investigation_store(repository)
    clock = [1000.0]
    instance = module.InvestigationRunStore(repository, clock=lambda: clock[0])
    yield instance, repository, clock
    if request.param == "sqlite":
        repository.connection.close()


def admit(store, owner="alice", key="key", job="job"):
    return store.admit(
        owner_id=owner,
        job_id=job,
        idempotency_key=key,
        request_json=raw({"question": "why?"}),
        binding_json=raw({"generation": 1}),
        snapshot_json=raw({"facts": [1, 2]}),
    )


@pytest.mark.parametrize(
    "bad",
    [
        b'{ "q":1}',
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b"[]",
        b'{"api_key":"secret"}',
        b'{"a":"' + b"x" * 16384 + b'"}',
        b'{"a":' + b"[" * 30 + b"0" + b"]" * 30 + b"}",
    ],
    ids=["spacing", "duplicate-key", "nan", "array", "credential", "oversize", "depth"],
)
def test_request_bytes_are_validated_before_admission(store, bad):
    s, _, _ = store
    with pytest.raises(api().InvestigationStoreError, match="INVALID_DOCUMENT"):
        s.admit(
            owner_id="alice",
            job_id="job",
            idempotency_key="bad",
            request_json=bad,
            binding_json=raw({}),
            snapshot_json=raw({}),
        )


def test_saved_custody_and_conflict_survive_source_deletion(store):
    s, repo, _ = store
    run, _ = admit(s)
    with pytest.raises(api().InvestigationStoreError, match="IDEMPOTENCY_CONFLICT"):
        s.lookup(
            owner_id="alice",
            job_id="other",
            idempotency_key="key",
            request_json=raw({"question": "why?"}),
        )
    with pytest.raises(api().InvestigationStoreError, match="IDEMPOTENCY_CONFLICT"):
        s.lookup(
            owner_id="alice",
            job_id="job",
            idempotency_key="key",
            request_json=raw({"question": "changed"}),
        )
    assert s.get("bob", "job", run["id"]) is None
    assert s.get("alice", "other", run["id"]) is None
    saved = s.saved_input("alice", "job", run["id"])
    assert saved["request_json"] == raw({"question": "why?"})
    assert saved["snapshot_json"] == raw({"facts": [1, 2]})
    assert len(saved["commitment"]) == 64
    assert s.saved_input("bob", "job", run["id"]) is None
    assert not {"request_json", "snapshot_json", "binding_json", "lease_token"} & run.keys()
    assert (
        s.lookup(
            owner_id="alice",
            job_id="job",
            idempotency_key="key",
            request_json=raw({"question": "why?"}),
        )
        == run
    )


def test_queue_capacity_is_durable_and_replay_precedes_limits(store):
    s, repo, clock = store
    first, _ = admit(s)
    for i in range(1, 4):
        admit(s, key=str(i))
    with pytest.raises(api().InvestigationStoreError, match="OWNER_QUEUE_FULL"):
        admit(s, key="overflow")
    assert admit(s) == (first, False)
    for owner in ("bob", "carol", "dave"):
        for i in range(4):
            admit(s, owner=owner, key=str(i))
    with pytest.raises(api().InvestigationStoreError, match="QUEUE_FULL"):
        admit(s, owner="eve")
    page = s.page("alice", "job", limit=2)
    assert len(page) == 2 and all(r["owner_id"] == "alice" for r in page)
    next_page = s.page("alice", "job", after=page[-1]["id"], limit=2)
    assert len({r["id"] for r in page + next_page}) == 4
    with pytest.raises(api().InvestigationStoreError, match="INVALID_PAGE"):
        s.page("alice", "job", limit=21)


def test_claim_transition_heartbeat_and_final_publication_are_fenced(store):
    s, _, clock = store
    run, _ = admit(s)
    claim = s.claim("worker-a")
    assert claim["id"] == run["id"] and claim["status"] == "PREPARING"
    assert claim["generation"] == 1 and claim["lease_token"]
    stale = dict(claim)
    claim = s.heartbeat(claim)
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.transition(stale, "INVESTIGATING")
    claim = s.transition(claim, "INVESTIGATING")
    claim = s.transition(claim, "VALIDATING")
    completed = s.publish(claim, "COMPLETED", raw({"conclusion": "unknown"}))
    assert completed["status"] == "COMPLETED"
    assert s.get("alice", "job", run["id"])["result"] == {"conclusion": "unknown"}
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.publish(claim, "FAILED", raw({}))
    assert s.claim("worker-b") is None


def test_execution_capacity_is_not_released_by_publication(store):
    s, _, _ = store
    admit(s)
    claim = s.claim("worker-a")
    admit(s, key="second")
    assert s.claim("worker-a") is None
    admit(s, owner="bob")
    other = s.claim("worker-b")
    assert other is not None
    admit(s, owner="carol")
    assert s.claim("worker-c") is None
    s.publish(claim, "FAILED", raw({}))
    assert s.claim("worker-c") is None
    assert s.worker_exited(claim)
    assert s.claim("worker-c") is not None


def test_cancel_wins_publication_without_releasing_compute(store):
    s, _, _ = store
    run, _ = admit(s)
    claim = s.claim("worker")
    assert s.cancel("bob", "job", run["id"]) is None
    cancelled = s.cancel("alice", "job", run["id"])
    assert cancelled["status"] == "CANCELLED"
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.publish(claim, "FAILED", raw({}))
    admit(s, key="second")
    assert s.claim("next") is None
    assert s.worker_exited(claim)
    assert s.get("alice", "job", run["id"]) == cancelled
    assert s.claim("next") is not None


def test_restart_expiry_is_fail_closed_without_external_call_replay(store):
    s, repo, clock = store
    run, _ = admit(s)
    claim = s.claim("worker")
    clock[0] += 30
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.heartbeat(claim)
    restarted = api().InvestigationRunStore(repo, clock=lambda: clock[0])
    assert restarted.reconcile() == 1
    failed = restarted.get("alice", "job", run["id"])
    assert failed["status"] == "FAILED" and failed["reason"] == "OWNER_LOST"
    admit(restarted, key="next")
    assert restarted.claim("new-worker") is None
    assert restarted.worker_exited(claim)
    assert restarted.claim("new-worker") is not None


def test_queue_expiry_and_absolute_run_deadline(store):
    s, _, clock = store
    run, _ = admit(s)
    clock[0] += 60
    assert s.claim("worker") is None
    assert s.get("alice", "job", run["id"])["reason"] == "QUEUE_EXPIRED"
    run, _ = admit(s, key="fresh")
    claim = s.claim("worker")
    for _ in range(14):
        clock[0] += 20
        claim = s.heartbeat(claim)
    clock[0] += 20
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.publish(claim, "FAILED", raw({}))
    assert s.reconcile() == 1
    assert s.get("alice", "job", run["id"])["reason"] == "DEADLINE_EXCEEDED"


def test_budgets_and_owned_evidence_are_atomic_and_bounded(store):
    s, _, _ = store
    run, _ = admit(s)
    claim = s.claim("worker")
    claim = s.reserve(
        claim,
        model_calls=6,
        tool_calls=12,
        transport_attempts=12,
        source_bytes=67108864,
        source_records=100000,
    )
    with pytest.raises(api().InvestigationStoreError, match="BUDGET_EXHAUSTED"):
        s.reserve(claim, model_calls=1)
    claim = s.append_step(claim, raw({"tool": "overview"}))
    stale = dict(claim)
    claim = s.save_evidence(claim, "evidence-1", raw({"metric": 42}))
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.save_evidence(stale, "evidence-2", raw({}))
    with pytest.raises(api().InvestigationStoreError, match="EVIDENCE_EXISTS"):
        s.save_evidence(claim, "evidence-1", raw({"metric": 0}))
    assert s.evidence("alice", "job", run["id"], "evidence-1") == {"metric": 42}
    assert s.evidence("bob", "job", run["id"], "evidence-1") is None
    assert s.steps("alice", "job", run["id"], after=0, limit=1) == [
        {"sequence": 1, "body": {"tool": "overview"}}
    ]
    assert s.steps("alice", "else", run["id"]) == []
    for i in range(1, 24):
        claim = s.append_step(claim, raw({"index": i}))
    with pytest.raises(api().InvestigationStoreError, match="STEP_LIMIT"):
        s.append_step(claim, raw({}))
    assert len(s.steps("alice", "job", run["id"], after=20)) == 4


def test_observation_total_includes_frozen_snapshot(store):
    s, _, _ = store
    run, _ = s.admit(
        owner_id="alice",
        job_id="job",
        idempotency_key="huge",
        request_json=raw({}),
        binding_json=raw({}),
        snapshot_json=raw({"facts": "x" * 250000}),
    )
    claim = s.claim("worker")
    with pytest.raises(api().InvestigationStoreError, match="OBSERVATION_LIMIT"):
        s.save_evidence(claim, "too-big", raw({"facts": "x" * 16000}))
    assert s.evidence("alice", "job", run["id"], "too-big") is None
    claim = s.save_evidence(claim, "small", raw({}))
    assert claim["evidence_count"] == 1


class PostgresCursorModel:
    """SQL-contract test double ONLY: not a PostgreSQL runtime test."""

    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.database.cursor()
        self.special = None

    def execute(self, sql, parameters=()):
        import re

        self.connection.statements.append(sql)
        self.special = None
        if "pg_try_advisory_xact_lock" in sql:
            self.special = (self.connection.lock_available,)
            return self
        if sql.startswith("SET LOCAL"):
            return self
        converted = sql.replace("%s", "?").replace("::jsonb", "")
        converted = re.sub(r"data->>'([a-z_]+)'", r"json_extract(data,'$.\1')", converted)
        self.cursor.execute(converted, parameters)
        return self

    def fetchone(self):
        return self.special if self.special is not None else self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def close(self):
        self.cursor.close()


class PostgresConnectionModel:
    def __init__(self):
        import sqlite3

        self.database = sqlite3.connect(":memory:")
        self.database.execute(
            "CREATE TABLE controller_objects(kind TEXT,id TEXT,data TEXT,PRIMARY KEY(kind,id))"
        )
        self.closed = False
        self.autocommit = False
        self.statements = []
        self.lock_available = True

    @property
    def info(self):
        from types import SimpleNamespace

        from psycopg.pq import TransactionStatus

        return SimpleNamespace(
            transaction_status=TransactionStatus.INTRANS
            if self.database.in_transaction
            else TransactionStatus.IDLE
        )

    def cursor(self):
        return PostgresCursorModel(self)

    def commit(self):
        self.database.commit()

    def rollback(self):
        self.database.rollback()


def test_postgres_repository_sql_contract_without_server():
    from c2hunter_controller.production import PostgresRepository

    repo = PostgresRepository("not-used", None)
    connection = PostgresConnectionModel()
    repo._connection = connection
    try:
        api().initialize_investigation_store(repo)
        s = api().InvestigationRunStore(repo, clock=lambda: 1000.0)
        connection.statements.clear()
        run, created = admit(s)
        assert created
        assert admit(s) == (run, False)
        claim = s.claim("worker")
        claim = s.reserve(claim, model_calls=1)
        claim = s.save_evidence(claim, "ev", raw({"metric": 1}))
        s.cancel("alice", "job", run["id"])
        s.worker_exited(claim)
        assert s.evidence("alice", "job", run["id"], "ev") == {"metric": 1}
        assert any("pg_try_advisory_xact_lock" in sql for sql in connection.statements)
        assert not any("CREATE" in sql for sql in connection.statements)
        assert any("%s::jsonb" in sql for sql in connection.statements)
        connection.lock_available = False
        with pytest.raises(api().InvestigationStoreError, match="STORE_BUSY"):
            admit(s, key="busy")
        assert not connection.database.in_transaction
    finally:
        connection.database.close()


def test_retention_refuses_growth_without_destroying_idempotency(tmp_path):
    module = api()
    for repository in (MemoryRepository(), SQLiteRepository(tmp_path / "retention.db")):
        try:
            module.initialize_investigation_store(repository)
            s = module.InvestigationRunStore(repository, clock=lambda: 1000.0)
            first, _ = admit(s)
            s.cancel("alice", "job", first["id"])
            if isinstance(repository, MemoryRepository):
                for i in range(1, 256):
                    run, _ = admit(s, key=str(i))
                    s.cancel("alice", "job", run["id"])
            else:
                with repository.connection:
                    repository.connection.executemany(
                        "INSERT INTO objects VALUES(?,?,?)",
                        [(module.RUN_KIND, f"retained-{i}", "{}") for i in range(255)],
                    )
            with pytest.raises(module.InvestigationStoreError, match="RETENTION_FULL"):
                admit(s, key="overflow")
            assert admit(s)[0]["id"] == first["id"]
        finally:
            if isinstance(repository, SQLiteRepository):
                repository.connection.close()


def test_clock_rollback_fails_closed(store):
    s, _, clock = store
    run, _ = admit(s)
    claim = s.claim("worker")
    clock[0] -= 1
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.heartbeat(claim)
    assert s.reconcile() == 1
    assert s.get("alice", "job", run["id"])["reason"] == "CLOCK_ROLLBACK"


def test_sqlite_late_fault_rolls_back_both_records_and_hides_raw_error(tmp_path):
    import sqlite3

    repo = SQLiteRepository(tmp_path / "fault.db")
    module = api()
    module.initialize_investigation_store(repo)
    s = module.InvestigationRunStore(repo, clock=lambda: 1000.0)
    repo.connection.execute(
        "CREATE TEMP TRIGGER fail_state BEFORE INSERT ON objects "
        "WHEN NEW.kind='ai_investigation_state_v1' "
        "BEGIN SELECT RAISE(ABORT,'sensitive-database-message'); END"
    )
    try:
        with pytest.raises(module.InvestigationStorageError, match="STORAGE_UNAVAILABLE") as error:
            admit(s)
        assert "sensitive" not in str(error.value)
        with sqlite3.connect(f"file:{repo._path}?mode=ro", uri=True) as observer:
            assert observer.execute(
                "SELECT count(*) FROM objects WHERE kind IN (?,?)",
                (module.RUN_KIND, module.STATE_KIND),
            ).fetchone() == (0,)
        assert not repo.connection.in_transaction
        repo.connection.execute("DROP TRIGGER fail_state")
        assert admit(s)[1]
    finally:
        repo.connection.close()


class CommitThenRaise:
    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def commit(self):
        self.connection.commit()
        raise RuntimeError("sensitive-commit-message")


def test_ambiguous_commit_quarantines_owner_and_reopen_replays(tmp_path):
    import sqlite3

    repo = SQLiteRepository(tmp_path / "uncertain.db")
    module = api()
    module.initialize_investigation_store(repo)
    s = module.InvestigationRunStore(repo, clock=lambda: 1000.0)
    repo.connection = CommitThenRaise(repo.connection)
    try:
        with pytest.raises(module.InvestigationOutcomeUnknown, match="STORAGE_OUTCOME_UNKNOWN"):
            admit(s)
        with pytest.raises(module.InvestigationOutcomeUnknown):
            admit(s)
        with sqlite3.connect(f"file:{repo._path}?mode=ro", uri=True) as observer:
            assert observer.execute(
                "SELECT count(*) FROM objects WHERE kind=?", (module.RUN_KIND,)
            ).fetchone() == (1,)
        independent = SQLiteRepository(repo._path)
        try:
            reopened = module.InvestigationRunStore(independent, clock=lambda: 1000.0)
            assert admit(reopened)[1] is False
        finally:
            independent.connection.close()
    finally:
        repo.connection.close()


def test_lookup_rejects_tampered_saved_custody(tmp_path):
    repo = SQLiteRepository(tmp_path / "tampered.db")
    module = api()
    module.initialize_investigation_store(repo)
    s = module.InvestigationRunStore(repo, clock=lambda: 1000.0)
    run, _ = admit(s)
    with repo.connection:
        repo.connection.execute(
            "UPDATE objects SET data=json_set(data,'$.snapshot_json','{}') WHERE kind=? AND id=?",
            (module.RUN_KIND, run["id"]),
        )
    try:
        with pytest.raises(module.InvestigationStoreError, match="STORE_CORRUPT"):
            s.lookup(
                owner_id="alice",
                job_id="job",
                idempotency_key="key",
                request_json=raw({"question": "why?"}),
            )
    finally:
        repo.connection.close()


def test_denied_sql_reads_filter_owner_before_transferring_body(tmp_path):
    repo = SQLiteRepository(tmp_path / "scope.db")
    module = api()
    module.initialize_investigation_store(repo)
    s = module.InvestigationRunStore(repo, clock=lambda: 1000.0)
    run, _ = admit(s)
    statements = []
    repo.connection.set_trace_callback(statements.append)
    try:
        assert s.get("other", "job", run["id"]) is None
        assert s.saved_input("other", "job", run["id"]) is None
        selects = [q for q in statements if q.startswith("SELECT data")]
        assert selects and all("owner_id" in q and "job_id" in q for q in selects)
        assert all(module.RUN_KIND not in q for q in selects)
    finally:
        repo.connection.close()


def _process_admit(path, barrier, output, key):
    repo = SQLiteRepository(path)
    try:
        s = api().InvestigationRunStore(repo, clock=lambda: 1000.0)
        barrier.wait(timeout=20)
        try:
            run, created = admit(s, key=key)
            output.put(("ok", run["id"], created))
        except api().InvestigationStoreError as error:
            output.put(("error", error.code))
    finally:
        repo.connection.close()


def test_sqlite_processes_admit_one_winner_and_share_queue_capacity(tmp_path):
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    path = str(tmp_path / "processes.db")
    repo = SQLiteRepository(path)
    api().initialize_investigation_store(repo)
    repo.connection.close()
    for keys in (("same", "same"), ("second", "third"), ("last-a", "last-b")):
        barrier = context.Barrier(2)
        output = context.Queue()
        processes = [
            context.Process(target=_process_admit, args=(path, barrier, output, key))
            for key in keys
        ]
        try:
            for process in processes:
                process.start()
            results = [output.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(timeout=30)
                assert process.exitcode == 0
            if keys[0] == "same":
                assert len({r[1] for r in results}) == 1
                assert sorted(r[2] for r in results) == [False, True]
            elif keys[0] == "last-a":
                assert sum(r[0] == "ok" for r in results) == 1
                assert ("error", "OWNER_QUEUE_FULL") in results
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            output.close()
            output.join_thread()


def test_sqlite_last_budget_reservation_has_one_cross_connection_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    path = tmp_path / "budget-race.db"
    repos = [SQLiteRepository(path), SQLiteRepository(path)]
    api().initialize_investigation_store(repos[0])
    stores = [api().InvestigationRunStore(r, clock=lambda: 1000.0) for r in repos]
    admit(stores[0])
    claim = stores[0].claim("worker")
    claim = stores[0].reserve(claim, tool_calls=11)
    barrier = Barrier(2)

    def reserve(s):
        barrier.wait(timeout=5)
        try:
            return s.reserve(claim, tool_calls=1)["budgets"]["tool_calls"]
        except api().InvestigationStoreError as error:
            return error.code

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, stores))
        assert sorted(map(str, results)) == ["12", "STALE_CLAIM"]
    finally:
        for repo in repos:
            repo.connection.close()


def test_sqlite_child_and_counter_rollback_together(tmp_path):
    repo = SQLiteRepository(tmp_path / "child-fault.db")
    module = api()
    module.initialize_investigation_store(repo)
    s = module.InvestigationRunStore(repo, clock=lambda: 1000.0)
    run, _ = admit(s)
    claim = s.claim("worker")
    repo.connection.execute(
        "CREATE TEMP TRIGGER fail_counter BEFORE UPDATE ON objects "
        "WHEN NEW.kind='ai_investigation_state_v1' BEGIN SELECT RAISE(ABORT,'fault'); END"
    )
    try:
        with pytest.raises(module.InvestigationStorageError):
            s.save_evidence(claim, "evidence", raw({}))
        assert s.evidence("alice", "job", run["id"], "evidence") is None
        assert not repo.connection.in_transaction
        repo.connection.execute("DROP TRIGGER fail_counter")
        assert s.save_evidence(claim, "evidence", raw({}))["evidence_count"] == 1
    finally:
        repo.connection.close()


def test_publication_rechecks_deadline_at_final_state_write(store, monkeypatch):
    s, _, clock = store
    run, _ = admit(s)
    claim = s.claim("worker")
    original = s._save_state

    def delayed(tx, state, **kwargs):
        clock[0] += 301
        return original(tx, state, **kwargs)

    monkeypatch.setattr(s, "_save_state", delayed)
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.publish(claim, "FAILED", raw({}))
    assert s.get("alice", "job", run["id"])["status"] == "PREPARING"


@pytest.mark.parametrize("body", [{"text": "\u0000"}, {"\u0000": "key"}])
def test_documents_reject_postgres_jsonb_nul_incompatibility(store, body):
    s, _, _ = store
    with pytest.raises(api().InvestigationStoreError, match="INVALID_DOCUMENT"):
        s.admit(
            owner_id="alice",
            job_id="job",
            idempotency_key="nul",
            request_json=raw(body),
            binding_json=raw({}),
            snapshot_json=raw({}),
        )


def test_memory_queue_reads_do_not_decode_retained_terminal_history(monkeypatch):
    module = api()
    repo = MemoryRepository()
    module.initialize_investigation_store(repo)
    s = module.InvestigationRunStore(repo, clock=lambda: 1000.0)
    for i in range(40):
        run, _ = admit(s, key=str(i))
        s.cancel("alice", "job", run["id"])
    original = module.json.loads

    def guarded(text, *args, **kwargs):
        assert '"status":"CANCELLED"' not in text, "historical hydration"
        return original(text, *args, **kwargs)

    monkeypatch.setattr(module.json, "loads", guarded)
    run, _ = admit(s, key="new")
    assert s.claim("worker")["id"] == run["id"]


def test_sqlite_publication_and_cancellation_have_one_terminal_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    path = tmp_path / "cancel-race.db"
    repos = [SQLiteRepository(path), SQLiteRepository(path)]
    module = api()
    module.initialize_investigation_store(repos[0])
    stores = [module.InvestigationRunStore(r, clock=lambda: 1000.0) for r in repos]
    run, _ = admit(stores[0])
    claim = stores[0].claim("worker")
    entered, release, contender = Event(), Event(), Event()

    def pause():
        entered.set()
        if not release.wait(timeout=10):
            raise RuntimeError("barrier timed out")
        return 1

    repos[0].connection.create_function("pause_publication", 0, pause)
    repos[0].connection.execute(
        "CREATE TEMP TRIGGER pause_final BEFORE UPDATE ON objects "
        "WHEN NEW.kind='ai_investigation_state_v1' "
        "AND json_extract(NEW.data,'$.status')='FAILED' "
        "BEGIN SELECT pause_publication(); END"
    )
    repos[1].connection.set_trace_callback(
        lambda sql: contender.set() if sql == "BEGIN IMMEDIATE" else None
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            published = pool.submit(stores[0].publish, claim, "FAILED", raw({}))
            try:
                assert entered.wait(timeout=10)
                cancelled = pool.submit(stores[1].cancel, "alice", "job", run["id"])
                assert contender.wait(timeout=10)
            finally:
                release.set()
            assert published.result(timeout=10) == cancelled.result(timeout=10)
        assert stores[1].get("alice", "job", run["id"])["status"] == "FAILED"
    finally:
        release.set()
        for repo in repos:
            repo.connection.close()


def test_initialization_and_operations_never_decode_legacy_jobs(tmp_path):
    repo = SQLiteRepository(tmp_path / "namespace.db")
    module = api()
    try:
        with repo.connection:
            repo.connection.execute(
                "INSERT INTO objects VALUES('legacy-unrelated','legacy','not-json')"
            )
        with pytest.raises(module.InvestigationStoreError, match="STORE_NOT_INITIALIZED"):
            module.InvestigationRunStore(repo)
        module.initialize_investigation_store(repo)
        s = module.InvestigationRunStore(repo, clock=lambda: 1000.0)
        statements = []
        repo.connection.set_trace_callback(statements.append)
        run, _ = admit(s)
        claim = s.claim("worker")
        s.cancel("alice", "job", run["id"])
        s.worker_exited(claim)
        assert not any("CREATE" in sql for sql in statements)
        plan = repo.connection.execute(
            "EXPLAIN QUERY PLAN SELECT data FROM objects WHERE kind=? "
            "AND json_extract(data,'$.slot')='HELD' ORDER BY id LIMIT 2",
            (module.STATE_KIND,),
        ).fetchall()
        assert any("investigation_slot_v1" in str(row) for row in plan)
    finally:
        repo.connection.close()


def test_module_origins_are_the_owned_checkout():
    import sys
    from pathlib import Path

    import c2hunter_analysis

    import c2hunter_controller.repositories as repositories

    checkout = Path(__file__).resolve().parents[2]
    assert sys.version_info >= (3, 12)
    assert Path(api().__file__).is_relative_to(checkout / "controller/src")
    assert Path(repositories.__file__).is_relative_to(checkout / "controller/src")
    assert Path(c2hunter_analysis.__file__).is_relative_to(checkout / "analysis/src")


def test_failed_owner_exit_has_stable_outcome_and_no_replay(store):
    s, _, _ = store
    run, _ = admit(s)
    claim = s.claim("worker")
    claim = s.reserve(claim, model_calls=1)
    assert s.worker_exited(claim)
    failed = s.get("alice", "job", run["id"])
    assert failed["status"] == "FAILED" and failed["reason"] == "WORKER_EXITED"
    assert admit(s) == (failed, False)
    assert s.claim("replacement") is None
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.worker_exited(claim)


def test_invalid_headers_and_budgets_never_change_owned_state(store):
    s, _, _ = store
    with pytest.raises(api().InvestigationStoreError, match="INVALID_HEADER"):
        admit(s, owner="bad owner")
    run, _ = admit(s)
    claim = s.claim("worker")
    for increments in ({"tool_calls": True}, {"tool_calls": -1}, {"unknown": 1}, {}):
        with pytest.raises(api().InvestigationStoreError, match="INVALID_BUDGET"):
            s.reserve(claim, **increments)
    for field, value in (
        ("owner_id", "other"),
        ("job_id", "other"),
        ("lease_token", "wrong"),
        ("generation", 9),
    ):
        with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
            s.heartbeat(dict(claim, **{field: value}))
    with pytest.raises(api().InvestigationStoreError, match="INVALID_TRANSITION"):
        s.publish(claim, "COMPLETED", raw({}))
    assert s.get("alice", "job", run["id"])["revision"] == claim["revision"]


def test_postgres_model_commit_unknown_is_not_acknowledged():
    from c2hunter_controller.production import PostgresRepository

    module = api()
    repo = PostgresRepository("not-used", None)
    connection = PostgresConnectionModel()
    repo._connection = connection
    try:
        module.initialize_investigation_store(repo)
        s = module.InvestigationRunStore(repo, clock=lambda: 1000.0)
        repo._connection = CommitThenRaise(connection)
        with pytest.raises(module.InvestigationOutcomeUnknown):
            admit(s)
        with pytest.raises(module.InvestigationOutcomeUnknown):
            s.claim("worker")
        assert connection.database.execute(
            "SELECT COUNT(*) FROM controller_objects WHERE kind=?", (module.RUN_KIND,)
        ).fetchone() == (1,)
    finally:
        connection.database.close()


def test_admit_replay_is_separate_and_durable(store):
    s, repository, clock = store
    run, created = admit(s)
    assert created and run["status"] == "QUEUED"
    reopened = api().InvestigationRunStore(repository, clock=lambda: clock[0])
    assert (
        reopened.lookup(
            owner_id="alice",
            job_id="job",
            idempotency_key="key",
            request_json=raw({"question": "why?"}),
        )
        == run
    )
    assert admit(reopened) == (run, False)
    assert run["id"] not in getattr(repository, "ai_runs", {})
    if isinstance(repository, SQLiteRepository):
        independent = SQLiteRepository(repository._path)
        try:
            observer = api().InvestigationRunStore(independent, clock=lambda: clock[0])
            assert observer.get("alice", "job", run["id"]) == run
        finally:
            independent.connection.close()


class ClaimSequenceClock:
    """Deterministic clock movement, never a change to the host clock."""

    def __init__(self, values):
        self.values = list(values)
        self.last = self.values[0]
        self.observed = []

    def __call__(self):
        if self.values:
            self.last = self.values.pop(0)
        self.observed.append(self.last)
        return self.last


def committed_claim_state(s, repository, identifier):
    if isinstance(repository, SQLiteRepository):
        import sqlite3

        with sqlite3.connect(f"file:{repository._path}?mode=ro", uri=True) as observer:
            return json.loads(
                observer.execute(
                    "SELECT data FROM objects WHERE kind=? AND id=?",
                    (api().STATE_KIND, identifier),
                ).fetchone()[0]
            )
    with s._transaction() as tx:
        return s._read(tx, api().STATE_KIND, identifier)


def assert_claim_refused(s, repository, run, claim, reason):
    assert claim is None, "an ineligible queued run must not grant private compute custody"
    durable = committed_claim_state(s, repository, run["id"])
    assert durable["status"] == "FAILED" and durable["reason"] == reason
    assert durable["created_at"] == run["created_at"]
    assert durable["slot"] == "FREE"
    assert durable["worker_id"] is None and durable["lease_token"] is None
    assert durable["generation"] == 0
    assert "deadline" not in durable and "lease_expires_at" not in durable
    assert all(value == 0 for value in durable["budgets"].values())
    with pytest.raises(api().InvestigationStoreError, match="STALE_CLAIM"):
        s.reserve(durable, model_calls=1)
    public = s.get("alice", "job", run["id"])
    assert admit(s) == (public, False)
    assert s.claim("replacement") is None
    assert s.get("alice", "job", run["id"]) == public


@pytest.mark.parametrize(
    ("schedule", "reason"),
    [
        ([1000.0, 999.0, 999.0], "CLOCK_ROLLBACK"),
        ([1000.0, 999.0, 1000.0], "CLOCK_ROLLBACK"),
        ([1059.0, 1061.0, 1061.0], "QUEUE_EXPIRED"),
        ([1059.0, 1061.0, 1059.0], "QUEUE_EXPIRED"),
        ([1059.0, 1060.0, 1060.0], "QUEUE_EXPIRED"),
        ([1000.0, 1000.0, 999.0], "CLOCK_ROLLBACK"),
        ([1059.0, 1059.0, 1061.0], "QUEUE_EXPIRED"),
        ([1059.0, 1059.0, 1060.0], "QUEUE_EXPIRED"),
        ([1000.0, 1000.0, 1000.0], None),
        ([1059.0, 1059.0, 1059.0], None),
    ],
    ids=[
        "review-rollback",
        "rollback-recovers-at-save",
        "review-expiry",
        "expiry-recovers-at-save",
        "selection-expiry-equality",
        "final-save-rollback",
        "final-save-expiry-plus-one",
        "final-save-expiry-equality",
        "creation-equality",
        "deadline-minus-one",
    ],
)
def test_claim_original_queue_time_at_publication(store, schedule, reason):
    s, repository, _ = store
    run, _ = admit(s)
    clock = ClaimSequenceClock(schedule)
    s.clock = clock
    claim = s.claim("worker")
    if reason is not None:
        assert_claim_refused(s, repository, run, claim, reason)
    else:
        assert claim["status"] == "PREPARING" and claim["slot"] == "HELD"
        assert claim["created_at"] == 1000.0
        assert claim["last_seen_at"] == schedule[-1]
        assert claim["deadline"] == schedule[1] + 300
        assert claim["lease_expires_at"] == schedule[1] + 30
        assert s.reserve(claim, model_calls=1)["budgets"]["model_calls"] == 1


@pytest.mark.parametrize(
    ("publication_time", "reason"),
    [
        (999.0, "CLOCK_ROLLBACK"),
        (1060.0, "QUEUE_EXPIRED"),
        (1061.0, "QUEUE_EXPIRED"),
        (1000.0, None),
        (1059.0, None),
    ],
    ids=["rollback", "expiry-equality", "expiry-plus-one", "creation-equality", "on-time"],
)
def test_claim_delayed_final_state_save(store, monkeypatch, publication_time, reason):
    s, repository, clock = store
    run, _ = admit(s)
    original = s._save_state
    entered = []

    def delayed(tx, state, **kwargs):
        entered.append(state["id"])
        clock[0] = publication_time
        return original(tx, state, **kwargs)

    monkeypatch.setattr(s, "_save_state", delayed)
    claim = s.claim("worker")
    assert entered == [run["id"]], "the actual final state-save boundary must be reached"
    if reason is not None:
        assert_claim_refused(s, repository, run, claim, reason)
    else:
        assert claim["status"] == "PREPARING"
        assert claim["last_seen_at"] == publication_time
        assert claim["deadline"] == 1300.0  # Final save must not restart the run deadline.


@pytest.mark.parametrize("last_seen", [1010.0, 990.0])
def test_claim_keeps_both_original_time_lower_bounds(store, last_seen):
    s, repository, _ = store
    run, _ = admit(s)
    # Persist a queued checkpoint; last_seen must never replace the creation bound.
    with s._transaction() as tx:
        state = s._read(tx, api().STATE_KIND, run["id"])
        state["last_seen_at"] = last_seen
        s._write(tx, api().STATE_KIND, run["id"], state)
    bound = max(1000.0, last_seen)
    s.clock = ClaimSequenceClock([bound, bound, bound - 1])
    claim = s.claim("worker")
    assert_claim_refused(s, repository, run, claim, "CLOCK_ROLLBACK")
