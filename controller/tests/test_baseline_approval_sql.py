"""Real SQL mutation/COMMIT/readback observers on bounded seeded retention."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any
from uuid import uuid4

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_baseline_approval_retention import operations, publish
from tests.test_baseline_scope_faults import observer, receipt
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


def durable(repo: Any) -> tuple:
    tables = ["baseline_scopes", "baseline_generations", "baseline_operations"]
    tables += (
        [
            "controller_objects",
            "job_flow_records",
            "job_flow_record_chunks",
            "candidate_records",
            "audit_events",
        ]
        if isinstance(repo, PostgresRepository)
        else ["objects"]
    )
    with closing(observer(repo)) as raw:
        return tuple(
            sorted(raw.execute("SELECT * FROM " + table).fetchall(), key=repr) for table in tables
        )


def full_retention_seed(repo: Any) -> None:
    """Two actual publications plus coherent synthetic receipts for fault sites.

    The separate 65-publication test proves actual operation retention; these
    seeded receipts do not claim real approvals or control execution.
    """
    repo.create_baseline_scope(config(), "admin", START)
    publish(repo, 0)
    request, second = publish(repo, 1)
    pg = isinstance(repo, PostgresRepository)
    with bs.transaction(repo.connection, postgres=pg, write=True) as cursor:
        db = bs._SQL(cursor, pg)
        for revision in range(3, 65):
            req = g.ApprovalRequest.from_mapping(
                dict(
                    request.to_mapping(),
                    expected_revision=revision - 1,
                    idempotency_key=f"seed-{revision}",
                )
            )
            rec = g.ApprovalReceipt.from_mapping(
                dict(second.receipt.to_mapping(), revision=revision, operation_id=str(uuid4()))
            )
            digest = hashlib.sha256(
                h.canonical_json(
                    {
                        "action": "APPROVE",
                        "scope_id": config().scope_id,
                        "actor": "reviewer",
                        "request": req.to_mapping(),
                    }
                ).encode()
            ).hexdigest()
            raw = h.canonical_json(rec.to_mapping())
            db.execute(
                "INSERT INTO baseline_operations VALUES(?,?,?,?,?,?,?,?)",
                (
                    config().scope_id,
                    revision,
                    req.idempotency_key,
                    digest,
                    rec.operation_id,
                    raw,
                    hashlib.sha256(raw.encode()).hexdigest(),
                    len(raw.encode()),
                ),
            )
        db.execute("UPDATE baseline_scopes SET control_revision=64")
    assert len(operations(repo)) == 64


@pytest.mark.parametrize(
    "fault",
    [
        "previous-delete",
        "generation-insert",
        "scope-update",
        "operation-insert",
        "operation-prune",
        "commit",
    ],
)
def test_retained_sql_mutation_fault(approval_repo: Any, fault: str) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL trigger and COMMIT observers")
    full_retention_seed(repo)
    request = fixtures.prepare(repo, 64)
    before = durable(repo)
    pg = isinstance(repo, PostgresRepository)
    con = repo.connection
    table, event = {
        "previous-delete": ("baseline_generations", "DELETE"),
        "generation-insert": ("baseline_generations", "INSERT"),
        "scope-update": ("baseline_scopes", "UPDATE"),
        "operation-insert": ("baseline_operations", "INSERT"),
        "operation-prune": ("baseline_operations", "DELETE"),
        "commit": ("baseline_operations", "INSERT"),
    }[fault]
    fired = []
    if pg:
        con.execute("CREATE SEQUENCE approval_fault_fired")
        con.execute(
            "CREATE FUNCTION approval_fault() RETURNS trigger LANGUAGE plpgsql "
            "AS $$ BEGIN PERFORM nextval('approval_fault_fired'); RAISE "
            "EXCEPTION 'owned publication fault'; END $$"
        )
        con.execute(
            "CREATE "
            + ("CONSTRAINT " if fault == "commit" else "")
            + f"TRIGGER approval_fail AFTER {event} ON {table} "
            + ("DEFERRABLE INITIALLY DEFERRED " if fault == "commit" else "")
            + "FOR EACH ROW EXECUTE FUNCTION approval_fault()"
        )
        con.commit()
    else:
        con.create_function("approval_fired", 0, lambda: fired.append(fault) or 1)
        action = "SELECT RAISE(ABORT,'owned publication fault');"
        if fault == "commit":
            con.execute("CREATE TABLE approval_parent(id INTEGER PRIMARY KEY)")
            con.execute(
                "CREATE TABLE approval_child(id INTEGER REFERENCES "
                "approval_parent(id) DEFERRABLE INITIALLY DEFERRED)"
            )
            action = "INSERT INTO approval_child VALUES(1);"
        con.executescript(
            f"CREATE TEMP TRIGGER approval_fail AFTER {event} ON {table} BEGIN "
            f"SELECT approval_fired(); {action} END;"
        )
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert durable(repo) == before  # independent raw connection before rescue/reopen
    if pg:
        with closing(observer(repo)) as raw:
            assert raw.execute(
                "SELECT last_value,is_called FROM approval_fault_fired"
            ).fetchone() == (1, True)
        fired.append(fault)
    assert fired == [fault]
    assert (con.info.transaction_status.name == "IDLE") if pg else not con.in_transaction
    con.execute(f"DROP TRIGGER approval_fail ON {table}" if pg else "DROP TRIGGER approval_fail")
    con.commit()
    reopened = PostgresRepository(repo.database_url, None) if pg else SQLiteRepository(repo._path)
    try:
        assert reopened.get_baseline_scope(config().scope_id).control_revision == 64
    finally:
        reopened.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(
            repo.publish_baseline_source, config().scope_id, request, "reviewer", START
        ).result(30)
    assert result.created and result.scope.control_revision == 65
    assert len(operations(repo)) == 64
    receipt(
        {
            "backend": "postgres" if pg else "sqlite",
            "site": table + "/" + event if fault != "commit" else "COMMIT",
            "fault": fault,
            "occurrence": 1,
            "fired": 1,
            "prestate": True,
            "idle": True,
            "reopen": True,
            "cross_thread_reuse": True,
        }
    )


@pytest.mark.parametrize("fault", ["scope", "receipt", "document", "serializer"])
def test_postcommit_readback_failure(approval_repo: Any, monkeypatch: Any, fault: str) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL postcommit readback is not Memory staged publication")
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    committed = []
    original_exit = bs._publication_transaction.__exit__

    def exited(owner: Any, *args: Any) -> Any:
        value = original_exit(owner, *args)
        if owner.write and not args[1]:
            committed.append(durable(repo))
        return value

    monkeypatch.setattr(bs._publication_transaction, "__exit__", exited)
    execute = bs._SQL.execute
    fired = []

    def sql(db: Any, statement: str, values: tuple = ()) -> Any:
        targets = {
            "scope": "SELECT config_json,",
            "receipt": "SELECT scope_id,revision,idempotency_key,",
            "document": "SELECT publication_revision,document_json,",
        }
        if committed and fault in targets and statement.startswith(targets[fault]):
            fired.append(True)
            return execute(db, "SELECT * FROM owned_missing_readback_table")
        return execute(db, statement, values)

    monkeypatch.setattr(bs._SQL, "execute", sql)
    original_json = g.generation_json
    marker = TypeError("owned readback serializer")

    def serializer(document: Any) -> Any:
        import sys

        if committed and fault == "serializer" and sys._getframe(1).f_code.co_name == "sql_publish":
            fired.append(True)
            raise marker
        return original_json(document)

    monkeypatch.setattr(g, "generation_json", serializer)
    with pytest.raises(TypeError if fault == "serializer" else bs.BaselineStorageError) as caught:
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert committed and fired == [True]
    if fault == "serializer":
        assert caught.value is marker
    assert durable(repo) == committed[0]
    monkeypatch.setattr(bs._SQL, "execute", execute)
    monkeypatch.setattr(g, "generation_json", original_json)
    replay = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert not replay.created and replay.receipt.revision == 1


@pytest.mark.parametrize("ahead", [1, 2])
def test_readback_later_publications(approval_repo: Any, monkeypatch: Any, ahead: int) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL commit/readback gap")
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    pg = isinstance(repo, PostgresRepository)
    peer = PostgresRepository(repo.database_url, None) if pg else SQLiteRepository(repo._path)
    original = bs._publication_transaction.__exit__
    advanced = []

    def exited(owner: Any, *args: Any) -> Any:
        value = original(owner, *args)
        if owner.connection is repo.connection and owner.write and not args[1] and not advanced:
            advanced.append(True)
            for index in range(1, ahead + 1):
                publish(peer, index)
        return value

    monkeypatch.setattr(bs._publication_transaction, "__exit__", exited)
    try:
        if ahead == 2:
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        else:
            result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
            assert result.created and result.scope.control_revision == 2
            assert result.receipt.generation_id == result.scope.previous.generation_id
        replay = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert (
            not replay.created
            and replay.receipt.revision == 1
            and replay.scope.control_revision == ahead + 1
        )
    finally:
        peer.close()
