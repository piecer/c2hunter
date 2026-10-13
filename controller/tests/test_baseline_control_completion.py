"""Finite control lifecycle branches not replaced by inherited approval witnesses."""

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.publication_fixtures import publication_adapter
from tests.test_baseline_approval_sql import durable
from tests.test_baseline_approval_transaction_repair import independent
from tests.test_baseline_control_faults import bind, evidence, idle, snapshot_hash
from tests.test_baseline_control_storage import control, invoke, raw_state, reopen, setup_references
from tests.test_historical_source import config

adapter = publication_adapter


@pytest.mark.parametrize("action", ["FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE"])
def test_actual_control_cas_zero_and_one_recovery(
    adapter: Any, monkeypatch: Any, action: str
) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory has no SQL CAS rowcount")
    view, _, _ = setup_references(repo)
    request = control(2, action, view.previous.generation_id if action == "ROLLBACK" else None)
    before = durable(repo)
    pg = not isinstance(repo, SQLiteRepository)
    fired = []
    if not pg:
        repo.connection.create_function("control_cas_fired", 0, lambda: fired.append(True) or 1)
        repo.connection.executescript(
            "CREATE TEMP TRIGGER control_cas BEFORE UPDATE ON baseline_scopes "
            "BEGIN SELECT control_cas_fired(); SELECT RAISE(IGNORE); END;"
        )
    else:
        with independent(repo) as con:
            con.execute("CREATE SEQUENCE control_cas_fired")
            con.execute(
                "CREATE FUNCTION control_cas_fn() RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN PERFORM nextval('control_cas_fired'); RETURN NULL; END $$"
            )
            con.execute(
                "CREATE TRIGGER control_cas BEFORE UPDATE ON baseline_scopes "
                "FOR EACH ROW EXECUTE FUNCTION control_cas_fn()"
            )
    lookups = []
    actual = bs._PublicationSQL.control_replay

    def lookup(*args: Any, **kwargs: Any) -> Any:
        lookups.append(True)
        return actual(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(bs._PublicationSQL, "control_replay", lookup)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_REVISION_CONFLICT$"):
            invoke(repo, request)
    if pg:
        with independent(repo) as con:
            assert con.execute("SELECT last_value,is_called FROM control_cas_fired").fetchone() == (
                1,
                True,
            )
    else:
        assert fired == [True]
    assert len(lookups) == 3 and durable(repo) == before and idle(repo)
    if pg:
        with independent(repo) as con:
            con.execute("DROP TRIGGER control_cas ON baseline_scopes")
    else:
        repo.connection.execute("DROP TRIGGER control_cas")
        repo.connection.commit()
    peer = reopen(repo)
    try:
        assert peer.get_baseline_scope(config().scope_id) == view
    finally:
        peer.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(invoke, repo, request).result(30).scope.control_revision == 3
    evidence(
        dict(
            kind="cas-zero",
            backend="postgres" if pg else "sqlite",
            action=action,
            fired=1,
            recovery_reads=1,
            independent_prestate=True,
            idle=True,
            reopen=True,
            cross_thread_reuse=True,
        )
    )


@pytest.mark.parametrize("constraint", ["check", "notnull", "foreign-key"])
def test_actual_insert_constraint_never_enters_recovery(
    adapter: Any, monkeypatch: Any, constraint: str
) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory has no SQL constraints")
    view, _, _ = setup_references(repo)
    before = durable(repo)
    actual = bs._SQL.execute
    replay = bs._PublicationSQL.control_replay
    fired, reads = [], []

    def execute(db: Any, statement: str, values: Any = ()) -> Any:
        if statement.startswith("INSERT INTO baseline_operations"):
            values = list(values)
            field, value = {
                "check": (1, 0),
                "notnull": (5, None),
                "foreign-key": (0, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"),
            }[constraint]
            values[field] = value
            fired.append(True)
        return actual(db, statement, values)

    def lookup(*args: Any, **kwargs: Any) -> Any:
        reads.append(True)
        return replay(*args, **kwargs)

    request = control(2, "REVOKE")
    with monkeypatch.context() as patch:
        patch.setattr(bs._SQL, "execute", execute)
        patch.setattr(bs._PublicationSQL, "control_replay", lookup)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            invoke(repo, request)
    assert fired == [True] and len(reads) == 2 and durable(repo) == before and idle(repo)
    peer = reopen(repo)
    try:
        assert peer.get_baseline_scope(config().scope_id) == view
    finally:
        peer.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(invoke, repo, request).result(30).scope.control_revision == 3
    evidence(
        dict(
            kind="constraint-negative",
            backend="sqlite" if isinstance(repo, SQLiteRepository) else "postgres",
            constraint=constraint,
            fired=1,
            recovery_reads=0,
            independent_prestate=True,
            idle=True,
            reopen=True,
            cross_thread_reuse=True,
        )
    )


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize("error_kind", ["IOERR", "unknown", "programmer"])
def test_sqlite_protocol_ambiguous_commit_explicit_reconciliation(
    tmp_path: Any, committed: bool, error_kind: str
) -> None:
    repo = SQLiteRepository(tmp_path / "ambiguous.sqlite")
    try:
        setup_references(repo, 0)
        real = repo.connection
        before = raw_state(repo)
        if error_kind == "programmer":
            primary = AttributeError("opaque synthetic outcome")
        else:
            primary = sqlite3.OperationalError("synthetic commit outcome")
            if error_kind == "IOERR":
                primary.sqlite_errorcode = sqlite3.SQLITE_IOERR
        fired, rollbacks, closes = [], [], []

        class Ambiguous:
            def __getattr__(self, name: str) -> Any:
                return getattr(real, name)

            def commit(self) -> None:
                if committed:
                    real.commit()
                fired.append(True)
                raise primary

            def rollback(self) -> None:
                rollbacks.append(True)
                real.rollback()

            def close(self) -> None:
                closes.append(True)
                real.close()

        bind(repo, Ambiguous())
        request = control(0, "FREEZE")
        with pytest.raises((AttributeError, bs.BaselineStorageError)) as caught:
            invoke(repo, request)
        if error_kind == "programmer":
            assert caught.value is primary
        else:
            assert caught.value.code == "BASELINE_STORAGE_UNAVAILABLE"
        after = raw_state(repo)
        assert (after == before) == (not committed)
        assert (
            fired == rollbacks == closes == [True] and repo._baseline_publication_connection.failed
        )
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            invoke(repo, request)
        assert closes == [True]
        peer = reopen(repo)
        try:
            receipt = peer.page_baseline_control_events(config().scope_id).items
            result = invoke(peer, request)
            assert result.scope.control_revision == 1
            if committed:
                assert result.receipt == receipt[0]
        finally:
            peer.close()
        evidence(
            dict(
                kind="synthetic-ambiguous-commit",
                backend="sqlite",
                committed=committed,
                error_kind=error_kind,
                fired=1,
                quarantined=True,
                close_attempts=1,
                raw_before_reopen=snapshot_hash(after),
                explicit_reconciliation=True,
                actual_transport=False,
            )
        )
        bind(repo, real)
    finally:
        repo.close()


def test_postgres_actual_scope_busy_and_local_transaction_properties(
    adapter: Any, monkeypatch: Any
) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository | SQLiteRepository):
        pytest.skip("PostgreSQL scope-row lock and SET LOCAL only")
    view, _, _ = setup_references(repo, 0)
    before = durable(repo)
    actual = bs._PublicationSQL.exists
    properties = []

    def exists(db: Any, identifier: str, *, lock: bool = False) -> Any:
        isolation = db.execute("SHOW transaction_isolation").fetchone()[0]
        timeout = db.execute("SHOW lock_timeout").fetchone()[0]
        properties.append((lock, isolation, timeout))
        return actual(db, identifier, lock=lock)

    with independent(repo) as blocker:
        blocker.execute("BEGIN")
        blocker.execute("SELECT scope_id FROM baseline_scopes FOR UPDATE")
        with monkeypatch.context() as patch:
            patch.setattr(bs._PublicationSQL, "exists", exists)
            start = time.monotonic()
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
                invoke(repo, control(0, "FREEZE"))
            elapsed = time.monotonic() - start
        assert 4.5 <= elapsed < 15
        assert repo.page_baseline_control_events(config().scope_id).total == 0
        assert durable(repo) == before and idle(repo)
        blocker.rollback()
    assert properties == [(False, "repeatable read", "5s"), (True, "read committed", "5s")]
    peer = reopen(repo)
    try:
        assert peer.get_baseline_scope(config().scope_id) == view
    finally:
        peer.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert (
            pool.submit(invoke, repo, control(0, "FREEZE")).result(30).scope.control_revision == 1
        )
    evidence(
        dict(
            kind="real-scope-busy",
            backend="postgres",
            fired=1,
            elapsed=elapsed,
            properties=properties,
            independent_prestate=True,
            idle=True,
            reopen=True,
            cross_thread_reuse=True,
        )
    )


@pytest.mark.parametrize("fault", ["request", "actor", "time", "scope"])
def test_invalid_control_before_owner(adapter: Any, monkeypatch: Any, fault: str) -> None:
    from datetime import datetime

    from tests.test_historical_source import START

    request = control(0, "FREEZE")
    actor, now, scope = "operator", START, config().scope_id
    if fault == "request":
        request = request.model_copy(update={"expected_revision": True})
    elif fault == "actor":
        actor = "x" * 201
    elif fault == "time":
        now = datetime(2020, 1, 1)
    else:
        scope = "bad UUID"
    fired = []

    def forbidden(*args: Any, **kw: Any) -> Any:
        fired.append(True)
        raise AssertionError("invalid request admitted owner")

    with monkeypatch.context() as patch:
        patch.setattr(bs, "publication_connection", forbidden)
        patch.setattr(bs, "memory_control", forbidden)
        with pytest.raises(ValueError):
            adapter.control_baseline_scope(scope, request, actor, now)
    assert fired == []


@pytest.mark.parametrize(
    "path", ["FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE", "page", "replay"]
)
def test_value_and_memory_preparation_sites(adapter: Any, path: str) -> None:
    import ast
    import sys
    from pathlib import Path

    from tests.test_baseline_control_faults import full_setup, restore_baseline

    repo = adapter
    memory = isinstance(repo, MemoryRepository)
    view, retained = full_setup(repo)
    before = raw_state(repo)
    functions = {
        "_stage_control",
        "_operation_row",
        "_control_operation",
        "_events",
        "_event_metadata",
    }
    if memory:
        functions.update({"memory_control", "memory_events"})
    tree = ast.parse(Path(bs.__file__).read_text())
    sites = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            for part in ast.walk(node):
                if isinstance(
                    part,
                    ast.Call
                    | ast.Dict
                    | ast.DictComp
                    | ast.SetComp
                    | ast.ListComp
                    | ast.Delete
                    | ast.Return,
                ):
                    sites.add((node.name, part.lineno))
    request = (
        retained
        if path == "replay"
        else control(
            64,
            path if path != "page" else "FREEZE",
            view.previous.generation_id if path == "ROLLBACK" else None,
        )
    )

    def call(client: Any) -> Any:
        return (
            client.page_baseline_control_events(config().scope_id)
            if path == "page"
            else invoke(client, request)
        )

    observed = []
    target = None
    fired = []
    marker = RuntimeError("new value preparation fault")

    def trace(frame: Any, event: str, arg: Any) -> Any:
        site = (frame.f_code.co_name, frame.f_lineno)
        if event == "line" and frame.f_code.co_filename == bs.__file__ and site in sites:
            observed.append(site)
            if target == len(observed) - 1:
                fired.append(site)
                raise marker
        return trace

    def restore() -> None:
        if memory:
            repo._baseline_scopes, repo._baseline_generations, repo._baseline_operations = before
        else:
            restore_baseline(repo, before)

    sys.settrace(trace)
    try:
        expected = call(repo)
    finally:
        sys.settrace(None)
    inventory = list(observed)
    assert inventory
    restore()
    evidence(
        dict(
            kind="value-inventory",
            backend="memory"
            if memory
            else "sqlite"
            if isinstance(repo, SQLiteRepository)
            else "postgres",
            path=path,
            sites=inventory,
        )
    )
    for target, site in enumerate(inventory):
        observed.clear()
        fired.clear()
        sys.settrace(trace)
        try:
            with pytest.raises(RuntimeError) as caught:
                call(repo)
        finally:
            sys.settrace(None)
        assert caught.value is marker and fired == [site]
        after = raw_state(repo)
        committed = not memory and len(after[2]) and after[0] != before[0]
        if committed:
            assert repo.get_baseline_scope(config().scope_id) == expected.scope
        else:
            assert after == before
        if not memory:
            assert idle(repo) and not repo._baseline_publication_connection.failed
            peer = reopen(repo)
            try:
                assert peer.get_baseline_scope(config().scope_id) == (
                    expected.scope if committed else view
                )
            finally:
                peer.close()
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(repo.get_baseline_scope, config().scope_id).result(
                30
            ).control_revision == (65 if committed else 64)
        evidence(
            dict(
                kind="value-stage-fault",
                backend="memory"
                if memory
                else "sqlite"
                if isinstance(repo, SQLiteRepository)
                else "postgres",
                path=path,
                target=target,
                site=site,
                fired=1,
                committed=bool(committed),
                raw_before_reopen=snapshot_hash(after),
                full_before=repr(before),
                full_after=repr(after),
                idle=not memory,
                reopen=not memory,
                cross_thread_read=True,
                primary_identity=True,
            )
        )
        restore()


@pytest.mark.parametrize("winner", ["approve", "control"])
def test_approve_control_forced_both_orders(adapter: Any, monkeypatch: Any, winner: str) -> None:
    from threading import Event

    from tests.test_baseline_control_storage import approval, store_source
    from tests.test_historical_source import START

    repo = adapter
    if isinstance(repo, MemoryRepository):
        setup_references(repo, 0)
        approve = approval(repo, store_source(repo, 0), 0)
        if winner == "approve":
            repo.publish_baseline_source(config().scope_id, approve, "reviewer", START)
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_REVISION_CONFLICT$"):
                invoke(repo, control(0, "FREEZE"))
        else:
            invoke(repo, control(0, "FREEZE"))
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_REVISION_CONFLICT$"):
                repo.publish_baseline_source(config().scope_id, approve, "reviewer", START)
        return
    setup_references(repo, 0)
    approve = approval(repo, store_source(repo, 0), 0)
    peer = reopen(repo)
    parked, release = Event(), Event()
    peer_connection = peer.connection
    actual = bs._publication_transaction.__exit__
    seen = []

    def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
        value = actual(owner, kind, error, tb)
        if owner.connection is peer_connection and not owner.write and not seen:
            seen.append(True)
            parked.set()
            assert release.wait(20)
        return value

    def call(client: Any, action: str) -> Any:
        return (
            client.publish_baseline_source(config().scope_id, approve, "reviewer", START)
            if action == "approve"
            else invoke(client, control(0, "FREEZE"))
        )

    try:
        with monkeypatch.context() as patch:
            patch.setattr(bs._publication_transaction, "__exit__", boundary)
            with ThreadPoolExecutor(max_workers=1) as pool:
                loser = pool.submit(call, peer, "control" if winner == "approve" else "approve")
                assert parked.wait(10)
                result = call(repo, winner)
                release.set()
                with pytest.raises(bs.BaselineStorageError, match="^BASELINE_REVISION_CONFLICT$"):
                    loser.result(30)
        assert len(seen) == 1 and repo.get_baseline_scope(config().scope_id) == result.scope
    finally:
        release.set()
        peer.close()


def test_recovery_transaction_each_statement(adapter: Any, monkeypatch: Any) -> None:
    import uuid

    from tests.test_baseline_control_faults import DriverProbe, bind

    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory has no SQL one-shot recovery transaction")
    setup_references(repo, 0)
    first = invoke(repo, control(0, "FREEZE"))
    request = control(1, "RETIRE")
    before = durable(repo)
    real = repo.connection
    probe = DriverProbe(real, not isinstance(repo, SQLiteRepository))
    with monkeypatch.context() as patch:
        patch.setattr(uuid, "uuid4", lambda: uuid.UUID(first.receipt.operation_id))
        bind(repo, probe)
        try:
            with pytest.raises(bs._PublicationUnique):
                invoke(repo, request)
            inventory = list(probe.events)
        finally:
            bind(repo, real)
    starts = [i for i, event in enumerate(inventory) if event["event"].startswith("BEGIN")]
    assert len(starts) == 3
    start = starts[2] - (1 if not isinstance(repo, SQLiteRepository) else 0)
    evidence(
        dict(
            kind="recovery-inventory",
            backend="sqlite" if isinstance(repo, SQLiteRepository) else "postgres",
            sites=inventory[start:],
            start=start,
        )
    )
    for target in range(start, len(inventory)):
        client = reopen(repo)
        connection = client.connection
        probe = DriverProbe(connection, not isinstance(repo, SQLiteRepository), target)
        bind(client, probe)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(uuid, "uuid4", lambda: uuid.UUID(first.receipt.operation_id))
                with pytest.raises(RuntimeError) as caught:
                    invoke(client, request)
            assert caught.value is probe.marker and probe.fired == 1
            assert probe.events[target] == inventory[target]
            assert durable(repo) == before
            failed = inventory[target]["event"] in ("ROLLBACK", "CURSOR_CLOSE")
            assert client._baseline_publication_connection.failed == failed
            assert probe.closes == int(failed)
            peer = reopen(repo)
            try:
                assert peer.get_baseline_scope(config().scope_id) == first.scope
            finally:
                peer.close()
            if failed:
                with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                    invoke(client, request)
            else:
                assert idle(client)
                probe.target = None
                with ThreadPoolExecutor(max_workers=1) as pool:
                    assert (
                        pool.submit(invoke, client, control(0, "FREEZE")).result(30).receipt
                        == first.receipt
                    )
            evidence(
                dict(
                    kind="recovery-statement-fault",
                    backend="sqlite" if isinstance(repo, SQLiteRepository) else "postgres",
                    target=target,
                    **inventory[target],
                    fired=1,
                    full_before=repr(before),
                    full_after=repr(durable(repo)),
                    primary_identity=True,
                    quarantined=failed,
                    close_attempts=probe.closes,
                    reopen=True,
                    cross_thread_reuse=not failed,
                )
            )
        finally:
            bind(client, connection)
            client.close()
