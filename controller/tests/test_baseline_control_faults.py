"""Actual adapter fault inventory. Statement and affected-row evidence are separate."""

import hashlib
import inspect
import json
import os
import sqlite3
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.publication_fixtures import publication_adapter
from tests.test_baseline_approval_sql import durable
from tests.test_baseline_approval_transaction_repair import independent
from tests.test_baseline_control_storage import control, invoke, raw_state, reopen, setup_references
from tests.test_historical_source import config

adapter = publication_adapter


def evidence(value: dict) -> None:
    value["source_sha256"] = hashlib.sha256(Path(bs.__file__).read_bytes()).hexdigest()
    if path := os.environ.get("CONTROL_EVIDENCE"):
        with Path(path).open("a") as stream:
            stream.write(json.dumps(value, sort_keys=True) + "\n")


def snapshot_hash(value: Any) -> str:
    return hashlib.sha256(repr(value).encode()).hexdigest()


def full_setup(repo: Any) -> tuple[Any, Any]:
    view, _, _ = setup_references(repo)
    request = None
    while view.control_revision < 64:
        request = control(view.control_revision, "UNFREEZE" if view.frozen else "FREEZE")
        view = invoke(repo, request).scope
    assert len(raw_state(repo)[2]) == 64
    return view, request


def restore_baseline(repo: Any, before: Any) -> None:
    # Fixture reset only, after every outcome/raw/reopen/reuse observation.
    with independent(repo) as con:
        con.execute("BEGIN")
        for table in ("baseline_operations", "baseline_generations", "baseline_scopes"):
            con.execute("DELETE FROM " + table)
        marker = "?" if isinstance(repo, SQLiteRepository) else "%s"
        for table, rows in zip(
            ("baseline_scopes", "baseline_generations", "baseline_operations"), before, strict=True
        ):
            for row in rows:
                con.execute(
                    "INSERT INTO " + table + " VALUES(" + ",".join([marker] * len(row)) + ")", row
                )
        con.commit()
    assert raw_state(repo) == before


class DriverProbe:
    def __init__(self, real: Any, postgres: bool, target: int | None = None) -> None:
        self.real, self.postgres, self.target = real, postgres, target
        self.events: list[dict] = []
        self.counts: Counter = Counter()
        self.fired = 0
        self.committed = False
        self.closes = 0
        # Existing _SQL.get's persisted-decoder boundary catches TypeError.
        # RuntimeError measures statement failure identity without redefining it.
        self.marker = RuntimeError("control statement primary")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)

    def observe(self, event: str) -> None:
        frame = inspect.currentframe()
        while frame is not None:
            if frame.f_code.co_filename == bs.__file__ and frame.f_code.co_name not in ("execute",):
                break
            frame = frame.f_back
        site = f"{frame.f_code.co_name}:{frame.f_lineno}" if frame else "driver"
        self.counts[(site, event)] += 1
        item = dict(
            site=site, event=event, occurrence=self.counts[(site, event)], committed=self.committed
        )
        self.events.append(item)
        if self.target == len(self.events) - 1:
            self.fired += 1
            if event == "COMMIT":
                if self.postgres:
                    import psycopg

                    raise psycopg.errors.CheckViolation("definite synthetic commit refusal")
                raise sqlite3.IntegrityError("definite synthetic commit refusal")
            raise self.marker

    def execute(self, statement: str, values: Any = ()) -> Any:
        self.observe(statement)
        return self.real.execute(statement, values)

    def cursor(self) -> Any:
        self.observe("CURSOR")
        return CursorProbe(self.real.cursor(), self)

    def commit(self) -> None:
        self.observe("COMMIT")
        self.real.commit()
        self.committed = True

    def rollback(self) -> None:
        self.observe("ROLLBACK")
        self.real.rollback()

    def close(self) -> None:
        self.closes += 1
        self.real.close()


class CursorProbe:
    def __init__(self, real: Any, owner: DriverProbe) -> None:
        self.real, self.owner = real, owner

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)

    def execute(self, statement: str, values: Any = ()) -> Any:
        self.owner.observe(statement)
        self.real.execute(statement, values)
        return self

    def close(self) -> None:
        self.owner.observe("CURSOR_CLOSE")
        self.real.close()


def bind(repo: Any, proxy: Any) -> None:
    if isinstance(repo, SQLiteRepository):
        repo.connection = proxy
    else:
        repo._connection = proxy


def idle(repo: Any) -> bool:
    if isinstance(repo, SQLiteRepository):
        return not repo.connection.in_transaction
    from psycopg.pq import TransactionStatus

    return repo.connection.info.transaction_status == TransactionStatus.IDLE


@pytest.mark.parametrize(
    "path",
    [
        "FREEZE",
        "UNFREEZE",
        "ROLLBACK",
        "REVOKE",
        "RETIRE",
        "replay",
        "page0",
        "page20",
        "page64",
        "page-empty",
        "page-one",
    ],
)
def test_every_sql_statement_occurrence(adapter: Any, path: str) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory has staged-map rather than SQL statement sites")
    if path in ("page-empty", "page-one"):
        view, _, _ = setup_references(repo, 0)
        retained_request = control(0, "FREEZE")
        if path == "page-one":
            view = invoke(repo, retained_request).scope
    else:
        view, retained_request = full_setup(repo)
    request = (
        retained_request
        if path == "replay"
        else control(
            64,
            path if not path.startswith("page") else "FREEZE",
            view.previous.generation_id if path == "ROLLBACK" else None,
        )
    )
    before, whole_before = raw_state(repo), durable(repo)

    def call(client: Any) -> Any:
        if path.startswith("page"):
            offset = 0 if path in ("page-empty", "page-one") else int(path[4:])
            return client.page_baseline_control_events(config().scope_id, offset, 20)
        return invoke(client, request)

    dry = reopen(repo)
    real = dry.connection
    trace = DriverProbe(real, not isinstance(repo, SQLiteRepository))
    bind(dry, trace)
    try:
        call(dry)
        inventory = list(trace.events)
        success = raw_state(repo)
    finally:
        bind(dry, real)
        dry.close()
    restore_baseline(repo, before)
    evidence(
        dict(
            kind="inventory",
            backend="sqlite" if isinstance(repo, SQLiteRepository) else "postgres",
            path=path,
            sites=inventory,
        )
    )
    for target, intended in enumerate(inventory):
        client = reopen(repo)
        real = client.connection
        probe = DriverProbe(real, not isinstance(repo, SQLiteRepository), target)
        bind(client, probe)
        try:
            with pytest.raises((RuntimeError, bs.BaselineStorageError)) as caught:
                call(client)
            assert probe.fired == 1 and probe.events[target] == intended
            if intended["event"] == "COMMIT":
                assert isinstance(caught.value, bs.BaselineStorageError)
                assert caught.value.code == "BASELINE_STORAGE_UNAVAILABLE"
            else:
                assert caught.value is probe.marker
            # Independent raw state, before constructing any fresh repository.
            after, whole_after = raw_state(repo), durable(repo)
            assert whole_after[3:] == whole_before[3:]
            if not probe.committed:
                assert after == before
            else:
                assert after[:2] == success[:2]
                assert len(after[2]) == 64
                assert after[2][:-1] == success[2][:-1]
            failed = client._baseline_publication_connection.failed
            assert failed == (intended["event"] in ("ROLLBACK", "CURSOR_CLOSE"))
            assert probe.closes == int(failed)
            if not failed:
                assert idle(client)
            fresh = reopen(repo)
            try:
                assert fresh.get_baseline_scope(config().scope_id).control_revision == (
                    65 if probe.committed else view.control_revision
                )
            finally:
                fresh.close()
            if failed:
                with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                    call(client)
                assert probe.closes == 1
            else:
                probe.target = None
                with ThreadPoolExecutor(max_workers=1) as pool:
                    result = pool.submit(call, client).result(30)
                assert result is not None and idle(client)
            evidence(
                dict(
                    kind="statement-fault",
                    backend="sqlite" if isinstance(repo, SQLiteRepository) else "postgres",
                    path=path,
                    target=target,
                    **intended,
                    fired=probe.fired,
                    primary="definite-driver" if intended["event"] == "COMMIT" else "identity",
                    raw_before_reopen=snapshot_hash(after),
                    full_before=repr(whole_before),
                    full_after=repr(whole_after),
                    prestate=not probe.committed,
                    quarantined=failed,
                    close_attempts=probe.closes,
                    reopened=True,
                    cross_thread_reuse=not failed,
                    unrelated_unchanged=True,
                )
            )
        finally:
            bind(client, real)
            client.close()
        restore_baseline(repo, before)


@pytest.mark.parametrize(
    "action,row_number",
    [("ROLLBACK", 1), ("REVOKE", 1), ("REVOKE", 2), ("RETIRE", 1), ("RETIRE", 2)],
)
def test_actual_delete_row_trigger_atomicity(adapter: Any, action: str, row_number: int) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Affected SQL row trigger is not a Memory representation")
    view, _ = full_setup(repo)
    before = durable(repo)
    request = control(64, action, view.previous.generation_id if action == "ROLLBACK" else None)
    fired = []
    if isinstance(repo, SQLiteRepository):

        def fire() -> int:
            fired.append(True)
            return len(fired)

        repo.connection.create_function("control_row_fired", 0, fire)
        repo.connection.executescript(
            "CREATE TEMP TRIGGER control_delete_fault BEFORE DELETE ON baseline_generations "
            f"BEGIN SELECT CASE WHEN control_row_fired()={row_number} "
            "THEN RAISE(ABORT,'owned row fault') END; END;"
        )
    else:
        # Sequence state is nontransactional, so rollback cannot erase firing.
        with independent(repo) as con:
            con.execute("CREATE SEQUENCE control_fired")
            con.execute(
                "CREATE FUNCTION control_row_fault() RETURNS trigger LANGUAGE plpgsql "
                "AS $$ BEGIN IF nextval('control_fired')="
                + str(row_number)
                + " THEN RAISE EXCEPTION 'owned row fault'; END IF; RETURN OLD; END $$"
            )
            con.execute(
                "CREATE TRIGGER control_delete_fault BEFORE DELETE ON baseline_generations "
                "FOR EACH ROW EXECUTE FUNCTION control_row_fault()"
            )
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        invoke(repo, request)
    if isinstance(repo, SQLiteRepository):
        count = len(fired)
    else:
        with independent(repo) as con:
            count = con.execute("SELECT last_value FROM control_fired").fetchone()[0]
    assert count == row_number
    assert durable(repo) == before and idle(repo)
    if isinstance(repo, SQLiteRepository):
        repo.connection.execute("DROP TRIGGER control_delete_fault")
        repo.connection.commit()
    else:
        with independent(repo) as con:
            con.execute("DROP TRIGGER control_delete_fault ON baseline_generations")
    peer = reopen(repo)
    try:
        assert peer.get_baseline_scope(config().scope_id) == view
    finally:
        peer.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(invoke, repo, request).result(30)
    assert result.scope.control_revision == 65
    evidence(
        dict(
            kind="row-trigger",
            backend="sqlite" if isinstance(repo, SQLiteRepository) else "postgres",
            action=action,
            row=row_number,
            fired=count,
            independent_prestate=True,
            idle=True,
            reopen=True,
            cross_thread_reuse=True,
        )
    )


@pytest.mark.parametrize(
    "site", ["scope", "insert", "trim", "deferred-fk", "deferred-P0001", "deferred-40001"]
)
def test_actual_mutation_and_deferred_commit_triggers(adapter: Any, site: str) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory has no SQL triggers or deferred constraints")
    pg = not isinstance(repo, SQLiteRepository)
    if not pg and site in ("deferred-P0001", "deferred-40001"):
        pytest.skip("PostgreSQL deferred constraint trigger SQLSTATE only")
    view, _ = full_setup(repo)
    before = durable(repo)
    fired = []
    table = "baseline_scopes" if site == "scope" else "baseline_operations"
    event = "UPDATE" if site == "scope" else "DELETE" if site == "trim" else "INSERT"
    if not pg:
        repo.connection.create_function(
            "control_mutation_fired", 0, lambda: fired.append(True) or 1
        )
        if site == "deferred-fk":
            repo.connection.executescript(
                "CREATE TABLE control_fk_parent(id INTEGER PRIMARY KEY); "
                "CREATE TABLE control_fk_child(id INTEGER REFERENCES control_fk_parent(id) "
                "DEFERRABLE INITIALLY DEFERRED);"
            )
            action = "INSERT INTO control_fk_child VALUES(1);"
        else:
            action = "SELECT RAISE(ABORT,'owned mutation fault');"
        repo.connection.executescript(
            f"CREATE TEMP TRIGGER control_mutation_fault AFTER {event} ON {table} "
            f"BEGIN SELECT control_mutation_fired(); {action} END;"
        )
    else:
        with independent(repo) as con:
            con.execute("CREATE SEQUENCE control_mutation_fired")
            if site == "deferred-fk":
                con.execute("CREATE TABLE control_fk_parent(id INTEGER PRIMARY KEY)")
                con.execute(
                    "CREATE TABLE control_fk_child(id INTEGER REFERENCES control_fk_parent(id) "
                    "DEFERRABLE INITIALLY DEFERRED)"
                )
                action = "INSERT INTO control_fk_child VALUES(1);"
            else:
                code = "40001" if site == "deferred-40001" else "P0001"
                action = "RAISE EXCEPTION 'owned mutation fault' USING ERRCODE='" + code + "';"
            con.execute(
                "CREATE FUNCTION control_mutation_fault_fn() RETURNS trigger LANGUAGE plpgsql "
                "AS $$ BEGIN PERFORM nextval('control_mutation_fired'); "
                + action
                + " RETURN NULL; END $$"
            )
            suffix = (
                " DEFERRABLE INITIALLY DEFERRED"
                if site in ("deferred-P0001", "deferred-40001")
                else ""
            )
            prefix = "CONSTRAINT " if suffix else ""
            con.execute(
                f"CREATE {prefix}TRIGGER control_mutation_fault AFTER {event} ON {table}{suffix} "
                "FOR EACH ROW EXECUTE FUNCTION control_mutation_fault_fn()"
            )
    request = control(64, "RETIRE")
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        invoke(repo, request)
    if pg:
        with independent(repo) as con:
            count = con.execute("SELECT last_value FROM control_mutation_fired").fetchone()[0]
    else:
        count = len(fired)
    assert count == 1 and durable(repo) == before and idle(repo)
    assert not repo._baseline_publication_connection.failed
    with independent(repo) as con:
        if pg:
            con.execute(f"DROP TRIGGER control_mutation_fault ON {table}")
    if not pg:
        repo.connection.execute("DROP TRIGGER control_mutation_fault")
        repo.connection.commit()
    peer = reopen(repo)
    try:
        assert peer.get_baseline_scope(config().scope_id) == view
    finally:
        peer.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(invoke, repo, request).result(30).scope.control_revision == 65
    evidence(
        dict(
            kind="real-trigger",
            backend="postgres" if pg else "sqlite",
            site=site,
            fired=count,
            independent_prestate=True,
            idle=True,
            reopen=True,
            cross_thread_reuse=True,
        )
    )


def test_real_sqlite_five_second_commit_busy(tmp_path: Any, monkeypatch: Any) -> None:
    import time

    repo = SQLiteRepository(tmp_path / "control-busy.sqlite")
    reader = sqlite3.connect(repo._path)
    try:
        view, _ = full_setup(repo)
        request = control(64, "REVOKE")
        before = durable(repo)
        assert repo.connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert repo.connection.execute("PRAGMA busy_timeout").fetchone() == (5000,)
        actual = bs._SQL.execute
        fired = []

        def boundary(db: Any, statement: str, values: Any = ()) -> Any:
            result = actual(db, statement, values)
            if statement.startswith("DELETE FROM baseline_operations WHERE"):
                reader.execute("BEGIN")
                reader.execute("SELECT * FROM baseline_scopes").fetchall()
                fired.append(time.monotonic())
            return result

        with monkeypatch.context() as patch:
            patch.setattr(bs._SQL, "execute", boundary)
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
                invoke(repo, request)
        assert len(fired) == 1 and time.monotonic() - fired[0] >= 4.5
        assert durable(repo) == before
        assert idle(repo) and not repo._baseline_publication_connection.failed
        reader.rollback()
        peer = reopen(repo)
        try:
            assert peer.get_baseline_scope(config().scope_id) == view
        finally:
            peer.close()
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(invoke, repo, request).result(30).scope.control_revision == 65
        evidence(
            dict(
                kind="real-commit-busy",
                backend="sqlite",
                fired=1,
                independent_prestate=True,
                idle=True,
                reopen=True,
                cross_thread_reuse=True,
            )
        )
    finally:
        reader.close()
        repo.close()


@pytest.mark.parametrize("phase", ["before", "after"])
def test_actual_owned_postgres_transport_loss(adapter: Any, phase: str) -> None:
    repo = adapter
    if not hasattr(repo, "database_url"):
        pytest.skip("Actual PostgreSQL AF_UNIX client transport only")
    setup_references(repo, 0)
    real = repo.connection
    pid = real.info.backend_pid
    with independent(repo) as admin:
        identity = admin.execute(
            "SELECT pid,backend_start,usename,datname FROM pg_stat_activity WHERE pid=%s", (pid,)
        ).fetchone()
    assert identity[0] == pid and identity[2] == "control_owner"
    evidence(
        dict(
            kind="owned-backend-before-cancellation",
            backend="postgres",
            pid=pid,
            start=str(identity[1]),
            phase=phase,
        )
    )
    before = durable(repo)
    rollbacks, closes, fired = [], [], []

    class LostTransport:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        def rollback(self) -> None:
            rollbacks.append(True)
            real.rollback()

        def commit(self) -> None:
            if phase == "after":
                real.commit()
            with independent(repo) as admin:
                current = admin.execute(
                    "SELECT pid,backend_start,usename,datname FROM pg_stat_activity WHERE pid=%s",
                    (pid,),
                ).fetchone()
                assert current == identity
                assert admin.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone() == (
                    True,
                )
            fired.append(True)
            if phase == "before":
                real.commit()
            else:
                real.execute("SELECT 1")

        def close(self) -> None:
            closes.append(True)
            real.close()

    proxy = LostTransport()
    bind(repo, proxy)
    request = control(0, "RETIRE")
    try:
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            invoke(repo, request)
        after = durable(repo)  # Before explicit repository reopening.
        assert fired == [True] and rollbacks == [True] and closes == [True]
        assert repo._baseline_publication_connection.failed
        assert (after == before) == (phase == "before")
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            invoke(repo, request)
        assert closes == [True]
        peer = reopen(repo)
        try:
            if phase == "after":
                receipt_before = peer.page_baseline_control_events(config().scope_id).items[0]
                assert invoke(peer, request).receipt == receipt_before
            else:
                assert peer.page_baseline_control_events(config().scope_id).total == 0
                assert invoke(peer, request).scope.control_revision == 1
        finally:
            peer.close()
        with independent(repo) as admin:
            assert admin.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE pid=%s AND backend_start=%s",
                (pid, identity[1]),
            ).fetchone() == (0,)
        evidence(
            dict(
                kind="actual-transport-loss",
                backend="postgres",
                phase=phase,
                pid=pid,
                fired=1,
                close_attempts=1,
                raw_before_reopen=snapshot_hash(after),
                quarantined=True,
                no_false_rollback=True,
                explicit_reconciliation=True,
                backend_absent=True,
            )
        )
    finally:
        bind(repo, real)


@pytest.mark.parametrize("autocommit", [False, True])
def test_caller_custody_both_public_methods(adapter: Any, autocommit: bool) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory has no foreign connection transaction")
    setup_references(repo, 0)
    real = repo.connection
    real.execute("CREATE TABLE control_sentinel(id INTEGER)")
    real.commit()
    if autocommit:
        real.autocommit = True
    else:
        real.execute("BEGIN")
        real.execute("INSERT INTO control_sentinel VALUES(17)")
    probe = DriverProbe(real, not isinstance(repo, SQLiteRepository))
    bind(repo, probe)
    try:
        for call in (
            lambda: invoke(repo, control(0, "FREEZE")),
            lambda: repo.page_baseline_control_events(config().scope_id),
        ):
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
                call()
        assert probe.events == [] and probe.closes == 0
        if not autocommit:
            assert real.execute("SELECT * FROM control_sentinel").fetchall() == [(17,)]
    finally:
        bind(repo, real)
        if autocommit:
            real.autocommit = (
                sqlite3.LEGACY_TRANSACTION_CONTROL if isinstance(repo, SQLiteRepository) else False
            )
        else:
            real.rollback()
    assert invoke(repo, control(0, "FREEZE")).scope.control_revision == 1


@pytest.mark.parametrize("action", ["FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE"])
def test_memory_fallible_preparation_inventory(action: str) -> None:
    import ast
    import sys

    repo = MemoryRepository()
    view, _ = full_setup(repo)
    request = control(64, action, view.previous.generation_id if action == "ROLLBACK" else None)
    before = raw_state(repo)
    functions = {"memory_control", "_stage_control", "_operation_row", "_control_operation"}
    tree = ast.parse(Path(bs.__file__).read_text())
    sites = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            for part in ast.walk(node):
                if isinstance(
                    part, ast.Call | ast.Dict | ast.DictComp | ast.SetComp | ast.ListComp
                ):
                    sites.add((node.name, part.lineno))
    observed = []
    target = None
    fired = []
    marker = MemoryError("synthetic preparation allocation refusal")

    def trace(frame: Any, event: str, arg: Any) -> Any:
        site = (frame.f_code.co_name, frame.f_lineno)
        if event == "line" and frame.f_code.co_filename == bs.__file__ and site in sites:
            observed.append(site)
            if target == len(observed) - 1:
                fired.append(site)
                raise marker
        return trace

    sys.settrace(trace)
    try:
        invoke(repo, request)
    finally:
        sys.settrace(None)
    inventory = list(observed)
    assert inventory
    repo._baseline_scopes, repo._baseline_generations, repo._baseline_operations = before
    evidence(dict(kind="memory-inventory", backend="memory", action=action, sites=inventory))
    for target, site in enumerate(inventory):
        observed.clear()
        fired.clear()
        references = (repo._baseline_scopes, repo._baseline_generations, repo._baseline_operations)
        sys.settrace(trace)
        try:
            with pytest.raises(MemoryError) as caught:
                invoke(repo, request)
        finally:
            sys.settrace(None)
        assert caught.value is marker and fired == [site]
        assert raw_state(repo) == before
        assert all(
            a is b
            for a, b in zip(
                references,
                (repo._baseline_scopes, repo._baseline_generations, repo._baseline_operations),
                strict=True,
            )
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(repo.get_baseline_scope, config().scope_id).result(15) == view
        evidence(
            dict(
                kind="memory-stage-fault",
                backend="memory",
                action=action,
                target=target,
                site=site,
                fired=1,
                original_map_references=True,
                independent_snapshot=False,
                public_other_thread_read=True,
                prestate=True,
            )
        )
    assert invoke(repo, request).scope.control_revision == 65


@pytest.mark.parametrize("phase", ["enter", "body", "commit", "readback"])
@pytest.mark.parametrize("close_fails", [False, True])
def test_cleanup_secondary_preserves_primary(
    adapter: Any, monkeypatch: Any, phase: str, close_fails: bool
) -> None:
    repo = adapter
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory has no SQL transaction cleanup")
    setup_references(repo, 0)
    real = repo.connection
    primary = TypeError("new control orchestration primary")
    fired, rollbacks, closes = [], [], []
    actual_stage = bs._stage_control

    class FailedCleanup(DriverProbe):
        def observe(self, event: str) -> None:
            if not fired and phase == "enter" and event.startswith("BEGIN"):
                fired.append(True)
                raise primary

        def commit(self) -> None:
            if phase == "commit":
                fired.append(True)
                if self.postgres:
                    import psycopg

                    raise psycopg.errors.CheckViolation("definite refusal")
                raise sqlite3.IntegrityError("definite refusal")
            real.commit()
            self.committed = True

        def rollback(self) -> None:
            rollbacks.append(True)
            if fired:
                raise RuntimeError("secondary rollback")
            real.rollback()

        def close(self) -> None:
            closes.append(True)
            real.close()
            if close_fails:
                raise RuntimeError("secondary close after release")

    proxy = FailedCleanup(real, not isinstance(repo, SQLiteRepository))
    bind(repo, proxy)

    def stage(*args: Any, **kw: Any) -> Any:
        if phase == "body":
            fired.append(True)
            raise primary
        return actual_stage(*args, **kw)

    actual_replay = bs._PublicationSQL.control_replay

    def replay(*args: Any, **kw: Any) -> Any:
        if phase == "readback" and proxy.committed:
            fired.append(True)
            raise primary
        return actual_replay(*args, **kw)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(bs, "_stage_control", stage)
            patch.setattr(bs._PublicationSQL, "control_replay", replay)
            with pytest.raises((TypeError, bs.BaselineStorageError)) as caught:
                invoke(repo, control(0, "FREEZE"))
        assert fired == [True] and closes == [True]
        assert repo._baseline_publication_connection.failed
        if phase == "commit":
            assert caught.value.code == "BASELINE_STORAGE_UNAVAILABLE"
        else:
            assert caught.value is primary
        after = raw_state(repo)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            invoke(repo, control(0, "FREEZE"))
        assert closes == [True]
        evidence(
            dict(
                kind="cleanup-secondary",
                backend="sqlite" if isinstance(repo, SQLiteRepository) else "postgres",
                phase=phase,
                close_fails=close_fails,
                fired=1,
                quarantined=True,
                close_attempts=1,
                primary_preserved=True,
                raw_before_reopen=snapshot_hash(after),
            )
        )
    finally:
        bind(repo, real)
