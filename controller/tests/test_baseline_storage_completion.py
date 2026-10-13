"""Real retained pairs, typed corruption, catalog and postcommit readback."""

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_baseline_retained_regression import durable, two_documents
from tests.test_historical_source import START, config, stored


@pytest.fixture(params=["memory", "sqlite"])
def pair_repo(request: Any, tmp_path: Any) -> Any:
    repo = (
        MemoryRepository()
        if request.param == "memory"
        else SQLiteRepository(tmp_path / "pair.sqlite")
    )
    with closing(repo):
        yield repo


MUTATIONS = (
    "config-id",
    "identity",
    "creator",
    "created-at",
    "revision",
    "frozen",
    "state",
    "watermark",
    "active-missing",
    "previous-missing",
    "same-pointer",
    "swap-order",
    "doc-missing",
    "doc-id",
    "doc-revision",
    "doc-size",
    "doc-hash",
    "doc-scope",
    "doc-json",
)


def corrupt(repo: Any, view: Any, docs: Any, mutation: str) -> None:
    values = {
        "identity": ("config_sha256", "0" * 64),
        "creator": ("created_by", ""),
        "created-at": ("created_at", "not-time"),
        "revision": ("control_revision", 1),
        "frozen": ("frozen", 2),
        "state": ("state", "EMPTY"),
        "watermark": ("accepted_event_end", START),
        "active-missing": ("active", None),
        "previous-missing": ("previous", None),
        "same-pointer": ("previous", view.active),
    }
    if isinstance(repo, MemoryRepository):
        if mutation in values:
            key, value = values[mutation]
            repo._baseline_scopes[view.config.scope_id] = view.model_copy(update={key: value})
        elif mutation == "config-id":
            cfg = view.config.model_copy(
                update={"scope_id": "ffffffff-ffff-ffff-ffff-ffffffffffff"}
            )
            repo._baseline_scopes[view.config.scope_id] = view.model_copy(update={"config": cfg})
        elif mutation == "swap-order":
            repo._baseline_scopes[view.config.scope_id] = view.model_copy(
                update={"active": view.previous, "previous": view.active}
            )
        else:
            key = (view.config.scope_id, docs[0].generation_id)
            envelope = repo._baseline_generations.pop(key)
            if mutation == "doc-missing":
                return
            if mutation == "doc-id":
                key = (key[0], "ffffffff-ffff-ffff-ffff-ffffffffffff")
            envelope = list(envelope)
            if mutation == "doc-revision":
                envelope[0] = 3
            elif mutation == "doc-size":
                envelope[3] += 1
            elif mutation == "doc-hash":
                envelope[2] = "0" * 64
            elif mutation == "doc-json":
                envelope[1] = "{}"
            elif mutation == "doc-scope":
                envelope[1] = envelope[1].replace(key[0], "ffffffff-ffff-ffff-ffff-ffffffffffff")
                envelope[2] = hashlib.sha256(envelope[1].encode()).hexdigest()
                envelope[3] = len(envelope[1].encode())
            repo._baseline_generations[key] = tuple(envelope)
        return
    con = repo.connection
    if mutation in values:
        field, value = values[mutation]
        field = {"active": "active_generation_id", "previous": "previous_generation_id"}.get(
            field, field
        )
        if mutation == "same-pointer":
            value = value.generation_id
        if mutation == "watermark":
            value = value.isoformat()
        con.execute("PRAGMA ignore_check_constraints=ON")
        con.execute("UPDATE baseline_scopes SET " + field + "=?", (value,))
    elif mutation == "config-id":
        text = h.canonical_json(
            dict(view.config.to_mapping(), scope_id="ffffffff-ffff-ffff-ffff-ffffffffffff")
        )
        con.execute(
            "UPDATE baseline_scopes SET config_json=?,config_byte_size=?,config_content_sha256=?",
            (text, len(text.encode()), hashlib.sha256(text.encode()).hexdigest()),
        )
    elif mutation == "swap-order":
        con.execute(
            "UPDATE baseline_scopes SET active_generation_id=previous_generation_id,"
            "previous_generation_id=active_generation_id"
        )
    elif mutation == "doc-missing":
        con.execute(
            "DELETE FROM baseline_generations WHERE generation_id=?", (docs[0].generation_id,)
        )
    else:
        values = {
            "doc-id": ("generation_id", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
            "doc-revision": ("publication_revision", 3),
            "doc-size": ("byte_size", g.generation_view(docs[0]).byte_size + 1),
            "doc-hash": ("content_sha256", "0" * 64),
            "doc-json": ("document_json", "{}"),
        }
        if mutation == "doc-scope":
            text = g.generation_json(docs[0]).replace(
                view.config.scope_id, "ffffffff-ffff-ffff-ffff-ffffffffffff"
            )
            con.execute(
                "UPDATE baseline_generations SET document_json=?,byte_size=?,content_sha256=? "
                "WHERE generation_id=?",
                (
                    text,
                    len(text.encode()),
                    hashlib.sha256(text.encode()).hexdigest(),
                    docs[0].generation_id,
                ),
            )
        else:
            field, value = values[mutation]
            con.execute(
                "UPDATE baseline_generations SET " + field + "=? WHERE generation_id=?",
                (value, docs[0].generation_id),
            )
    con.commit()


@pytest.mark.parametrize("mutation", MUTATIONS)
@pytest.mark.parametrize("reader", ["get", "page", "preview", "create-replay"])
def test_retained_pair_scalar_corruption(
    pair_repo: Any, mutation: str, reader: str, record_property: Any
) -> None:
    repo = pair_repo
    view, docs = two_documents(repo)
    repo.save_job(stored())
    corrupt(repo, view, docs, mutation)
    before = durable(repo)
    operations = {
        "get": lambda: repo.get_baseline_scope(config().scope_id),
        "page": repo.page_baseline_scopes,
        "preview": lambda: repo.preview_baseline_source(config().scope_id, "root", 2, "APPROVAL"),
        "create-replay": lambda: repo.create_baseline_scope(config(), "fixture-admin", START),
    }
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        operations[reader]()
    assert durable(repo) == before
    record_property("real_producer_documents", len(docs))
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert (
            pool.submit(repo.get_baseline_scope, "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").result(10)
            is None
        )
    if isinstance(repo, SQLiteRepository):
        assert not repo.connection.in_transaction


@pytest.mark.parametrize("fault", ["missing", "corrupt", "readerror"])
def test_sqlite_postcommit_readback_durable_winner(
    tmp_path: Any, monkeypatch: Any, fault: str, record_property: Any
) -> None:
    with closing(SQLiteRepository(tmp_path / "readback.sqlite")) as repo:
        original = bs.sql_get
        fired = []

        def broken(connection: Any, identifier: str, **kw: Any) -> Any:
            assert not connection.in_transaction
            with closing(sqlite3.connect("file:" + repo._path + "?mode=ro", uri=True)) as obs:
                rows = obs.execute("SELECT config_json,created_by FROM baseline_scopes").fetchall()
                assert len(rows) == 1 and rows[0][1] == "admin"
            fired.append("committed")
            execute = bs._SQL.execute

            def target(self: Any, query: str, values: tuple = ()) -> Any:
                if fault == "missing" and query.startswith("SELECT length(CAST(config_json"):
                    return execute(self, query + " AND FALSE", values)
                if fault in ("corrupt", "readerror") and query.startswith("SELECT config_json,"):
                    if fault == "readerror":
                        return execute(self, "SELECT * FROM missing_owned_readback_relation")
                    return execute(
                        self,
                        query.replace("config_content_sha256,", "'" + "0" * 64 + "',", 1),
                        values,
                    )
                return execute(self, query, values)

            with monkeypatch.context() as patch:
                patch.setattr(bs._SQL, "execute", target)
                return original(connection, identifier, **kw)

        monkeypatch.setattr(bs, "sql_get", broken)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.create_baseline_scope(config(), "admin", START)
        assert fired == ["committed"]
        assert len(durable(repo)[0]) == 1 and not repo.connection.in_transaction
        record_property("postcommit_fault_fired", len(fired))
        monkeypatch.setattr(bs, "sql_get", original)
        with ThreadPoolExecutor(max_workers=1) as pool:
            view, created = pool.submit(
                repo.create_baseline_scope, config(), "admin", START
            ).result(10)
        assert not created and view.created_at == START
        with closing(SQLiteRepository(repo._path)) as peer:
            assert peer.get_baseline_scope(config().scope_id) == view


def test_retired_scope_counts_and_repeat_at_full(pair_repo: Any) -> None:
    repo = pair_repo
    view, _ = repo.create_baseline_scope(config(), "admin", START)
    for i in range(15):
        cfg = h.ScopeConfig.from_mapping(
            dict(config().to_mapping(), scope_id=f"00000000-0000-0000-0000-{i:012d}")
        )
        repo.create_baseline_scope(cfg, "admin", START)
    if isinstance(repo, MemoryRepository):
        repo._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
            dict(view.to_mapping(), state="RETIRED", frozen=True, control_revision=1)
        )
    else:
        with repo.connection:
            repo.connection.execute(
                "UPDATE baseline_scopes SET state='RETIRED',frozen=1,control_revision=1 "
                "WHERE scope_id=?",
                (config().scope_id,),
            )
    current, created = repo.create_baseline_scope(config(), "admin", START)
    assert not created and current.state == "RETIRED" and current.created_at == view.created_at
    extra = h.ScopeConfig.from_mapping(
        dict(config().to_mapping(), scope_id="ffffffff-ffff-ffff-ffff-ffffffffffff")
    )
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_SCOPE_LIMIT$"):
        repo.create_baseline_scope(extra, "admin", START)
    assert repo.page_baseline_scopes().total == 16


@pytest.mark.parametrize("fault", ["config-json", "config-byte-size", "config-content-sha256"])
@pytest.mark.parametrize("reader", ["get", "page", "preview", "create-replay"])
def test_sqlite_config_envelope_corruption(tmp_path: Any, fault: str, reader: str) -> None:
    with closing(SQLiteRepository(tmp_path / "config.sqlite")) as repo:
        head, _ = two_documents(repo)
        repo.save_job(stored())
        statements = {
            "config-json": "UPDATE baseline_scopes SET config_json='{}'",
            "config-byte-size": "UPDATE baseline_scopes SET config_byte_size=config_byte_size+1",
            "config-content-sha256": "UPDATE baseline_scopes SET config_content_sha256='bad'",
        }
        with repo.connection:
            repo.connection.execute(statements[fault])
        before = durable(repo)
        operations = {
            "get": lambda: repo.get_baseline_scope(head.config.scope_id),
            "page": repo.page_baseline_scopes,
            "preview": lambda: repo.preview_baseline_source(
                head.config.scope_id, "root", 2, "COMPARISON"
            ),
            "create-replay": lambda: repo.create_baseline_scope(config(), "fixture-admin", START),
        }
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            operations[reader]()
        assert durable(repo) == before and not repo.connection.in_transaction


def test_create_staging_exception_preserves_identity_and_storage(
    pair_repo: Any, monkeypatch: Any, record_property: Any
) -> None:
    repo = pair_repo
    cfg = config()
    before = durable(repo)
    error = RuntimeError("owned canonical staging failure")
    fired = []

    def fail(*_a: Any, **_kw: Any) -> Any:
        fired.append(1)
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(bs.h, "canonical_json", fail)
        with pytest.raises(RuntimeError) as caught:
            repo.create_baseline_scope(cfg, "admin", START)
    assert caught.value is error and fired == [1]
    assert durable(repo) == before
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(repo.create_baseline_scope, cfg, "admin", START).result(10)[1]
    record_property("staging_fault_fired", len(fired))
