"""Exact catalog envelopes, retained documents and corruption are not absence."""

from typing import Any

import pytest

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from tests.test_historical_generation import producer_args
from tests.test_historical_source import START, config

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


def execute(repo: Any, query: str, values: tuple = ()) -> Any:
    return repo.connection.execute(
        query.replace("?", "%s") if hasattr(repo, "database_url") else query, values
    )


def seed_generation(repo: Any) -> tuple[Any, Any]:
    view, _ = repo.create_baseline_scope(config(), "admin", START)
    document = g.produce_generation(**producer_args())
    reference = g.generation_view(document)
    view = g.ScopeView.from_mapping(
        dict(
            view.to_mapping(),
            state="HAS_REFERENCE",
            control_revision=1,
            accepted_event_end=reference.newest_event_end,
            active=reference.to_mapping(),
        )
    )
    raw = g.generation_json(document)
    if hasattr(repo, "jobs"):
        assert hasattr(repo, "_baseline_generations"), "retained Memory generation envelope missing"
        repo._baseline_generations[(config().scope_id, document.generation_id)] = (
            document.publication_revision,
            raw,
            reference.content_sha256,
            reference.byte_size,
        )
        repo._baseline_scopes[config().scope_id] = view
    else:
        execute(
            repo,
            "INSERT INTO "
            "baseline_generations(scope_id,generation_id,publication_revision,document_json,content_sha256,byte_size)"
            " VALUES(?,?,?,?,?,?)",
            (
                config().scope_id,
                document.generation_id,
                document.publication_revision,
                raw,
                reference.content_sha256,
                reference.byte_size,
            ),
        )
        execute(
            repo,
            "UPDATE baseline_scopes SET "
            "state='HAS_REFERENCE',control_revision=1,accepted_event_end=?,active_generation_id=?"
            " WHERE scope_id=?",
            (view.to_mapping()["accepted_event_end"], document.generation_id, config().scope_id),
        )
        repo.connection.commit()
    return view, document


def test_valid_retained_document_without_live_source(scope_repo: Any, monkeypatch: Any) -> None:
    view, document = seed_generation(scope_repo)
    monkeypatch.setattr(scope_repo, "get_job", lambda *_: pytest.fail("live-source read"))
    assert scope_repo.get_baseline_scope(config().scope_id) == view
    assert scope_repo.page_baseline_scopes().items == (view,)


@pytest.mark.parametrize("corruption", ["missing", "digest", "size", "revision", "overbyte"])
def test_retained_document_corruption_is_storage_failure(scope_repo: Any, corruption: str) -> None:
    repo = scope_repo
    _, doc = seed_generation(repo)
    if hasattr(repo, "jobs"):
        key = (config().scope_id, doc.generation_id)
        revision, raw, digest, size = repo._baseline_generations[key]
        if corruption == "missing":
            del repo._baseline_generations[key]
        else:
            if corruption == "digest":
                digest = "0" * 64
            if corruption == "size":
                size += 1
            if corruption == "revision":
                revision += 1
            if corruption == "overbyte":
                raw = "é" * 2097152
            repo._baseline_generations[key] = (revision, raw, digest, size)
    else:
        if corruption == "missing":
            execute(repo, "DELETE FROM baseline_generations")
        elif corruption == "digest":
            execute(repo, "UPDATE baseline_generations SET content_sha256=?", ("0" * 64,))
        elif corruption == "size":
            execute(repo, "UPDATE baseline_generations SET byte_size=byte_size+1")
        elif corruption == "revision":
            execute(repo, "UPDATE baseline_generations SET publication_revision=2")
        else:
            if hasattr(repo, "database_url"):
                # Corrupt-storage read defense also protects pre-constraint imported data.
                names = execute(
                    repo,
                    "SELECT conname FROM pg_constraint WHERE "
                    "conrelid='baseline_generations'::regclass AND contype='c'",
                ).fetchall()
                from psycopg import sql

                for (name,) in names:
                    repo.connection.execute(
                        sql.SQL("ALTER TABLE baseline_generations DROP CONSTRAINT {}").format(
                            sql.Identifier(name)
                        )
                    )
            else:
                execute(repo, "PRAGMA ignore_check_constraints=ON")
            execute(repo, "UPDATE baseline_generations SET document_json=?", ("é" * 2097152,))
        repo.connection.commit()
    with pytest.raises(ValueError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.get_baseline_scope(config().scope_id)


@pytest.mark.parametrize("changed", ["actor", "name", "reason"])
def test_full_config_creator_replay_and_quota(scope_repo: Any, changed: str) -> None:
    cfg = config()
    view, _ = scope_repo.create_baseline_scope(cfg, "admin", START)
    for index in range(15):
        other = h.ScopeConfig.from_mapping(
            dict(cfg.to_mapping(), scope_id=f"00000000-0000-0000-0000-{index:012d}")
        )
        assert scope_repo.create_baseline_scope(other, "admin", START)[1]
    assert scope_repo.create_baseline_scope(cfg, "admin", START) == (view, False)
    candidate = h.ScopeConfig.from_mapping(
        dict(cfg.to_mapping(), **({changed: "different"} if changed != "actor" else {}))
    )
    assert h.scope_config_sha256(candidate) == view.config_sha256
    with pytest.raises(ValueError, match="^BASELINE_SCOPE_EXISTS$"):
        scope_repo.create_baseline_scope(
            candidate, "other" if changed == "actor" else "admin", START
        )
    extra = h.ScopeConfig.from_mapping(
        dict(cfg.to_mapping(), scope_id="ffffffff-ffff-ffff-ffff-ffffffffffff")
    )
    with pytest.raises(ValueError, match="^BASELINE_SCOPE_LIMIT$"):
        scope_repo.create_baseline_scope(extra, "admin", START)
    items = scope_repo.page_baseline_scopes(0, 10)
    assert items.total == 16 and items.next_offset == 10
    tail = scope_repo.page_baseline_scopes(10, 10)
    assert len(tail.items) == 6 and tail.next_offset is None
    ids = [i.config.scope_id for i in (*items.items, *tail.items)]
    assert ids == sorted(ids) and len(set(ids)) == 16
    assert scope_repo.page_baseline_scopes(16, 20).items == ()
