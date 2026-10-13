"""Independent repository acceptance witnesses; no future publication API.

Generation fixtures use genuine synthetic reviews through the accepted producer.
Preview itself receives no review, and raw envelope installation does not claim
that a publication/control method exists. All assertions use public readers.
"""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_generation import advance, publish, source_job
from tests.test_historical_source import START, config, review, stored


def two_documents(repo: Any) -> tuple[Any, tuple[Any, ...]]:
    """Produce legal active+previous documents from real persisted acquisition."""
    head, created = repo.create_baseline_scope(config(), "fixture-admin", START)
    assert created
    documents = []
    current = None
    for index in range(2):
        raw = source_job(index)
        repo.save_job(raw)
        snapshot = repo.read_historical_source(
            raw["id"], purpose="APPROVAL", scope=head.config, quality_review=review()
        )
        current = publish(snapshot, head, current, index=index + 1)
        documents.append(current)
        head = advance(head, current)
    envelopes = []
    for doc in documents:
        ref = g.generation_view(doc)
        raw = g.generation_json(doc)
        assert (
            g.decode_generation(
                raw, content_sha256=ref.content_sha256, byte_size=ref.byte_size, scope=head.config
            )
            == doc
        )
        envelopes.append((doc.publication_revision, raw, ref.content_sha256, ref.byte_size))
    if isinstance(repo, MemoryRepository):
        with repo._lock:
            repo._baseline_scopes[head.config.scope_id] = head
            for doc, envelope in zip(documents, envelopes, strict=True):
                repo._baseline_generations[(head.config.scope_id, doc.generation_id)] = envelope
    else:
        with repo._lock, repo.connection:
            for doc, envelope in zip(documents, envelopes, strict=True):
                repo.connection.execute(
                    "INSERT INTO baseline_generations "
                    "(scope_id,generation_id,publication_revision,"
                    "document_json,content_sha256,byte_size) "
                    "VALUES(?,?,?,?,?,?)",
                    (head.config.scope_id, doc.generation_id, *envelope),
                )
            repo.connection.execute(
                "UPDATE baseline_scopes SET control_revision=?,state=?,accepted_event_end=?,"
                "active_generation_id=?,previous_generation_id=? WHERE scope_id=?",
                (
                    head.control_revision,
                    head.state,
                    head.to_mapping()["accepted_event_end"],
                    head.active.generation_id,
                    head.previous.generation_id,
                    head.config.scope_id,
                ),
            )
    for index in range(2):
        assert repo.delete_job(f"root-{index}")
    return head, tuple(documents)


def durable(repo: Any) -> Any:
    if isinstance(repo, MemoryRepository):
        with repo._lock:
            return (dict(repo._baseline_scopes), dict(repo._baseline_generations))
    with closing(sqlite3.connect("file:" + repo._path + "?mode=ro", uri=True)) as reader:
        return (
            reader.execute("SELECT * FROM baseline_scopes ORDER BY scope_id").fetchall(),
            reader.execute(
                "SELECT * FROM baseline_generations ORDER BY scope_id,generation_id"
            ).fetchall(),
        )


def deny_generic(*_args: Any, **_kwargs: Any) -> Any:
    pytest.fail("a retained-reference read depended on generic live-source hydration")


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_real_two_document_vertical(
    backend: str, purpose: str, tmp_path: Any, monkeypatch: Any
) -> None:
    repo = MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "two.sqlite")
    with closing(repo):
        head, docs = two_documents(repo)
        assert head.control_revision == 2
        assert head.previous.generation_id == docs[0].generation_id
        assert head.active.generation_id == docs[1].generation_id
        assert [d.publication_revision for d in docs] == [1, 2]
        assert [len(d.sources) for d in docs] == [1, 2]
        repo.save_job(stored())
        before = durable(repo)
        for name in ("get_job", "get_job_summary", "list_jobs", "get_candidates"):
            monkeypatch.setattr(repo, name, deny_generic)
        monkeypatch.setattr(
            "c2hunter_controller.historical_source.source_build_input", deny_generic
        )
        assert repo.get_baseline_scope(head.config.scope_id) == head
        assert repo.page_baseline_scopes().items == (head,)
        preview = repo.preview_baseline_source(head.config.scope_id, "root", 2, purpose)
        assert preview.scope_revision == 2
        assert preview.scope_config_sha256 == head.config_sha256
        assert preview.admissible and preview.eligible_profile_count == 4
        assert durable(repo) == before
        assert repo.get_baseline_scope("ffffffff-ffff-ffff-ffff-ffffffffffff") is None
        if backend == "sqlite":
            assert not repo.connection.in_transaction
            with closing(SQLiteRepository(repo._path)) as reopened:
                assert reopened.get_baseline_scope(head.config.scope_id) == head
                assert reopened.page_baseline_scopes().items == (head,)
                assert (
                    reopened.preview_baseline_source(head.config.scope_id, "root", 2, purpose)
                    == preview
                )
                assert durable(reopened) == before
        else:
            assert len(repo._baseline_generations) == 2


@pytest.mark.parametrize("operation", ["get", "page", "preview", "create-replay"])
def test_memory_null_retained_envelope_is_storage_failure(
    operation: str, monkeypatch: Any, record_property: Any
) -> None:
    """Present null retained state must be a closed storage failure, not TypeError."""
    with closing(MemoryRepository()) as repo:
        head, _ = two_documents(repo)
        repo.save_job(stored())
        identifier = head.config.scope_id
        key = (identifier, head.active.generation_id)
        original = repo._baseline_generations[key]
        assert repo.get_baseline_scope(identifier) == head  # legal control first
        with repo._lock:
            repo._baseline_generations[key] = None
        before = durable(repo)
        calls = []

        def observe_document(*args: Any, **kwargs: Any) -> Any:
            calls.append(args[2])
            return actual_document(*args, **kwargs)

        actual_document = bs._document
        monkeypatch.setattr(bs, "_document", observe_document)
        operations = {
            "get": lambda: repo.get_baseline_scope(identifier),
            "page": repo.page_baseline_scopes,
            "preview": lambda: repo.preview_baseline_source(identifier, "root", 2, "APPROVAL"),
            "create-replay": lambda: repo.create_baseline_scope(config(), "fixture-admin", START),
        }
        caught = None
        try:
            operations[operation]()
        except Exception as error:
            caught = error
        # Observe the actual corrupt dereference separately from its error contract.
        assert calls == [None]
        record_property("null_envelope_dereferences", len(calls))
        record_property("actual_exception_type", type(caught).__name__)
        record_property("actual_exception_text", str(caught))
        assert durable(repo) == before
        with repo._lock:
            repo._baseline_generations[key] = original
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(repo.get_baseline_scope, identifier).result(timeout=10) == head
        assert isinstance(caught, bs.BaselineStorageError), (
            f"present corrupt retained envelope escaped {operation}: "
            f"{type(caught).__name__}: {caught}"
        )
        assert caught.code == "BASELINE_STORAGE_UNAVAILABLE"
