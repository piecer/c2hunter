"""Deterministic new-preview fences; no sleeps or substituted preview results."""

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_baseline_retained_regression import durable, two_documents
from tests.test_historical_read_races import ObservedLock
from tests.test_historical_source import START, config, stored


@pytest.mark.parametrize("backend", ["memory", "sqlite-same", "sqlite-peer"])
@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("mutation", ["source", "delete", "candidate", "scope", "head", "parent"])
@pytest.mark.parametrize("projection_error", [False, True])
def test_preview_final_projection_visibility(
    backend: str,
    purpose: str,
    mutation: str,
    projection_error: bool,
    tmp_path: Any,
    monkeypatch: Any,
    record_property: Any,
) -> None:
    repo = MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "race.sqlite")
    with closing(repo):
        if mutation == "head":
            head, _ = two_documents(repo)
        else:
            head, _ = repo.create_baseline_scope(config(), "admin", START)
        revision = head.control_revision
        repo.save_job(stored())
        repo.save_candidates("root", [{"id": "old", "candidate_ip": "203.0.113.9", "score": 40}])
        before = repo.preview_baseline_source(config().scope_id, "root", revision, purpose)
        baseline = durable(repo)
        peer = SQLiteRepository(repo._path) if backend == "sqlite-peer" else repo
        observer = None
        if isinstance(repo, SQLiteRepository):
            observer = sqlite3.connect("file:" + repo._path + "?mode=ro", uri=True)
            observer.execute("BEGIN")
            assert (
                observer.execute("SELECT * FROM baseline_scopes ORDER BY scope_id").fetchall()
                == baseline[0]
            )
        entered, release, attempted = threading.Event(), threading.Event(), threading.Event()
        finish, fired = bs.finish_preview, []
        error = ValueError("owned projection error")

        def pause(*args: Any, **kw: Any) -> Any:
            fired.append(1)
            entered.set()
            assert release.wait(15)
            if projection_error:
                raise error
            return finish(*args, **kw)

        monkeypatch.setattr(bs, "finish_preview", pause)
        if peer is repo:
            monkeypatch.setattr(repo, "_lock", ObservedLock(repo._lock, attempted))
        else:
            peer.connection.set_trace_callback(
                lambda query: attempted.set() if query == "COMMIT" else None
            )

        def write() -> None:
            if mutation == "source":
                raw = stored()
                raw["flow_records"][0]["total_bytes"] = 999
                peer.save_job(raw)
            elif mutation == "delete":
                peer.delete_job("root")
            elif mutation == "candidate":
                peer.save_candidates(
                    "root", [{"id": "new", "candidate_ip": "203.0.113.9", "score": 80}]
                )
            elif isinstance(peer, MemoryRepository):
                with peer._lock:
                    if mutation == "parent":
                        peer.jobs["root"]["parent_job_id"] = "unlocked-new-parent"
                    elif mutation == "scope":
                        peer._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
                            dict(head.to_mapping(), control_revision=1)
                        )
                    else:
                        peer._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
                            dict(
                                head.to_mapping(),
                                control_revision=3,
                                state="REVOKED",
                                active=None,
                                previous=None,
                            )
                        )
                        peer._baseline_generations = {}
            else:
                with peer._lock, peer.connection:
                    if mutation == "parent":
                        peer.connection.execute(
                            "UPDATE objects SET "
                            "data=json_set(data,'$.parent_job_id','unlocked-new-parent') "
                            "WHERE kind='job' AND id='root'"
                        )
                    elif mutation == "scope":
                        peer.connection.execute("UPDATE baseline_scopes SET control_revision=1")
                    else:
                        peer.connection.execute(
                            "UPDATE baseline_scopes SET control_revision=3,state='REVOKED',"
                            "active_generation_id=NULL,previous_generation_id=NULL"
                        )
                        peer.connection.execute("DELETE FROM baseline_generations")

        try:
            with (
                ThreadPoolExecutor(max_workers=1, thread_name_prefix="reader") as reads,
                ThreadPoolExecutor(max_workers=1, thread_name_prefix="writer") as writes,
            ):
                future = reads.submit(
                    repo.preview_baseline_source, config().scope_id, "root", revision, purpose
                )
                assert entered.wait(10)
                pending = writes.submit(write)
                try:
                    assert attempted.wait(10)
                    assert not pending.done()
                    if observer is not None:
                        assert (
                            observer.execute(
                                "SELECT * FROM baseline_scopes ORDER BY scope_id"
                            ).fetchall()
                            == baseline[0]
                        )
                        assert (
                            observer.execute(
                                "SELECT * FROM baseline_generations ORDER BY scope_id,generation_id"
                            ).fetchall()
                            == baseline[1]
                        )
                finally:
                    if observer is not None:
                        observer.rollback()
                    release.set()
                if projection_error:
                    with pytest.raises(ValueError) as caught:
                        future.result(10)
                    assert caught.value is error
                else:
                    assert future.result(10) == before
                pending.result(10)
            assert fired == [1]
            monkeypatch.setattr(bs, "finish_preview", finish)
            if isinstance(repo, SQLiteRepository):
                assert not repo.connection.in_transaction and not peer.connection.in_transaction
            repo.save_job(stored())
            revision = 3 if mutation == "head" else 1 if mutation == "scope" else 0
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(
                    repo.preview_baseline_source, config().scope_id, "root", revision, purpose
                ).result(10)
            if mutation == "candidate":
                assert (result.source_binding_sha256 == before.source_binding_sha256) is (
                    purpose == "APPROVAL"
                )
            record_property("projection_barrier_fired", len(fired))
            record_property("writer_attempt_observed", attempted.is_set())
        finally:
            release.set()
            if observer is not None:
                observer.close()
            if peer is not repo:
                peer.close()


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_discovery_parent_mutation_cannot_chase_new_edge(
    backend: str, purpose: str, tmp_path: Any, monkeypatch: Any, record_property: Any
) -> None:
    repo = (
        MemoryRepository()
        if backend == "memory"
        else SQLiteRepository(tmp_path / "discovery.sqlite")
    )
    with closing(repo):
        repo.create_baseline_scope(config(), "admin", START)
        repo.save_job(stored())
        control = repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
        peer = repo if backend == "memory" else SQLiteRepository(repo._path)
        entered, release, attempted = threading.Event(), threading.Event(), threading.Event()
        calls = []
        name = "_metadata" if backend == "memory" else "_sqlite_metadata"
        original = getattr(r, name)

        def pause(*a: Any, **kw: Any) -> Any:
            result = original(*a, **kw)
            calls.append(result["id"])
            entered.set()
            assert release.wait(15)
            return result

        monkeypatch.setattr(r, name, pause)
        if backend == "memory":
            monkeypatch.setattr(repo, "_lock", ObservedLock(repo._lock, attempted))
        else:
            peer.connection.set_trace_callback(lambda q: attempted.set() if q == "COMMIT" else None)

        def mutate() -> None:
            with peer._lock:
                if backend == "memory":
                    peer.jobs["root"]["parent_job_id"] = "unlocked-new-parent"
                else:
                    with peer.connection:
                        peer.connection.execute(
                            "UPDATE objects SET "
                            "data=json_set(data,'$.parent_job_id','unlocked-new-parent') "
                            "WHERE kind='job' AND id='root'"
                        )

        try:
            with (
                ThreadPoolExecutor(max_workers=1, thread_name_prefix="reader") as reads,
                ThreadPoolExecutor(max_workers=1, thread_name_prefix="writer") as writes,
            ):
                future = reads.submit(
                    repo.preview_baseline_source, config().scope_id, "root", 0, purpose
                )
                assert entered.wait(10)
                pending = writes.submit(mutate)
                try:
                    assert attempted.wait(10) and not pending.done()
                finally:
                    release.set()
                assert future.result(10) == control
                pending.result(10)
            assert calls == ["root"]
            record_property("discovery_calls", calls)
            monkeypatch.setattr(r, name, original)
            with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_LINEAGE_INVALID$"):
                repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
            repo.save_job(stored())
            assert repo.preview_baseline_source(config().scope_id, "root", 0, purpose) == control
        finally:
            release.set()
            if peer is not repo:
                peer.close()
