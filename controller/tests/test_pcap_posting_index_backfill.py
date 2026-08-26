from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Barrier, Thread
from typing import Any

import pytest
from test_pcap_offset_index_live import _build as build_live_parent
from test_pcap_offset_index_live import _pcap as live_pcap
from test_pcap_offset_index_live import _save as save_live_source
from test_pcap_posting_index_repository import MutableClock, _prepare

from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_backfill_marks_only_the_deterministic_bounded_batch_with_database_time(
    tmp_path: Any, kind: str
) -> None:
    database_now = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(database_now)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "backfill.sqlite", _lease_clock=clock)
    )
    # Deliberately create in reverse order: selection is stable by exact source identity.
    for source_id in ("posting-job-c", "posting-job-b", "posting-job-a"):
        _prepare(repository, source_id=source_id)

    assert repository.request_posting_index_backfill(limit=2) == 2
    assert (
        [key for key in sorted(repository.posting_index_intents) if key[0] == "PCAP_UPLOAD"]
        == [
            ("PCAP_UPLOAD", "posting-job-a"),
            ("PCAP_UPLOAD", "posting-job-b"),
        ]
        if kind == "memory"
        else [
            tuple(row)
            for row in repository.connection.execute(
                "SELECT source_kind,source_id FROM pcap_posting_index_intents "
                "ORDER BY source_kind,source_id"
            ).fetchall()
        ]
    )
    for source_id in ("posting-job-a", "posting-job-b"):
        intent = repository.get_posting_index_intent("PCAP_UPLOAD", source_id)
        assert intent is not None
        assert intent.requested_at == database_now
        assert intent.updated_at == database_now
        assert repository.get_posting_index_task("PCAP_UPLOAD", source_id) is None

    clock.value += timedelta(seconds=1)
    assert repository.request_posting_index_backfill(limit=2) == 1
    assert repository.request_posting_index_backfill(limit=2) == 0
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_backfill_preserves_terminal_same_identity_and_survives_sqlite_restart(
    tmp_path: Any, kind: str
) -> None:
    path = tmp_path / "terminal-restart.sqlite"
    repository = MemoryRepository() if kind == "memory" else SQLiteRepository(path)
    source, parent, _posting, _replacement = _prepare(
        repository, source_id=f"posting-job-terminal-{kind}"
    )
    original = repository.request_posting_index(source, parent)
    assert original is not None
    repository.admit_posting_index("PCAP_UPLOAD", source.source_id, capacity=1, max_attempts=1)
    claimed = repository.claim_posting_index(lease_seconds=30)
    assert claimed is not None and claimed.lease_token
    assert repository.fail_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        transient=False,
        error_code="POSTING_TERMINAL",
        retry_base_seconds=1,
    )
    terminal_intent = repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id)
    terminal_task = repository.get_posting_index_task("PCAP_UPLOAD", source.source_id)
    if kind == "sqlite":
        repository.close()
        repository = SQLiteRepository(path)

    assert repository.request_posting_index_backfill(limit=1) == 0
    assert repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id) == terminal_intent
    assert repository.get_posting_index_task("PCAP_UPLOAD", source.source_id) == terminal_task
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_backfill_excludes_wrong_mode_missing_source_stale_owner_and_unsupported_parent(
    tmp_path: Any, kind: str
) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "eligibility.sqlite")
    )
    ids = {
        "eligible": "posting-job-eligible",
        "mode": "posting-job-reanalysis",
        "missing": "posting-job-missing",
        "stale": "posting-job-stale",
        "unsupported": "posting-job-unsupported",
    }
    prepared = {name: _prepare(repository, source_id=source_id) for name, source_id in ids.items()}
    if kind == "memory":
        repository.jobs[ids["mode"]]["mode"] = "REANALYSIS"
        repository.capture_source_versions.pop(ids["missing"])
        stale = prepared["stale"][0]
        repository.capture_source_versions[ids["stale"]] = type(stale)(
            stale.source_kind,
            stale.source_id,
            stale.object_key,
            f"{stale.source_version_id}-replacement",
            stale.source_size_bytes,
            stale.source_sha256,
        )
        unsupported_parent = prepared["unsupported"][1]
        repository.structural_index_generations[unsupported_parent.build_id] = type(
            unsupported_parent
        )(
            unsupported_parent.build_id,
            type(unsupported_parent.binding)(
                unsupported_parent.binding.source_kind,
                unsupported_parent.binding.source_id,
                unsupported_parent.binding.source_version_id,
                unsupported_parent.binding.source_size_bytes,
                unsupported_parent.binding.source_sha256,
                unsupported_parent.binding.capture_format,
                99,
                unsupported_parent.binding.parser_contract_version,
            ),
            unsupported_parent.created_at,
            unsupported_parent.index_sha256,
            unsupported_parent.interfaces,
            unsupported_parent.packets,
        )
    else:
        repository.connection.execute(
            "UPDATE objects SET data=json_set(data,'$.mode','REANALYSIS') "
            "WHERE kind='job' AND id=?",
            (ids["mode"],),
        )
        repository.connection.execute(
            "DELETE FROM pcap_capture_source_versions "
            "WHERE source_kind='PCAP_UPLOAD' AND source_id=?",
            (ids["missing"],),
        )
        repository.connection.execute(
            "UPDATE pcap_capture_source_versions "
            "SET source_version_id=source_version_id||'-replacement' "
            "WHERE source_kind='PCAP_UPLOAD' AND source_id=?",
            (ids["stale"],),
        )
        repository.connection.execute(
            "UPDATE pcap_offset_index_generations "
            "SET binding=json_set(binding,'$.schema_version',99) "
            "WHERE build_id=?",
            (prepared["unsupported"][1].build_id,),
        )
        repository.connection.commit()

    assert repository.request_posting_index_backfill(limit=10) == 1
    assert repository.get_posting_index_intent("PCAP_UPLOAD", ids["eligible"]) is not None
    for name in ("mode", "missing", "stale", "unsupported"):
        assert repository.get_posting_index_intent("PCAP_UPLOAD", ids[name]) is None
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_backfill_uses_exact_source_kind_and_only_finalized_live_segments(
    tmp_path: Any, kind: str
) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "live-eligibility.sqlite")
    )
    # The upload intentionally shares the LIVE segment's source_id.
    _prepare(repository, source_id="segment-1")
    save_live_source(repository, live_pcap())
    assert repository.request_posting_index_backfill(limit=10) == 1
    assert repository.get_posting_index_intent("PCAP_UPLOAD", "segment-1") is not None
    assert repository.get_posting_index_intent("LIVE_SEGMENT", "segment-1") is None

    assert build_live_parent(repository)
    assert repository.request_posting_index_backfill(limit=10) == 1
    live_intent = repository.get_posting_index_intent("LIVE_SEGMENT", "segment-1")
    assert live_intent is not None and live_intent.spec.source_kind == "LIVE_SEGMENT"
    assert repository.get_posting_index_task("LIVE_SEGMENT", "segment-1") is None
    repository.close()


class _ExactLookupOnlyDict(dict[Any, Any]):
    def __iter__(self):  # type: ignore[no-untyped-def]
        raise AssertionError("broad source scan")

    def values(self):  # type: ignore[no-untyped-def]
        raise AssertionError("broad source scan")

    def items(self):  # type: ignore[no-untyped-def]
        raise AssertionError("broad source scan")


def test_memory_backfill_does_not_scan_all_authoritative_sources() -> None:
    repository = MemoryRepository()
    _prepare(repository, source_id="posting-job-exact-lookup")
    repository.capture_source_versions = _ExactLookupOnlyDict(repository.capture_source_versions)
    repository.jobs = _ExactLookupOnlyDict(repository.jobs)

    assert repository.request_posting_index_backfill(limit=1) == 1
    repository.close()


def test_sqlite_concurrent_backfill_workers_are_bounded_and_resumable(tmp_path: Any) -> None:
    path = tmp_path / "concurrent.sqlite"
    repository = SQLiteRepository(path)
    for source_id in ("posting-job-c", "posting-job-b", "posting-job-a"):
        _prepare(repository, source_id=source_id)
    repository.close()

    barrier = Barrier(2)
    results: list[int] = []
    errors: list[BaseException] = []

    def run() -> None:
        facade = SQLiteRepository(path)
        try:
            barrier.wait()
            results.append(facade.request_posting_index_backfill(limit=2))
        except BaseException as exc:
            errors.append(exc)
        finally:
            facade.close()

    workers = [Thread(target=run, daemon=True) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(5)

    assert not errors
    assert all(not worker.is_alive() for worker in workers)
    assert sorted(results) == [1, 2]
    reopened = SQLiteRepository(path)
    assert reopened.request_posting_index_backfill(limit=2) == 0
    assert reopened.connection.execute(
        "SELECT COUNT(*) FROM pcap_posting_index_intents"
    ).fetchone() == (3,)
    reopened.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_replaced_current_structural_owner_gets_a_new_backfill_identity(
    tmp_path: Any, kind: str
) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "replacement-backfill.sqlite")
    )
    source, parent, _posting, _replacement = _prepare(
        repository, source_id=f"posting-job-replacement-{kind}"
    )
    assert repository.request_posting_index_backfill(limit=1) == 1
    original = repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id)
    assert original is not None

    replacement_id = f"{parent.build_id}-new-owner"
    repository.begin_structural_index(replacement_id, parent.binding, parent.created_at)
    repository.stage_structural_index_packets(replacement_id, parent.packets)
    assert repository.publish_structural_index(
        replacement_id, parent.binding, parent.interfaces, len(parent.packets)
    )
    assert repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id) is None
    assert repository.request_posting_index_backfill(limit=1) == 1
    replacement = repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id)
    assert replacement is not None
    assert replacement.spec.parent_structural_build_id == replacement_id
    assert replacement.spec.identity != original.spec.identity
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_backfill_limit_must_be_positive(tmp_path: Any, kind: str) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "invalid-limit.sqlite")
    )
    with pytest.raises(ValueError, match="backfill limit"):
        repository.request_posting_index_backfill(limit=0)
    repository.close()
