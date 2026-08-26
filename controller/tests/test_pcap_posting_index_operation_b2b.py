from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from c2hunter_analysis.pcap_postings import (
    PCAP_FILTER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_SCHEMA_VERSION,
    PostingBuildLimits,
)
from test_pcap_offset_index_live import _build as build_live_parent
from test_pcap_offset_index_live import _pcap as live_pcap
from test_pcap_offset_index_live import _save as save_live_source
from test_pcap_posting_index_repository import _claim, _prepare
from test_pcap_posting_index_worker import task as worker_task

from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_offset_index import (
    IndexAvailability,
    SourceIndexBinding,
    StructuralIndexLookup,
)
from c2hunter_controller.pcap_posting_index import (
    PostingIndexAvailability,
    PostingIndexPermanentError,
    PostingIndexTransientError,
)
from c2hunter_controller.pcap_posting_index_worker import (
    PostingOperationResult,
    create_posting_operation_builder,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def _settings() -> Settings:
    return Settings(
        environment="test",
        pcap_posting_index_build_max_packets=101,
        pcap_posting_index_build_max_memberships=102,
        pcap_posting_index_build_max_distinct_keys=103,
        pcap_posting_index_build_max_encoded_bytes=104,
        pcap_posting_index_build_max_chunks=105,
        pcap_posting_index_build_batch_size=7,
    )


def _operation(builder: Any, repository: Any, claimed: Any, *, deadline: float = 10.0) -> Any:
    assert claimed.lease_token is not None
    return builder(
        repository,
        task=claimed,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        deadline=deadline,
        should_cancel=lambda: False,
    )


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_upload_factory_builds_and_atomically_publishes_from_claimed_task(
    tmp_path: Path, kind: str
) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "posting-operation.sqlite")
    )
    source, parent, _first, _second = _prepare(repository, source_id=f"posting-op-{kind}")
    claimed, _now = _claim(repository, source, parent)

    result = _operation(
        create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
        repository,
        claimed,
    )()

    assert result == PostingOperationResult(
        published=True,
        membership_count=result.membership_count,
        encoded_byte_count=result.encoded_byte_count,
    )
    assert result.membership_count > 0 and result.encoded_byte_count > 0
    lookup = repository.get_posting_index(source, parent)
    assert lookup.availability is PostingIndexAvailability.READY
    assert lookup.snapshot is not None
    assert (
        lookup.snapshot.binding.parent_structural_build_id
        == claimed.spec.parent_structural_build_id
    )
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_live_factory_uses_live_version_parent_and_linked_sensor_object(
    tmp_path: Path, kind: str
) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "posting-live-operation.sqlite")
    )
    save_live_source(repository, live_pcap())
    assert build_live_parent(repository, request_postings=True)
    claimed = repository.claim_posting_index(lease_seconds=30)
    assert claimed is not None and claimed.spec.source_kind == "LIVE_SEGMENT"

    result = _operation(
        create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
        repository,
        claimed,
    )()

    source = repository.get_live_capture_source_version("segment-1")
    assert source is not None
    binding = SourceIndexBinding(
        source.source_kind,
        source.source_id,
        source.source_version_id,
        source.source_size_bytes,
        source.source_sha256,
        "PCAP",
    )
    parent_lookup = repository.get_structural_index(binding)
    assert parent_lookup.availability is IndexAvailability.READY
    assert parent_lookup.snapshot is not None
    assert isinstance(result, PostingOperationResult) and result.published
    assert (
        repository.get_posting_index(source, parent_lookup.snapshot).availability
        is PostingIndexAvailability.READY
    )
    repository.close()


def test_contract_mismatch_is_permanent_before_metadata_or_source_io() -> None:
    class Repository:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"repository I/O before contract rejection: {name}")

    claimed = replace(
        worker_task(),
        spec=replace(
            worker_task().spec, posting_schema_version=PCAP_POSTING_INDEX_SCHEMA_VERSION + 1
        ),
    )
    operation = _operation(
        create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
        Repository(),
        claimed,
    )

    with pytest.raises(PostingIndexPermanentError) as raised:
        operation()
    assert raised.value.code == "POSTING_CONTRACT_UNSUPPORTED"


def test_factory_passes_exact_claim_uuid_limits_batch_and_combined_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="posting-exact-operation")
    claimed, _now = _claim(repository, source, parent)
    captured: dict[str, Any] = {}

    def build(repository_arg: Any, opened: Any, **kwargs: Any) -> bool:
        captured.update(kwargs)
        captured["repository"] = repository_arg
        captured["source"] = opened
        assert kwargs["should_cancel"]() is False
        kwargs["on_published"](_first)
        opened.close()  # The orchestration layer owns the source lifetime.
        return True

    monkeypatch.setattr(
        "c2hunter_controller.pcap_posting_index_worker.build_and_publish_source_posting_index",
        build,
    )
    monkeypatch.setattr(
        "c2hunter_controller.pcap_posting_index_worker.uuid4",
        lambda: type("BuildUuid", (), {"hex": "frozen-build-uuid"})(),
    )
    builder = create_posting_operation_builder(_settings(), monotonic=lambda: 9.0)

    assert _operation(builder, repository, claimed, deadline=10.0)() == PostingOperationResult(
        published=True,
        membership_count=_first.generation.membership_count,
        encoded_byte_count=_first.generation.encoded_byte_count,
    )
    assert captured["repository"] is repository
    assert captured["source_version"] == source
    assert captured["parent"].build_id == parent.build_id
    assert captured["parent"].index_sha256 == parent.index_sha256
    assert captured["attempt"] == claimed.attempt
    assert captured["lease_token"] == claimed.lease_token
    assert captured["build_id"] == "frozen-build-uuid"
    assert captured["limits"] == PostingBuildLimits(101, 102, 103, 104, 105, 7)
    assert captured["stage_batch_size"] == 7
    assert captured["internal_networks"] == ("0.0.0.0/0", "::/0")
    assert captured["source"].closed
    assert (
        claimed.spec.posting_schema_version,
        claimed.spec.posting_parser_contract_version,
        claimed.spec.filter_contract_version,
    ) == (
        PCAP_POSTING_INDEX_SCHEMA_VERSION,
        PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
        PCAP_FILTER_CONTRACT_VERSION,
    )


@pytest.mark.parametrize(
    ("availability", "code"),
    [
        (IndexAvailability.MISSING, "POSTING_PARENT_MISSING"),
        (IndexAvailability.STALE, "POSTING_PARENT_STALE"),
        (IndexAvailability.CORRUPT, "POSTING_PARENT_CORRUPT"),
        (IndexAvailability.UNSUPPORTED_SCHEMA, "POSTING_PARENT_UNSUPPORTED"),
    ],
)
def test_non_ready_parent_is_permanent_before_source_open(
    monkeypatch: pytest.MonkeyPatch, availability: IndexAvailability, code: str
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id=f"parent-{availability}")
    claimed, _now = _claim(repository, source, parent)
    opens = 0

    monkeypatch.setattr(
        repository, "get_structural_index", lambda _binding: StructuralIndexLookup(availability)
    )

    def opened(_source_id: str) -> None:
        nonlocal opens
        opens += 1

    monkeypatch.setattr(repository, "open_job_capture", opened)
    with pytest.raises(PostingIndexPermanentError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == code
    assert opens == 0


@pytest.mark.parametrize(
    ("replacement", "code"),
    [(None, "POSTING_SOURCE_MISSING"), ("changed", "POSTING_SOURCE_STALE")],
)
def test_missing_or_replaced_source_is_permanent_before_open(
    monkeypatch: pytest.MonkeyPatch, replacement: str | None, code: str
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id=f"source-{replacement}")
    claimed, _now = _claim(repository, source, parent)
    resolved = None if replacement is None else replace(source, source_version_id="sha256:changed")
    monkeypatch.setattr(repository, "get_capture_source_version", lambda _source_id: resolved)
    monkeypatch.setattr(
        repository,
        "open_job_capture",
        lambda _source_id: pytest.fail("source opened after authoritative version rejection"),
    )

    with pytest.raises(PostingIndexPermanentError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == code


def test_metadata_and_open_backend_failures_have_bounded_transient_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="backend-errors")
    claimed, _now = _claim(repository, source, parent)
    builder = create_posting_operation_builder(_settings(), monotonic=lambda: 0.0)

    monkeypatch.setattr(
        repository,
        "get_capture_source_version",
        lambda _source_id: (_ for _ in ()).throw(RuntimeError("raw database id")),
    )
    with pytest.raises(PostingIndexTransientError) as metadata:
        _operation(builder, repository, claimed)()
    assert metadata.value.code == "POSTING_METADATA_UNAVAILABLE"
    assert "raw" not in metadata.value.code

    monkeypatch.setattr(repository, "get_capture_source_version", lambda _source_id: source)
    monkeypatch.setattr(
        repository,
        "open_job_capture",
        lambda _source_id: (_ for _ in ()).throw(OSError("raw object key")),
    )
    with pytest.raises(PostingIndexTransientError) as opened:
        _operation(builder, repository, claimed)()
    assert opened.value.code == "POSTING_SOURCE_OPEN_UNAVAILABLE"
    assert "raw" not in opened.value.code


def test_deadline_after_metadata_prevents_source_open(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="deadline-pre-open")
    claimed, _now = _claim(repository, source, parent)
    ticks = iter((0.0, 11.0))
    monkeypatch.setattr(
        repository,
        "open_job_capture",
        lambda _source_id: pytest.fail("source opened after deadline"),
    )

    with pytest.raises(PostingIndexTransientError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: next(ticks)),
            repository,
            claimed,
            deadline=10.0,
        )()
    assert raised.value.code == "POSTING_BUILD_CANCELLED"


class _TrackingSource:
    def __init__(
        self, wrapped: Any, *, version_id: str | None = None, fail_read: bool = False
    ) -> None:
        self.wrapped = wrapped
        self.version_id = version_id or wrapped.version_id
        self.fail_read = fail_read
        self.close_count = 0
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        assert size > 0
        if self.fail_read:
            raise OSError("raw read failure")
        return self.wrapped.read(size)

    def seek(self, *_args: Any) -> None:
        raise AssertionError("posting operation must not seek")

    def read_range(self, *_args: Any) -> None:
        raise AssertionError("posting operation must not use ranges")

    def close(self) -> None:
        self.close_count += 1
        self.closed = True
        self.wrapped.close()


def test_opened_version_drift_closes_once_without_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="open-version-drift")
    claimed, _now = _claim(repository, source, parent)
    original = repository.open_job_capture(source.source_id)
    assert original is not None
    tracked = _TrackingSource(original, version_id="sha256:replacement")
    monkeypatch.setattr(repository, "open_job_capture", lambda _source_id: tracked)

    with pytest.raises(PostingIndexPermanentError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == "POSTING_SOURCE_STALE"
    assert tracked.close_count == 1


def test_read_failure_is_transient_and_orchestrator_closes_once_without_seek_or_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="read-failure")
    claimed, _now = _claim(repository, source, parent)
    original = repository.open_job_capture(source.source_id)
    assert original is not None
    tracked = _TrackingSource(original, fail_read=True)
    monkeypatch.setattr(repository, "open_job_capture", lambda _source_id: tracked)

    with pytest.raises(PostingIndexTransientError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == "POSTING_SOURCE_READ_UNAVAILABLE"
    assert tracked.close_count == 1


def test_invalid_opened_source_is_closed_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="invalid-opened-source")
    claimed, _now = _claim(repository, source, parent)

    class InvalidSource:
        version_id = source.source_version_id
        close_count = 0

        def close(self) -> None:
            self.close_count += 1

    invalid = InvalidSource()
    monkeypatch.setattr(repository, "open_job_capture", lambda _source_id: invalid)
    with pytest.raises(PostingIndexPermanentError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == "POSTING_SOURCE_INVALID"
    assert invalid.close_count == 1


def test_malformed_live_open_tuple_is_rejected_without_closing_the_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    save_live_source(repository, live_pcap())
    assert build_live_parent(repository)
    source = repository.get_live_capture_source_version("segment-1")
    assert source is not None
    binding = SourceIndexBinding(
        "LIVE_SEGMENT",
        source.source_id,
        source.source_version_id,
        source.source_size_bytes,
        source.source_sha256,
        "PCAP",
    )
    parent = repository.get_structural_index(binding).snapshot
    assert parent is not None
    claimed, _now = _claim(repository, source, parent)

    class MalformedTuple(tuple[object, ...]):
        close_count = 0

        def close(self) -> None:
            self.close_count += 1

    malformed = MalformedTuple(({},))
    monkeypatch.setattr(repository, "open_sensor_pcap", lambda _source_id: malformed)
    with pytest.raises(PostingIndexPermanentError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == "POSTING_SOURCE_INVALID"
    assert malformed.close_count == 0


def test_live_open_with_invalid_metadata_closes_only_the_capture_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    save_live_source(repository, live_pcap())
    assert build_live_parent(repository)
    source = repository.get_live_capture_source_version("segment-1")
    assert source is not None
    binding = SourceIndexBinding(
        "LIVE_SEGMENT",
        source.source_id,
        source.source_version_id,
        source.source_size_bytes,
        source.source_sha256,
        "PCAP",
    )
    parent = repository.get_structural_index(binding).snapshot
    assert parent is not None
    claimed, _now = _claim(repository, source, parent)
    opened = repository.open_sensor_pcap(source.source_id)
    assert opened is not None
    tracked = _TrackingSource(opened[1])
    monkeypatch.setattr(repository, "open_sensor_pcap", lambda _source_id: ([], tracked))
    with pytest.raises(PostingIndexPermanentError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == "POSTING_SOURCE_INVALID"
    assert tracked.close_count == 1


def test_source_open_occurs_after_repository_lock_is_released(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="open-unlocked")
    claimed, _now = _claim(repository, source, parent)
    original_open = repository.open_job_capture
    observed = False

    def open_unlocked(source_id: str) -> Any:
        nonlocal observed
        assert not repository._lock._is_owned()  # type: ignore[attr-defined]
        observed = True
        return original_open(source_id)

    monkeypatch.setattr(repository, "open_job_capture", open_unlocked)
    assert _operation(
        create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
        repository,
        claimed,
    )()
    assert observed


def test_source_deleted_during_publication_is_permanent_stale_and_closes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="delete-at-publication")
    claimed, _now = _claim(repository, source, parent)
    original_open = repository.open_job_capture
    original_publish = repository.publish_posting_index
    tracked: _TrackingSource | None = None

    def open_tracked(source_id: str) -> _TrackingSource:
        nonlocal tracked
        opened = original_open(source_id)
        assert opened is not None
        tracked = _TrackingSource(opened)
        return tracked

    def publish_after_delete(*args: Any, **kwargs: Any) -> bool:
        assert repository.delete_retained_source(source.source_id)
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(repository, "open_job_capture", open_tracked)
    monkeypatch.setattr(repository, "publish_posting_index", publish_after_delete)
    with pytest.raises(PostingIndexPermanentError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == "POSTING_PUBLICATION_REJECTED"
    assert tracked is not None and tracked.close_count == 1


@pytest.mark.parametrize(("attempt_delta", "token"), [(1, "lease-1"), (0, "other-token")])
def test_operation_rejects_non_exact_claim_before_metadata_or_source_io(
    attempt_delta: int, token: str
) -> None:
    class Repository:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"repository I/O for stale operation claim: {name}")

    claimed = worker_task()
    operation = create_posting_operation_builder(_settings(), monotonic=lambda: 0.0)(
        Repository(),  # type: ignore[arg-type]
        task=claimed,
        attempt=claimed.attempt + attempt_delta,
        lease_token=token,
        deadline=10.0,
        should_cancel=lambda: False,
    )
    with pytest.raises(PostingIndexPermanentError) as raised:
        operation()
    assert raised.value.code == "POSTING_TASK_STALE"


def test_deadline_midscan_is_transient_and_closes_source_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="deadline-midscan")
    claimed, _now = _claim(repository, source, parent)
    original = repository.open_job_capture(source.source_id)
    assert original is not None
    tracked = _TrackingSource(original)
    monkeypatch.setattr(repository, "open_job_capture", lambda _source_id: tracked)
    calls = 0

    def monotonic() -> float:
        nonlocal calls
        calls += 1
        return 11.0 if calls >= 5 else 0.0

    with pytest.raises(PostingIndexTransientError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=monotonic),
            repository,
            claimed,
            deadline=10.0,
        )()
    assert raised.value.code == "POSTING_BUILD_CANCELLED"
    assert calls >= 5
    assert tracked.close_count == 1


def test_staging_backend_failure_is_transient_and_source_closes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    source, parent, _first, _second = _prepare(repository, source_id="staging-failure")
    claimed, _now = _claim(repository, source, parent)
    original = repository.open_job_capture(source.source_id)
    assert original is not None
    tracked = _TrackingSource(original)
    monkeypatch.setattr(repository, "open_job_capture", lambda _source_id: tracked)
    monkeypatch.setattr(
        repository,
        "begin_posting_index",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("raw database row")),
    )

    with pytest.raises(PostingIndexTransientError) as raised:
        _operation(
            create_posting_operation_builder(_settings(), monotonic=lambda: 0.0),
            repository,
            claimed,
        )()
    assert raised.value.code == "POSTING_STAGING_UNAVAILABLE"
    assert tracked.close_count == 1
