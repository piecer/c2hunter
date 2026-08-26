from __future__ import annotations

import hashlib
from collections.abc import Callable

import pytest

from c2hunter_controller.pcap_indexed_export import (
    CaptureByteRange,
    CaptureRangeMissing,
    CaptureRangeShortRead,
    CaptureRangeVersionDrift,
)
from c2hunter_controller.pcap_offset_index import CaptureSourceVersion
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository

RepositoryFactory = Callable[[], MemoryRepository | SQLiteRepository]
FACTORIES: tuple[RepositoryFactory, ...] = (MemoryRepository, lambda: SQLiteRepository(":memory:"))


@pytest.mark.parametrize("repository_factory", FACTORIES)
def test_upload_exact_first_middle_last_ranges(repository_factory: RepositoryFactory) -> None:
    repository = repository_factory()
    content = b"0123456789"
    repository.save_job_capture("job", content)
    source = repository.get_capture_source_version("job")
    assert source is not None
    statements: list[str] = []
    if isinstance(repository, SQLiteRepository):
        repository.connection.set_trace_callback(statements.append)
    try:
        assert repository.read_capture_range(source, CaptureByteRange(0, 2)) == b"01"
        assert repository.read_capture_range(source, CaptureByteRange(4, 3)) == b"456"
        assert repository.read_capture_range(source, CaptureByteRange(9, 1)) == b"9"
        if isinstance(repository, SQLiteRepository):
            content_queries = [
                statement for statement in statements if "CONTENT" in statement.upper()
            ]
            assert content_queries
            assert all("SUBSTR(CONTENT" in statement.upper() for statement in content_queries)
            expected_calls = (
                "SUBSTR(CONTENT, 1, 2)",
                "SUBSTR(CONTENT, 5, 3)",
                "SUBSTR(CONTENT, 10, 1)",
            )
            assert all(
                any(expected in statement.upper() for statement in content_queries)
                for expected in expected_calls
            )
    finally:
        repository.close()


@pytest.mark.parametrize("repository_factory", FACTORIES)
def test_range_requires_exact_authoritative_identity_and_never_trusts_caller_key(
    repository_factory: RepositoryFactory,
) -> None:
    repository = repository_factory()
    repository.save_job_capture("job", b"abcdef")
    source = repository.get_capture_source_version("job")
    assert source is not None
    try:
        with pytest.raises(ValueError):
            repository.read_capture_range(source, CaptureByteRange(5, 2))
        for changed in (
            CaptureSourceVersion(
                source.source_kind,
                source.source_id,
                "caller/chosen/object",
                source.source_version_id,
                source.source_size_bytes,
                source.source_sha256,
            ),
            CaptureSourceVersion(
                source.source_kind,
                source.source_id,
                source.object_key,
                "stale",
                source.source_size_bytes,
                source.source_sha256,
            ),
        ):
            with pytest.raises(CaptureRangeVersionDrift):
                repository.read_capture_range(changed, CaptureByteRange(0, 1))
        with pytest.raises(CaptureRangeMissing):
            repository.read_capture_range(
                CaptureSourceVersion(
                    source.source_kind,
                    "missing",
                    "captures/missing.pcap",
                    "v",
                    1,
                    hashlib.sha256(b"x").hexdigest(),
                ),
                CaptureByteRange(0, 1),
            )
    finally:
        repository.close()


@pytest.mark.parametrize("repository_factory", FACTORIES)
def test_range_short_read_remains_distinct_after_authoritative_precheck(
    repository_factory: RepositoryFactory,
) -> None:
    repository = repository_factory()
    repository.save_job_capture("job", b"abcdef")
    source = repository.get_capture_source_version("job")
    assert source is not None
    try:
        if isinstance(repository, MemoryRepository):
            repository.job_captures["job"] = b"a"
        else:
            repository.connection.execute(
                "UPDATE job_capture_blobs SET content=? WHERE job_id=?", (b"a", "job")
            )
            repository.connection.commit()
        with pytest.raises(CaptureRangeShortRead):
            repository.read_capture_range(source, CaptureByteRange(0, 2))
    finally:
        repository.close()


@pytest.mark.parametrize("repository_factory", FACTORIES)
def test_live_exact_first_middle_last_ranges(repository_factory: RepositoryFactory) -> None:
    repository = repository_factory()
    content = b"0123456789"
    source = CaptureSourceVersion(
        "LIVE_SEGMENT",
        "segment",
        "sensor-pcaps/sensor/segment/generation.pcap",
        "etag:live",
        len(content),
        hashlib.sha256(content).hexdigest(),
    )
    if isinstance(repository, MemoryRepository):
        repository.sensor_pcap_content["segment"] = content
        repository.capture_source_versions["LIVE_SEGMENT:segment"] = source
    else:
        repository.connection.execute(
            "INSERT INTO sensor_pcap_blobs(segment_id,content) VALUES(?,?)",
            ("segment", content),
        )
        repository.connection.execute(
            "INSERT INTO pcap_capture_source_versions("
            "source_kind,source_id,object_key,source_version_id,source_size_bytes,source_sha256"
            ") VALUES(?,?,?,?,?,?)",
            (
                source.source_kind,
                source.source_id,
                source.object_key,
                source.source_version_id,
                source.source_size_bytes,
                source.source_sha256,
            ),
        )
        repository.connection.commit()
    try:
        assert repository.read_capture_range(source, CaptureByteRange(0, 2)) == b"01"
        assert repository.read_capture_range(source, CaptureByteRange(4, 3)) == b"456"
        assert repository.read_capture_range(source, CaptureByteRange(9, 1)) == b"9"
    finally:
        repository.close()


def test_memory_post_read_identity_recheck_rejects_replacement() -> None:
    repository = MemoryRepository()
    repository.save_job_capture("job", b"abcdef")
    source = repository.get_capture_source_version("job")
    assert source is not None
    original_lock = repository._lock

    class ReplacingLock:
        enters = 0

        def __enter__(self) -> None:
            self.enters += 1
            if self.enters == 2:
                repository.capture_source_versions["job"] = CaptureSourceVersion(
                    source.source_kind,
                    source.source_id,
                    source.object_key,
                    "replacement",
                    source.source_size_bytes,
                    source.source_sha256,
                )

        def __exit__(self, *_args: object) -> None:
            return None

    repository._lock = ReplacingLock()  # type: ignore[assignment]
    try:
        with pytest.raises(CaptureRangeVersionDrift):
            repository.read_capture_range(source, CaptureByteRange(0, 2))
    finally:
        repository._lock = original_lock
        repository.close()


def test_capture_byte_range_validation_and_overflow() -> None:
    for offset, length in (
        (-1, 1),
        (0, 0),
        (0, -1),
        ((1 << 63) - 1, 1),
        (True, 1),
        (0, True),
    ):
        with pytest.raises(ValueError):
            CaptureByteRange(offset, length)
