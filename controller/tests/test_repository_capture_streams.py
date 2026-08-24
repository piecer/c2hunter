from __future__ import annotations

import hashlib
import io
import threading
from typing import Any

import pytest

from c2hunter_controller.repositories import CaptureSource, MemoryRepository, SQLiteRepository


@pytest.fixture(params=["memory", "sqlite"])
def repository(request: pytest.FixtureRequest, tmp_path: Any) -> Any:
    if request.param == "memory":
        return MemoryRepository()
    repo = SQLiteRepository(tmp_path / "repository.db")
    request.addfinalizer(repo.close)
    return repo


def test_capture_source_close_keeps_close_error_primary_and_releases_once() -> None:
    calls: list[str] = []

    class FailingCloseStream(io.BytesIO):
        def close(self) -> None:
            calls.append("close")
            raise RuntimeError("close failed")

    def fail_release() -> None:
        calls.append("release")
        raise RuntimeError("release failed")

    source = CaptureSource(FailingCloseStream(b"payload"), "version", release_conn=fail_release)

    with pytest.raises(RuntimeError, match="close failed"):
        source.close()

    assert source.closed is True
    assert calls == ["close", "release"]
    source.close()
    assert calls == ["close", "release"]


def test_capture_source_rejects_non_bytes_read_result() -> None:
    class MalformedStream:
        def read(self, size: int | None = -1) -> Any:
            return bytearray(b"not-bytes")

        def close(self) -> None:
            pass

    source = CaptureSource(MalformedStream(), "version")
    with pytest.raises(TypeError, match="bytes"):
        source.read(1)
    source.close()


def test_capture_source_default_and_non_positive_reads_use_one_bounded_chunk() -> None:
    class PositiveSizeOnlyStream(io.BytesIO):
        def __init__(self, content: bytes) -> None:
            super().__init__(content)
            self.read_sizes: list[int] = []

        def read(self, size: int | None = -1) -> bytes:
            if size is None or size <= 0:
                raise AssertionError(f"underlying read must be positive, got {size!r}")
            self.read_sizes.append(size)
            return super().read(size)

    content = b"a" * (64 * 1024 + 1)
    for requested_size in (-1, 0, None):
        stream = PositiveSizeOnlyStream(content)
        source = CaptureSource(stream, "version")

        chunk = source.read(requested_size)

        assert chunk == content[: 64 * 1024]
        assert stream.read_sizes == [64 * 1024]
        source.close()

    stream = PositiveSizeOnlyStream(content)
    source = CaptureSource(stream, "version")
    assert source.read() == content[: 64 * 1024]
    assert stream.read_sizes == [64 * 1024]
    assert source.read(1) == b"a"
    assert stream.read_sizes == [64 * 1024, 1]
    assert source.read(1) == b""
    assert stream.read_sizes == [64 * 1024, 1, 1]
    source.close()


def test_capture_source_identity_and_closed_are_read_only() -> None:
    source = CaptureSource(io.BytesIO(b"payload"), "version")

    for attribute, value in (("version_id", "changed"), ("closed", True)):
        with pytest.raises(AttributeError):
            setattr(source, attribute, value)

    assert source.version_id == "version"
    assert source.closed is False
    source.close()


def test_sqlite_open_and_close_are_serialized_and_source_is_detached(tmp_path: Any) -> None:
    repository = SQLiteRepository(tmp_path / "serialized.db")
    repository.save_job_capture("job-a", b"detached payload")
    open_holds_lock = threading.Event()
    allow_open = threading.Event()
    close_finished = threading.Event()
    opened: list[CaptureSource | None] = []
    errors: list[BaseException] = []
    base_lock = threading.RLock()

    class GatedLock:
        def __enter__(self) -> None:
            base_lock.acquire()
            if threading.current_thread().name == "capture-open":
                open_holds_lock.set()
                allow_open.wait(timeout=2)

        def __exit__(self, *_args: object) -> None:
            base_lock.release()

    repository._lock = GatedLock()  # type: ignore[assignment]

    def run_open() -> None:
        try:
            opened.append(repository.open_job_capture("job-a"))
        except BaseException as exc:
            errors.append(exc)

    def run_close() -> None:
        try:
            repository.close()
        except BaseException as exc:
            errors.append(exc)
        finally:
            close_finished.set()

    open_thread = threading.Thread(target=run_open, name="capture-open")
    close_thread = threading.Thread(target=run_close, name="repository-close")
    open_thread.start()
    assert open_holds_lock.wait(timeout=1)
    close_thread.start()
    try:
        assert not close_finished.wait(timeout=0.1)
    finally:
        allow_open.set()
        open_thread.join(timeout=2)
        close_thread.join(timeout=2)

    assert not errors
    assert len(opened) == 1 and opened[0] is not None
    source = opened[0]
    assert source is not None
    with source:
        assert source.read() == b"detached payload"


def test_open_job_capture_streams_uneven_chunks_and_closes(repository: Any) -> None:
    repository.save_job_capture("job-a", b"abcdefghij")

    source = repository.open_job_capture("job-a")

    assert source is not None
    assert list(source.iter_chunks(3)) == [b"abc", b"def", b"ghi", b"j"]
    assert source.read(1) == b""
    assert source.closed is False
    source.close()
    source.close()
    assert source.closed is True
    with pytest.raises(ValueError):
        source.read(1)


def test_open_source_rejects_non_positive_chunk_size_without_consuming(repository: Any) -> None:
    repository.save_job_capture("job-a", b"abc")
    source = repository.open_job_capture("job-a")
    assert source is not None

    with pytest.raises(ValueError):
        list(source.iter_chunks(0))
    with pytest.raises(ValueError):
        list(source.iter_chunks(-1))
    assert source.read() == b"abc"
    source.close()


def test_empty_capture_is_present_not_missing(repository: Any) -> None:
    repository.save_job_capture("empty", b"")

    source = repository.open_job_capture("empty")

    assert source is not None
    with source:
        assert list(source.iter_chunks(2)) == []
    assert repository.get_job_capture("empty") == b""
    assert repository.open_job_capture("missing") is None


def test_opened_job_source_is_an_immutable_snapshot(repository: Any) -> None:
    repository.save_job_capture("job-a", b"version-a")
    first = repository.open_job_capture("job-a")
    assert first is not None
    first_version = first.version_id

    repository.save_job_capture("job-a", b"version-b")
    second = repository.open_job_capture("job-a")
    assert second is not None

    if isinstance(repository, SQLiteRepository):
        repository.close()
    with first, second:
        assert b"".join(first.iter_chunks(2)) == b"version-a"
        assert b"".join(second.iter_chunks(3)) == b"version-b"
        assert first_version == "sha256:" + hashlib.sha256(b"version-a").hexdigest()
        assert second.version_id == "sha256:" + hashlib.sha256(b"version-b").hexdigest()
        assert first.version_id != second.version_id
        with pytest.raises(AttributeError):
            first.version_id = "changed"


def _segment(segment_id: str, content: bytes, marker: str) -> dict[str, Any]:
    return {
        "id": segment_id,
        "sensor_id": "sensor-a",
        "analysis_job_id": None,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "marker": {"value": marker},
    }


def test_open_sensor_pcap_snapshots_metadata_and_content_together(repository: Any) -> None:
    content = b"sensor-version-a"
    metadata = _segment("segment-a", content, "a")
    repository.save_sensor_pcap(metadata, content)

    opened = repository.open_sensor_pcap("segment-a")

    assert opened is not None
    opened_metadata, source = opened
    metadata["marker"]["value"] = "mutated"
    if isinstance(repository, MemoryRepository):
        with repository._lock:
            repository.sensor_pcaps["segment-a"]["marker"]["value"] = "overwritten"
            repository.sensor_pcap_content["segment-a"] = b"sensor-version-b"
    with source:
        assert opened_metadata["marker"] == {"value": "a"}
        assert b"".join(source.iter_chunks(4)) == content
    assert repository.open_sensor_pcap("missing") is None


def test_sqlite_open_sensor_pcap_uses_one_lock_held_snapshot(tmp_path: Any) -> None:
    repository = SQLiteRepository(tmp_path / "sensor-snapshot.db")
    content_a = b"sensor-version-a"
    content_b = b"sensor-version-b"
    metadata_a = _segment("segment-a", content_a, "a")
    metadata_b = _segment("segment-a", content_b, "b")
    repository.save_sensor_pcap(metadata_a, content_a)
    open_holds_lock = threading.Event()
    allow_open = threading.Event()
    base_lock = threading.RLock()
    opened: list[tuple[dict[str, Any], CaptureSource] | None] = []
    errors: list[BaseException] = []
    traced: list[str] = []
    repository.connection.set_trace_callback(traced.append)

    class GatedLock:
        def __enter__(self) -> None:
            base_lock.acquire()
            if threading.current_thread().name == "sensor-open":
                open_holds_lock.set()
                allow_open.wait(timeout=2)

        def __exit__(self, *_args: object) -> None:
            base_lock.release()

    repository._lock = GatedLock()  # type: ignore[assignment]

    def run_open() -> None:
        try:
            opened.append(repository.open_sensor_pcap("segment-a"))
        except BaseException as exc:
            errors.append(exc)

    def overwrite() -> None:
        try:
            with repository._lock:
                repository.connection.execute(
                    "UPDATE objects SET data=? WHERE kind='sensor_pcap' AND id=?",
                    (repository._serialize(metadata_b), "segment-a"),
                )
                repository.connection.execute(
                    "UPDATE sensor_pcap_blobs SET content=? WHERE segment_id=?",
                    (content_b, "segment-a"),
                )
                repository.connection.commit()
        except BaseException as exc:
            errors.append(exc)

    open_thread = threading.Thread(target=run_open, name="sensor-open")
    writer_thread = threading.Thread(target=overwrite, name="sensor-overwrite")
    open_thread.start()
    assert open_holds_lock.wait(timeout=1)
    writer_thread.start()
    allow_open.set()
    open_thread.join(timeout=2)
    writer_thread.join(timeout=2)

    assert not errors
    assert len(opened) == 1 and opened[0] is not None
    opened_value = opened[0]
    assert opened_value is not None
    opened_metadata, source = opened_value
    with source:
        assert opened_metadata["marker"] == {"value": "a"}
        assert source.read() == content_a
    snapshot_queries = [
        query
        for query in traced
        if query.startswith("SELECT objects.data,sensor_pcap_blobs.content")
    ]
    assert len(snapshot_queries) == 1
    assert "JOIN sensor_pcap_blobs" in snapshot_queries[0]
    current = repository.open_sensor_pcap("segment-a")
    assert current is not None
    current_metadata, current_source = current
    with current_source:
        assert current_metadata["marker"] == {"value": "b"}
        assert current_source.read() == content_b
    repository.close()


def test_incremental_integrity_is_chunk_boundary_independent(repository: Any) -> None:
    content = b"0123456789abcdefghijklmnopqrstuvwxyz"
    repository.save_job_capture("job-a", content)

    for chunk_size in (1, 7, 24, len(content) + 10):
        source = repository.open_job_capture("job-a")
        assert source is not None
        observed_size = 0
        observed_sha = hashlib.sha256()
        with source:
            for chunk in source.iter_chunks(chunk_size):
                observed_size += len(chunk)
                observed_sha.update(chunk)
        assert observed_size == len(content)
        assert observed_sha.hexdigest() == hashlib.sha256(content).hexdigest()


def test_compatibility_get_job_capture_drains_and_closes_on_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()

    class TrackingSource:
        def __init__(self, error: Exception | None = None) -> None:
            self.closed = False
            self.error = error

        def iter_chunks(self, chunk_size: int = 64 * 1024) -> Any:
            yield b"ab"
            if self.error is not None:
                raise self.error
            yield b"cd"

        def close(self) -> None:
            self.closed = True

        def __enter__(self) -> TrackingSource:
            return self

        def __exit__(self, *_args: object) -> None:
            self.close()

    sources = [TrackingSource(), TrackingSource(RuntimeError("read failed"))]
    monkeypatch.setattr(repository, "open_job_capture", lambda _job_id: sources.pop(0))

    first = repository.open_job_capture("unused")
    monkeypatch.setattr(repository, "open_job_capture", lambda _job_id: first)
    assert repository.get_job_capture("job-a") == b"abcd"
    assert first.closed

    second = TrackingSource(RuntimeError("read failed"))
    monkeypatch.setattr(repository, "open_job_capture", lambda _job_id: second)
    with pytest.raises(RuntimeError, match="read failed"):
        repository.get_job_capture("job-a")
    assert second.closed

    class InvalidChunkSource(TrackingSource):
        def iter_chunks(self, chunk_size: int = 64 * 1024) -> Any:
            yield "not-bytes"

    third = InvalidChunkSource()
    monkeypatch.setattr(repository, "open_job_capture", lambda _job_id: third)
    with pytest.raises(TypeError):
        repository.get_job_capture("job-a")
    assert third.closed


def test_compatibility_get_sensor_pcap_closes_on_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    closed: list[str] = []

    class Source:
        def __init__(self, fail: bool = False) -> None:
            self.fail = fail

        def iter_chunks(self, chunk_size: int = 64 * 1024) -> Any:
            yield b"bytes"
            if self.fail:
                raise RuntimeError("read failed")

        def close(self) -> None:
            closed.append("closed")

        def __enter__(self) -> Source:
            return self

        def __exit__(self, *_args: object) -> None:
            self.close()

    monkeypatch.setattr(repository, "open_sensor_pcap", lambda _id: ({"id": "s"}, Source()))
    assert repository.get_sensor_pcap("s") == ({"id": "s"}, b"bytes")
    assert closed == ["closed"]

    monkeypatch.setattr(repository, "open_sensor_pcap", lambda _id: ({"id": "s"}, Source(True)))
    with pytest.raises(RuntimeError, match="read failed"):
        repository.get_sensor_pcap("s")
    assert closed == ["closed", "closed"]

    class InvalidChunkSource(Source):
        def iter_chunks(self, chunk_size: int = 64 * 1024) -> Any:
            yield "not-bytes"

    monkeypatch.setattr(
        repository, "open_sensor_pcap", lambda _id: ({"id": "s"}, InvalidChunkSource())
    )
    with pytest.raises(TypeError):
        repository.get_sensor_pcap("s")
    assert closed == ["closed", "closed", "closed"]
