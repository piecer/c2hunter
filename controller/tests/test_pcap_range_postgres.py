from __future__ import annotations

import threading
from typing import Any

import pytest

from c2hunter_controller.pcap_indexed_export import (
    CaptureByteRange,
    CaptureRangeMissing,
    CaptureRangeShortRead,
    CaptureRangeUnavailable,
    CaptureRangeVersionDrift,
)
from c2hunter_controller.pcap_offset_index import CaptureSourceVersion
from c2hunter_controller.production import MinioBlobStore, PostgresRepository


class Response:
    def __init__(
        self,
        content: bytes,
        *,
        status: int | None = 206,
        headers: dict[str, str] | None = None,
        max_chunk: int | None = None,
        read_error: Exception | None = None,
        close_error: Exception | None = None,
        release_error: Exception | None = None,
    ) -> None:
        self.content = content
        self.status = status
        self.headers = (
            headers
            if headers is not None
            else {
                "content-range": "bytes 2-4/10",
                "content-length": str(len(content)),
                "x-amz-version-id": "version",
            }
        )
        self.max_chunk = max_chunk
        self.read_error = read_error
        self.close_error = close_error
        self.release_error = release_error
        self.read_sizes: list[int] = []
        self.closed = 0
        self.released = 0

    def read(self, size: int) -> bytes:
        assert isinstance(size, int) and size > 0
        self.read_sizes.append(size)
        if self.read_error is not None:
            raise self.read_error
        actual = min(size, self.max_chunk) if self.max_chunk is not None else size
        chunk, self.content = self.content[:actual], self.content[actual:]
        return chunk

    def close(self) -> None:
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error

    def release_conn(self) -> None:
        self.released += 1
        if self.release_error is not None:
            raise self.release_error


class Client:
    def __init__(self, response: Response | None = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def get_object(self, *args: Any, **kwargs: Any) -> Response:
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response


def _store(client: Client) -> MinioBlobStore:
    store = MinioBlobStore.__new__(MinioBlobStore)
    store.client = client
    store.bucket = "bucket"
    return store


def _version_response(content: bytes, offset: int, total: int = 10, **kwargs: Any) -> Response:
    headers = {
        "content-range": f"bytes {offset}-{offset + len(content) - 1}/{total}",
        "content-length": str(len(content)),
        "x-amz-version-id": "version",
    }
    return Response(content, headers=headers, **kwargs)


@pytest.mark.parametrize(
    ("offset", "content"),
    [(0, b"01"), (4, b"456"), (9, b"9")],
)
def test_minio_exact_first_middle_last_ranges(offset: int, content: bytes) -> None:
    response = _version_response(content, offset)
    client = Client(response)
    assert (
        _store(client).read_range(
            "captures/s.pcap",
            expected_version_id="s3-version:version",
            expected_size=10,
            offset=offset,
            length=len(content),
        )
        == content
    )
    assert client.calls == [
        (
            ("bucket", "captures/s.pcap"),
            {"offset": offset, "length": len(content), "version_id": "version"},
        )
    ]
    assert response.read_sizes == [len(content)]
    assert (response.closed, response.released) == (1, 1)


@pytest.mark.parametrize(
    "content_range",
    ["bytes 2-4/9", "bytes 2-4/11", "bytes 2-4/*"],
)
def test_minio_rejects_content_range_total_that_is_not_authoritative_size(
    content_range: str,
) -> None:
    response = Response(
        b"cde",
        headers={
            "content-range": content_range,
            "content-length": "3",
            "x-amz-version-id": "version",
        },
    )

    with pytest.raises(CaptureRangeShortRead, match="content range mismatch"):
        _store(Client(response)).read_range(
            "key",
            expected_version_id="s3-version:version",
            expected_size=10,
            offset=2,
            length=3,
        )
    assert (response.closed, response.released) == (1, 1)


@pytest.mark.parametrize("expected_size", [-1, True, 0, 4])
def test_minio_rejects_invalid_size_or_out_of_bounds_range_before_provider_io(
    expected_size: int,
) -> None:
    client = Client(_version_response(b"cde", 2))

    with pytest.raises(ValueError):
        _store(client).read_range(
            "key",
            expected_version_id="s3-version:version",
            expected_size=expected_size,
            offset=2,
            length=3,
        )
    assert client.calls == []


def test_minio_short_fragmented_reads_are_positive_and_bounded() -> None:
    response = _version_response(b"cdefg", 2, max_chunk=2)
    assert (
        _store(Client(response)).read_range(
            "key", expected_version_id="s3-version:version", expected_size=10, offset=2, length=5
        )
        == b"cdefg"
    )
    assert response.read_sizes == [5, 3, 1]
    assert all(size > 0 for size in response.read_sizes)


def test_minio_etag_uses_if_match_and_verifies_exact_response_identity() -> None:
    response = Response(
        b"cde",
        headers={
            "content-range": "bytes 2-4/10",
            "content-length": "3",
            "etag": '"abc"',
        },
    )
    client = Client(response)
    assert (
        _store(client).read_range(
            "key", expected_version_id="etag:abc", expected_size=10, offset=2, length=3
        )
        == b"cde"
    )
    assert client.calls[0][1] == {
        "offset": 2,
        "length": 3,
        "request_headers": {"If-Match": '"abc"'},
    }


@pytest.mark.parametrize(
    ("expected_version", "headers"),
    [
        (
            "s3-version:version",
            {
                "content-range": "bytes 2-4/10",
                "content-length": "3",
                "x-amz-version-id": "other",
            },
        ),
        (
            "etag:abc",
            {
                "content-range": "bytes 2-4/10",
                "content-length": "3",
                "etag": '"other"',
            },
        ),
    ],
)
def test_minio_rejects_response_version_or_etag_drift(
    expected_version: str, headers: dict[str, str]
) -> None:
    response = Response(b"cde", headers=headers)
    with pytest.raises(CaptureRangeVersionDrift):
        _store(Client(response)).read_range(
            "key", expected_version_id=expected_version, expected_size=10, offset=2, length=3
        )
    assert (response.closed, response.released) == (1, 1)


@pytest.mark.parametrize(
    "response",
    [
        Response(b"0123456789", status=200, headers={"content-length": "10"}),
        Response(
            b"cde",
            headers={"content-length": "3", "x-amz-version-id": "version"},
        ),
        Response(
            b"cde",
            headers={
                "content-range": "garbage",
                "content-length": "3",
                "x-amz-version-id": "version",
            },
        ),
        Response(
            b"cde",
            headers={"content-range": "bytes 2-4/10", "x-amz-version-id": "version"},
        ),
        Response(
            b"cde",
            headers={
                "content-range": "bytes 2-4/10",
                "content-length": "2",
                "x-amz-version-id": "version",
            },
        ),
        Response(
            b"cde",
            headers={"content-range": "bytes 2-4/10", "content-length": "3"},
        ),
    ],
)
def test_minio_rejects_ignored_range_and_missing_malformed_or_mismatched_headers(
    response: Response,
) -> None:
    with pytest.raises((CaptureRangeShortRead, CaptureRangeVersionDrift)):
        _store(Client(response)).read_range(
            "key", expected_version_id="s3-version:version", expected_size=10, offset=2, length=3
        )
    assert (response.closed, response.released) == (1, 1)


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (
            Response(
                b"cd",
                headers={
                    "content-range": "bytes 2-4/10",
                    "content-length": "3",
                    "x-amz-version-id": "version",
                },
            ),
            CaptureRangeShortRead,
        ),
        (_version_response(b"cde", 2, status=404), CaptureRangeMissing),
        (_version_response(b"cde", 2, status=412), CaptureRangeVersionDrift),
        (_version_response(b"cde", 2, status=503), CaptureRangeUnavailable),
        (
            _version_response(b"cde", 2, read_error=TimeoutError("read timeout")),
            CaptureRangeUnavailable,
        ),
    ],
)
def test_minio_maps_status_short_read_and_timeout_and_releases(
    response: Response, error: type[Exception]
) -> None:
    with pytest.raises(error):
        _store(Client(response)).read_range(
            "key", expected_version_id="s3-version:version", expected_size=10, offset=2, length=3
        )
    assert (response.closed, response.released) == (1, 1)


@pytest.mark.parametrize(
    ("code", "error"),
    [
        ("NoSuchKey", CaptureRangeMissing),
        ("NoSuchVersion", CaptureRangeMissing),
        ("PreconditionFailed", CaptureRangeVersionDrift),
        ("InternalError", CaptureRangeUnavailable),
    ],
)
def test_minio_maps_open_failures(code: str, error: type[Exception]) -> None:
    exc = RuntimeError(code)
    exc.code = code  # type: ignore[attr-defined]
    with pytest.raises(error):
        _store(Client(error=exc)).read_range(
            "key", expected_version_id="s3-version:version", expected_size=10, offset=2, length=3
        )


def test_minio_cleanup_exceptions_preserve_primary_and_attempt_each_once() -> None:
    response = Response(
        b"cd",
        headers={
            "content-range": "bytes 2-4/10",
            "content-length": "3",
            "x-amz-version-id": "version",
        },
        close_error=RuntimeError("close"),
        release_error=RuntimeError("release"),
    )
    with pytest.raises(CaptureRangeShortRead, match="ended early"):
        _store(Client(response)).read_range(
            "key", expected_version_id="s3-version:version", expected_size=10, offset=2, length=3
        )
    assert (response.closed, response.released) == (1, 1)


class Cursor:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def execute(self, statement: str, parameters: tuple[Any, ...]) -> None:
        self.connection.queries.append((statement, parameters))

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.connection.rows.pop(0)


class Connection:
    closed = False

    def __init__(self, rows: list[tuple[Any, ...] | None]) -> None:
        self.rows = list(rows)
        self.queries: list[tuple[str, tuple[Any, ...]]] = []
        self.commits = 0
        self.rollbacks = 0

    def cursor(self) -> Cursor:
        return Cursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class RangeBlob:
    def __init__(self, connection: Connection, result: bytes = b"cd") -> None:
        self.connection = connection
        self.result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.repository: PostgresRepository | None = None

    def read_range(self, key: str, **kwargs: Any) -> bytes:
        # The authoritative precheck transaction must be complete before provider I/O.
        assert self.connection.commits == 1
        repository = self.repository
        assert repository is not None
        acquired: list[bool] = []

        def probe_repository_lock() -> None:
            lock_acquired = repository._lock.acquire(blocking=False)
            acquired.append(lock_acquired)
            if lock_acquired:
                repository._lock.release()

        probe = threading.Thread(target=probe_repository_lock)
        probe.start()
        probe.join(timeout=1)
        assert not probe.is_alive() and acquired == [True]
        self.calls.append((key, kwargs))
        return self.result


def _repository(connection: Connection, blob: RangeBlob) -> PostgresRepository:
    repository = PostgresRepository("unused", blob)  # type: ignore[arg-type]
    repository._connection = connection
    blob.repository = repository
    return repository


def test_postgres_reads_authoritative_key_after_commit_then_rechecks_after_io() -> None:
    row = ("PCAP_UPLOAD", "s", "authoritative", "s3-version:v", 10, "a" * 64)
    connection = Connection([row, row])
    blob = RangeBlob(connection)
    source = CaptureSourceVersion(*row)

    assert _repository(connection, blob).read_capture_range(source, CaptureByteRange(2, 2)) == b"cd"
    assert blob.calls == [
        (
            "authoritative",
            {
                "expected_version_id": "s3-version:v",
                "expected_size": 10,
                "offset": 2,
                "length": 2,
            },
        )
    ]
    assert connection.commits == 2
    assert len(connection.queries) == 2


def test_postgres_rejects_arbitrary_caller_key_before_provider_io() -> None:
    row = ("PCAP_UPLOAD", "s", "authoritative", "s3-version:v", 10, "a" * 64)
    connection = Connection([row])
    blob = RangeBlob(connection)
    caller = CaptureSourceVersion("PCAP_UPLOAD", "s", "caller-key", "s3-version:v", 10, "a" * 64)
    with pytest.raises(CaptureRangeVersionDrift):
        _repository(connection, blob).read_capture_range(caller, CaptureByteRange(2, 2))
    assert blob.calls == []


@pytest.mark.parametrize(
    ("after", "error"),
    [
        (None, CaptureRangeMissing),
        (
            ("LIVE_SEGMENT", "s", "other", "etag:x", 10, "b" * 64),
            CaptureRangeVersionDrift,
        ),
    ],
)
def test_postgres_post_io_deletion_or_replacement_invalidates_result(
    after: tuple[Any, ...] | None, error: type[Exception]
) -> None:
    row = ("LIVE_SEGMENT", "s", "canonical", "etag:v", 10, "a" * 64)
    connection = Connection([row, after])
    blob = RangeBlob(connection)
    with pytest.raises(error):
        _repository(connection, blob).read_capture_range(
            CaptureSourceVersion(*row), CaptureByteRange(2, 2)
        )
    assert len(blob.calls) == 1
