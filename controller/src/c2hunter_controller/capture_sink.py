from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Iterator
from types import TracebackType
from typing import BinaryIO, Self, cast


class CaptureLimitTooSmall(ValueError):
    """The hard output cap cannot hold the required capture header."""


class CaptureStorageError(RuntimeError):
    """Temporary capture storage failed without exposing host details."""


class CaptureRecordError(ValueError):
    """A matched packet record violates the capture-writer contract."""


_STORAGE_MESSAGE = "capture temporary storage operation failed"


def _storage_error(exc: OSError) -> CaptureStorageError:
    return CaptureStorageError(_STORAGE_MESSAGE)


class CaptureSink:
    """Hard-capped, unit-atomic output backed by a spooled temporary file."""

    def __init__(
        self,
        *,
        max_output_bytes: int,
        spool_max_memory_bytes: int,
        spool_directory: str | None = None,
    ) -> None:
        if max_output_bytes < 0:
            raise ValueError("max_output_bytes must be non-negative")
        if spool_max_memory_bytes <= 0:
            raise ValueError("spool_max_memory_bytes must be positive")
        self.max_output_bytes = max_output_bytes
        self._size = 0
        self._hash = hashlib.sha256()
        self._closed = False
        try:
            self._spool = cast(
                BinaryIO,
                tempfile.SpooledTemporaryFile(
                    max_size=spool_max_memory_bytes,
                    mode="w+b",
                    dir=spool_directory,
                ),
            )
        except OSError as exc:
            raise _storage_error(exc) from exc

    @property
    def size_bytes(self) -> int:
        return self._size

    @property
    def sha256(self) -> str:
        return self._hash.hexdigest()

    @property
    def rolled(self) -> bool:
        return bool(getattr(self._spool, "_rolled", False))

    def write_unit(self, *parts: bytes) -> bool:
        self._ensure_open()
        unit = b"".join(parts)
        if self._size + len(unit) > self.max_output_bytes:
            return False
        try:
            written = self._spool.write(unit)
        except OSError as exc:
            raise _storage_error(exc) from exc
        if written != len(unit):
            raise CaptureStorageError(_STORAGE_MESSAGE)
        self._size += written
        self._hash.update(unit)
        return True

    def rewind(self) -> None:
        self._ensure_open()
        try:
            self._spool.flush()
            self._spool.seek(0)
        except OSError as exc:
            raise _storage_error(exc) from exc

    def read_bytes(self) -> bytes:
        self.rewind()
        try:
            content = self._spool.read()
        except OSError as exc:
            raise _storage_error(exc) from exc
        if len(content) != self._size:
            raise CaptureStorageError(_STORAGE_MESSAGE)
        return content

    def detach(self) -> BinaryIO:
        self.rewind()
        self._closed = True
        return self._spool

    def _ensure_open(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed capture sink")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._spool.close()
        except OSError as exc:
            raise _storage_error(exc) from exc


class CaptureArtifact:
    """Owns a completed rewound capture spool and its immutable accounting."""

    def __init__(
        self,
        spool: BinaryIO,
        *,
        capture_format: str,
        size_bytes: int,
        sha256: str,
        matched_packet_count: int,
        exported_packet_count: int,
    ) -> None:
        self._spool = spool
        self._closed = False
        self._consumed = False
        self._iterating = False
        self.capture_format = capture_format
        self.size_bytes = size_bytes
        self.sha256 = sha256
        self.matched_packet_count = matched_packet_count
        self.exported_packet_count = exported_packet_count
        self.omitted_packet_count = matched_packet_count - exported_packet_count
        self.truncated = self.omitted_packet_count > 0
        self.truncation_reasons = ("OUTPUT_BYTE_LIMIT",) if self.truncated else ()

    def _ensure_open(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed capture artifact")

    @property
    def rolled(self) -> bool:
        self._ensure_open()
        return bool(getattr(self._spool, "_rolled", False))

    def iter_chunks(self, chunk_size: int = 64 * 1024) -> Iterator[bytes]:
        self._ensure_open()
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if self._iterating:
            raise RuntimeError("capture artifact is already being consumed")
        if self._consumed:
            raise RuntimeError("capture artifact has already been consumed")
        self._consumed = True
        self._iterating = True
        emitted_size = 0
        emitted_hash = hashlib.sha256()
        try:
            self._spool.seek(0)
            while chunk := self._spool.read(chunk_size):
                if type(chunk) is not bytes:
                    raise CaptureStorageError(_STORAGE_MESSAGE)
                emitted_size += len(chunk)
                emitted_hash.update(chunk)
                yield chunk
            if emitted_size != self.size_bytes or emitted_hash.hexdigest() != self.sha256:
                raise CaptureStorageError(_STORAGE_MESSAGE)
        except OSError as exc:
            raise _storage_error(exc) from exc
        finally:
            self._iterating = False

    def read_bytes(self) -> bytes:
        content = b"".join(self.iter_chunks())
        if len(content) != self.size_bytes or hashlib.sha256(content).hexdigest() != self.sha256:
            raise CaptureStorageError(_STORAGE_MESSAGE)
        return content

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._spool.close()
        except OSError as exc:
            raise _storage_error(exc) from exc

    def __enter__(self) -> Self:
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc is None:
            self.close()
            return
        try:
            self.close()
        except CaptureStorageError:
            # Cleanup failure must never replace the operation's primary exception.
            pass
