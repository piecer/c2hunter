"""Controller-local, nonblocking baseline computation ownership.

A lease is prepared before entering storage and acquired only after authoritative
retained replay. The invoking owner closes it after publication/readback, never
an awaiting HTTP task. No callback, queue, executor or global singleton.
"""

from __future__ import annotations

from threading import Lock
from types import TracebackType
from typing import Self, final


@final
class BaselineAdmission:
    def __init__(self) -> None:
        self._lock = Lock()


@final
class BaselineLease:
    def __init__(self, admission: BaselineAdmission | None) -> None:
        if admission is not None and type(admission) is not BaselineAdmission:
            raise TypeError("expected BaselineAdmission")
        self._lock = admission._lock if admission is not None else None
        self._held = False

    def __enter__(self) -> Self:
        return self

    def acquire(self) -> bool:
        if self._held:
            raise RuntimeError("baseline lease already acquired")
        if self._lock is None:
            return True
        self._held = self._lock.acquire(blocking=False)
        return self._held

    def close(self) -> None:
        if self._held and self._lock is not None:
            self._held = False
            self._lock.release()

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
