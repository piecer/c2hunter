"""Bounded Argon2id work; never normalize or truncate a password."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.profiles import RFC_9106_LOW_MEMORY

_SLOTS = threading.BoundedSemaphore(2)
# A public dummy hash is not a credential. It has the same work factors as real users.
_DUMMY = (
    "$argon2id$v=19$m=65536,t=3,p=4$MIIRqgvgQbgj220jfp0MPA$"
    "YfwJSVjtjSU0zzV/P3S9nnQ/USre2wvJMjfCIjrTQbg"
)


class PasswordError(ValueError):
    """Invalid password encoding or bounds (contains no submitted input)."""


class PasswordBusy(Exception):
    """No expensive-work slot available; callers must return 429."""


class Passwords:
    def __init__(self) -> None:
        self._hasher = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)

    @staticmethod
    def validate(password: str) -> None:
        try:
            valid = isinstance(password, str) and 12 <= len(password) <= 128
            if not valid or len(password.encode("utf-8")) > 512:
                raise PasswordError(
                    "Password must contain 12..128 characters and at most 512 bytes"
                )
        except UnicodeError:
            raise PasswordError("Invalid password encoding") from None

    @contextmanager
    def slot(self) -> Iterator[None]:
        if not _SLOTS.acquire(blocking=False):
            raise PasswordBusy("Password service busy")
        try:
            yield
        finally:
            _SLOTS.release()

    def hash(self, password: str) -> str:
        self.validate(password)
        with self.slot():
            return self._hasher.hash(password)

    def verify(self, encoded: str | None, password: str) -> bool:
        self.validate(password)
        with self.slot():
            try:
                valid = self._hasher.verify(encoded or _DUMMY, password)
                return valid and encoded is not None
            except (VerificationError, InvalidHashError):
                return False
