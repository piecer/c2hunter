"""Actual default-timeout contention plus driver-code-family mapping controls."""

import sqlite3
import time
from typing import Any

import pytest

from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_historical_read import read
from tests.test_historical_source import stored


def test_real_five_second_sqlite_busy_rolls_back_and_reuses(
    tmp_path: Any, monkeypatch: Any
) -> None:
    path = tmp_path / "busy.sqlite"
    repo = SQLiteRepository(path)
    repo.save_job(stored())
    expected = read(repo)
    assert repo.connection.execute("PRAGMA busy_timeout").fetchone() == (5000,)
    driver_codes = []
    snapshot = r.sqlite_snapshot

    def observe(*args: Any, **kwargs: Any) -> Any:
        try:
            return snapshot(*args, **kwargs)
        except sqlite3.Error as error:
            driver_codes.append(error.sqlite_errorcode)
            raise

    monkeypatch.setattr(r, "sqlite_snapshot", observe)
    peer = sqlite3.connect(path)
    peer.execute("BEGIN EXCLUSIVE")
    try:
        started = time.monotonic()
        with pytest.raises(r.HistoricalReadError) as error:
            read(repo)
        elapsed = time.monotonic() - started
        assert driver_codes == [sqlite3.SQLITE_BUSY]
        assert elapsed >= 4.8
        assert not repo.connection.in_transaction
    finally:
        peer.rollback()
        peer.close()
    try:
        assert read(repo) == expected
        assert str(error.value) == error.value.code == "BASELINE_BUSY"
    finally:
        repo.close()


@pytest.mark.parametrize(
    "driver_code,expected",
    [
        (sqlite3.SQLITE_BUSY, "BASELINE_BUSY"),
        (sqlite3.SQLITE_BUSY_RECOVERY, "BASELINE_BUSY"),
        (sqlite3.SQLITE_BUSY_SNAPSHOT, "BASELINE_BUSY"),
        (sqlite3.SQLITE_BUSY_TIMEOUT, "BASELINE_BUSY"),
        (sqlite3.SQLITE_LOCKED, "BASELINE_BUSY"),
        (sqlite3.SQLITE_LOCKED_SHAREDCACHE, "BASELINE_BUSY"),
        (sqlite3.SQLITE_LOCKED_VTAB, "BASELINE_BUSY"),
        (sqlite3.SQLITE_CORRUPT, "BASELINE_STORAGE_UNAVAILABLE"),
        (sqlite3.SQLITE_IOERR_READ, "BASELINE_STORAGE_UNAVAILABLE"),
        (None, "BASELINE_STORAGE_UNAVAILABLE"),
    ],
)
def test_driver_code_families_not_error_text(
    tmp_path: Any, monkeypatch: Any, driver_code: int | None, expected: str
) -> None:
    repo = SQLiteRepository(tmp_path / "codes.sqlite")
    repo.save_job(stored())
    failure = sqlite3.OperationalError("database is locked; private/path/source")
    if driver_code is not None:
        failure.sqlite_errorcode = driver_code
    fired = []

    def fault(*args: Any, **kwargs: Any) -> Any:
        fired.append(True)
        raise failure

    monkeypatch.setattr(r, "sqlite_snapshot", fault)
    try:
        with pytest.raises(r.HistoricalReadError) as error:
            read(repo)
        assert fired == [True]
        assert str(error.value) == error.value.code == expected
        assert not repo.connection.in_transaction
        monkeypatch.undo()
        assert read(repo).source.original.id == "root"
    finally:
        repo.close()


def test_real_closed_connection_remains_unavailable(tmp_path: Any) -> None:
    repo = SQLiteRepository(tmp_path / "closed.sqlite")
    repo.save_job(stored())
    repo.close()
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        read(repo)
