"""Reachable persistence faults through delegating real SQLite connections."""

import json
import sqlite3

import pytest

from c2hunter_controller import historical_ai_storage as custody
from c2hunter_controller.historical_ai_builder import build_historical_target_snapshot
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_historical_ai_storage import advance, prepared


def test_typed_storage_errors_have_one_no_ack_classification():
    from c2hunter_controller._baseline_storage import BaselineStorageError

    for error in (
        custody.HistoricalStorageError(),
        custody.HistoricalStorageOutcomeUnknown(),
        BaselineStorageError(),
        BaselineStorageError("BASELINE_BUSY"),
    ):
        assert isinstance(error, custody.HISTORICAL_STORAGE_ERRORS)
    assert not isinstance(
        ValueError("BASELINE_STORAGE_UNAVAILABLE"), custody.HISTORICAL_STORAGE_ERRORS
    )


class FaultConnection:
    def __init__(self, connection, *, commit_error=False, read_error=False):
        self.connection = connection
        self.commit_error = commit_error
        self.read_error = read_error
        self.fired = False
        self.closed = False
        self.committed = False
        self.calls_after_close = 0
        self.read_queries = []

    def cursor(self):
        return FaultCursor(self.connection.cursor(), self)

    def __getattr__(self, name):
        if self.closed:
            self.calls_after_close += 1
        return getattr(self.connection, name)

    def commit(self):
        self.connection.commit()
        self.committed = True
        if self.commit_error and not self.fired:
            self.fired = True
            raise sqlite3.OperationalError("commit succeeded but response was lost")

    def close(self):
        self.closed = True
        self.connection.close()


class FaultCursor:
    def __init__(self, cursor, owner):
        self.cursor, self.owner = cursor, owner

    def __getattr__(self, name):
        return getattr(self.cursor, name)

    def __iter__(self):
        return iter(self.cursor)

    def execute(self, statement, parameters=()):
        if self.owner.committed and statement.startswith("SELECT"):
            self.owner.read_queries.append(statement)
            if self.owner.read_error and not self.owner.fired:
                self.owner.fired = True
                raise sqlite3.OperationalError("first postcommit read failed")
        self.cursor.execute(statement, parameters)
        return self


@pytest.mark.parametrize("operation", ["admit", "save"])
def test_commit_success_then_raises_quarantines_without_overwriting_durable_state(
    tmp_path, operation
):
    path = tmp_path / "uncertain.db"
    repo = SQLiteRepository(path)
    request, _, _ = prepared(repo)
    expected_status = "QUEUED"
    if operation == "save":
        run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
        submitted = advance(run, "CANCELLED", 0)
        expected_status = "CANCELLED"
    fault = FaultConnection(repo.connection, commit_error=True)
    repo.connection = fault
    with pytest.raises(custody.HistoricalStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        if operation == "admit":
            repo.admit_historical_ai_run(request, build_historical_target_snapshot)
        else:
            repo.save_ai_run(submitted)
    assert fault.fired and fault.committed and fault.closed
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as observer:
        rows = observer.execute("SELECT data FROM ai_analysis_runs").fetchall()
        assert len(rows) == 1 and json.loads(rows[0][0])["status"] == expected_status
    with pytest.raises(custody.HistoricalStorageError):
        repo.get_ai_run(request.run_id)
    with pytest.raises(custody.HistoricalStorageError):
        repo.admit_historical_ai_run(request, lambda *_: pytest.fail("same connection retry"))
    assert fault.calls_after_close == 0
    reopened = SQLiteRepository(path)
    replay, created = reopened.admit_historical_ai_run(request, lambda *_: pytest.fail("rebuilt"))
    assert not created and replay["status"] == expected_status
    if operation == "save":
        assert reopened.save_ai_run(submitted) == replay
        assert reopened.save_ai_run(advance(run, "PREPARING", 10)) == replay
    reopened.close()


@pytest.mark.parametrize("operation", ["admit", "save"])
@pytest.mark.parametrize("read_error", [False, True])
def test_success_requires_independent_readback_and_read_failure_quarantines(
    tmp_path, monkeypatch, operation, read_error
):
    path = tmp_path / "readback.db"
    repo = SQLiteRepository(path)
    request, _, _ = prepared(repo)
    expected_status = "QUEUED"
    if operation == "save":
        run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
        submitted = advance(run, "CANCELLED", 0)
        expected_status = "CANCELLED"
    writer = FaultConnection(repo.connection, read_error=read_error)
    repo.connection = writer
    real_connect = sqlite3.connect
    readers = []

    def connect(*args, **kwargs):
        assert writer.committed  # Read snapshot begins only after publication.
        reader = FaultConnection(real_connect(*args, **kwargs), read_error=read_error)
        reader.committed = True
        readers.append(reader)
        return reader

    monkeypatch.setattr(sqlite3, "connect", connect)

    def publish():
        if operation == "admit":
            return repo.admit_historical_ai_run(request, build_historical_target_snapshot)[0]
        return repo.save_ai_run(submitted)

    if read_error:
        with pytest.raises(custody.HistoricalStorageOutcomeUnknown):
            publish()
        assert writer.closed
        with pytest.raises(custody.HistoricalStorageError):
            repo.save_ai_run({"id": request.run_id})
    else:
        result = publish()
        assert result["status"] == expected_status
        assert not writer.closed
    assert len(readers) == 1 and readers[0].closed
    assert readers[0].fired is read_error
    assert readers[0].read_queries and not writer.read_queries
    assert writer.calls_after_close == 0
    with real_connect(path.as_uri() + "?mode=ro", uri=True) as observer:
        rows = observer.execute("SELECT data FROM ai_analysis_runs").fetchall()
        assert len(rows) == 1 and json.loads(rows[0][0])["status"] == expected_status
    monkeypatch.setattr(sqlite3, "connect", real_connect)
    if not read_error:
        repo.close()
    reopened = SQLiteRepository(path)
    replay, created = reopened.admit_historical_ai_run(request, lambda *_: pytest.fail("rebuilt"))
    assert not created and replay["status"] == expected_status
    if operation == "save":
        assert reopened.save_ai_run(submitted) == replay
    reopened.close()
