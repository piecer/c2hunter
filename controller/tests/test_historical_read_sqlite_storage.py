"""Reject SQLite non-TEXT JSON cells without masking programming failures."""

from typing import Any

import pytest

from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_historical_read import read
from tests.test_historical_source import stored


@pytest.mark.parametrize("axis", ["metadata", "flows", "candidates"])
def test_blob_json_rejected_before_decoder_and_reusable(
    tmp_path: Any, monkeypatch: Any, axis: str
) -> None:
    repo = SQLiteRepository(tmp_path / "storage.sqlite")
    repo.save_job(stored())
    repo.save_candidates("root", [{"id": "rule", "candidate_ip": "203.0.113.9", "score": 40}])
    expected = read(repo)
    table, predicate = {
        "metadata": ("objects", " WHERE kind='job'"),
        "flows": ("job_flow_records", ""),
        "candidates": ("candidate_records", ""),
    }[axis]
    statement = "UPDATE " + table + " SET data=CAST(data AS BLOB)" + predicate
    repo.connection.execute(statement)
    repo.connection.commit()
    assert repo.connection.execute("SELECT typeof(data) FROM " + table + predicate).fetchone() == (
        "blob",
    )
    decoder = r._decode
    non_text_calls = []
    statements = []

    def observe(raw: str, **kwargs: Any) -> Any:
        if type(raw) is not str:
            non_text_calls.append(type(raw).__name__)
        return decoder(raw, **kwargs)

    monkeypatch.setattr(r, "_decode", observe)
    repo.connection.set_trace_callback(statements.append)
    try:
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_INVALID$"):
            read(repo)
        assert not non_text_calls
        if axis == "flows":
            assert not any("json_each" in query for query in statements)
        assert not repo.connection.in_transaction
    finally:
        repo.connection.set_trace_callback(None)
        repo.connection.execute("UPDATE " + table + " SET data=CAST(data AS TEXT)" + predicate)
        repo.connection.commit()
        assert read(repo) == expected
        repo.close()


def test_programmer_attribute_error_is_not_sanitized(tmp_path: Any, monkeypatch: Any) -> None:
    repo = SQLiteRepository(tmp_path / "programming.sqlite")
    repo.save_job(stored())
    failure = AttributeError("programmer defect")

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise failure

    monkeypatch.setattr(r, "_decode", broken)
    try:
        with pytest.raises(AttributeError) as error:
            read(repo)
        assert error.value is failure
        assert not repo.connection.in_transaction
    finally:
        repo.close()
