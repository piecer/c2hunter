"""SQL row admission stops at the first cumulative overflow, not after hydration."""

import json
from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_read as r
from c2hunter_controller import historical_source as s
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_historical_read import poison, read
from tests.test_historical_read_postgres import pg_repo  # noqa: F401
from tests.test_historical_source import stored


def nodes(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + sum(1 + nodes(child) for child in value.values())
    if isinstance(value, list):
        return 1 + sum(nodes(child) for child in value)
    return 1


@pytest.fixture(params=["sqlite", "postgres"])
def sql_repo(request: Any, tmp_path: Any) -> Any:
    if request.param == "postgres":
        yield request.getfixturevalue("pg_repo")
    else:
        repo = SQLiteRepository(tmp_path / "nodes.sqlite")
        try:
            yield repo
        finally:
            repo.close()


def persist(repo: Any, axis: str, rows: list[dict[str, Any]]) -> None:
    raw = stored()
    if axis == "flows":
        raw["flow_records"] = rows
    repo.save_job(raw)
    if axis == "candidates":
        repo.save_candidates("root", rows)


def prototype(axis: str) -> dict[str, Any]:
    return (
        stored()["flow_records"][0]
        if axis == "flows"
        else {"id": "rule", "candidate_ip": "203.0.113.9", "score": 40}
    )


@pytest.mark.parametrize("axis", ["flows", "candidates"])
def test_stop_after_first_overflowing_row(sql_repo: Any, monkeypatch: Any, axis: str) -> None:
    rows = [dict(prototype(axis), unused=[0] * 16000, id=f"row-{i}") for i in range(32)]
    assert max(len(json.dumps(row).encode()) for row in rows) < r.ROW_BYTES
    persist(sql_repo, axis, rows)
    decoded = []
    original = r._decode

    def decode(raw: str, **kwargs: Any) -> Any:
        value = original(raw, **kwargs)
        if "unused" in value:
            decoded.append(nodes(value))
        return value

    monkeypatch.setattr(r, "_decode", decode)
    monkeypatch.setattr(s, "project_source", poison)
    with pytest.raises(r.HistoricalReadError) as error:
        read(sql_repo)
    assert error.value.code == (
        "BASELINE_SOURCE_LIMIT" if axis == "flows" else "BASELINE_CANDIDATE_LIMIT"
    )
    # Parsing the one overflowing row is necessary; parsing any later row is not.
    assert 1 + sum(decoded[:-1]) <= 262144 < 1 + sum(decoded)
    assert len(decoded) == 17
    monkeypatch.undo()
    persist(sql_repo, axis, [dict(prototype(axis), id="normal")])
    assert read(sql_repo).source.original.id == "root"


@pytest.mark.parametrize("axis", ["flows", "candidates"])
@pytest.mark.parametrize("extra", [0, 1])
def test_exact_cumulative_nodes(sql_repo: Any, monkeypatch: Any, axis: str, extra: int) -> None:
    rows = [dict(prototype(axis), unused=[0] * 15000, id=f"row-{i}") for i in range(17)]
    last = dict(prototype(axis), unused=[], id="last")
    last["unused"] = [0] * (262144 - nodes(rows) - nodes(last) + extra)
    rows.append(last)
    assert nodes(rows) == 262144 + extra
    persist(sql_repo, axis, rows)
    if extra:
        monkeypatch.setattr(s, "project_source", poison)
        with pytest.raises(r.HistoricalReadError) as error:
            read(sql_repo)
        assert error.value.code == (
            "BASELINE_SOURCE_LIMIT" if axis == "flows" else "BASELINE_CANDIDATE_LIMIT"
        )
    else:
        snapshot = read(sql_repo)
        assert len(snapshot.source.strict_flows if axis == "flows" else snapshot.candidates) == 18


@pytest.mark.parametrize("axis", ["flows", "candidates"])
def test_invalid_member_after_valid_prefix(sql_repo: Any, monkeypatch: Any, axis: str) -> None:
    rows = [dict(prototype(axis), id=f"row-{i}", unused="é🙂") for i in range(257)]
    rows[129]["unused"] = "bad\u0001"
    persist(sql_repo, axis, rows)
    original = r._decode
    attempts = []

    def decode(raw: str, **kwargs: Any) -> Any:
        if '"unused"' in raw:
            attempts.append(raw)
        return original(raw, **kwargs)

    monkeypatch.setattr(r, "_decode", decode)
    monkeypatch.setattr(s, "project_source", poison)
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_INVALID$"):
        read(sql_repo)
    assert len(attempts) == 130


@pytest.mark.parametrize("axis", ["flows", "candidates"])
def test_valid_utf8_across_cursor_batches(sql_repo: Any, axis: str) -> None:
    rows = [dict(prototype(axis), id=f"row-{i}", unused="é🙂") for i in range(257)]
    persist(sql_repo, axis, rows)
    snapshot = read(sql_repo)
    if axis == "candidates":
        assert [dict(c.fields.entries)["id"] for c in snapshot.candidates] == [
            row["id"] for row in rows
        ]
    else:
        assert len(snapshot.source.strict_flows) == 257
    assert h._validate_original(rows) < r.FLOW_BYTES
