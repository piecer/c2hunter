"""Persisted reader tracer bullets; no generic loader is an admissible path."""

from pathlib import Path
from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import historical_baseline as h
from c2hunter_controller.historical_source import project_source, source_build_input
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_source import RECEIPT, config, review, stored


def build(source: Any, purpose: str = "COMPARISON") -> Any:
    return b.build_behavior_windows(
        source_build_input(
            source,
            scope=config(),
            quality_review=review(),
            source_receipt_id=RECEIPT if purpose == "APPROVAL" else None,
        )
    )


def poison(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("forbidden generic loader")


def read(repository: Any, purpose: str = "COMPARISON", **kwargs: Any) -> Any:
    method = getattr(repository, "read_historical_source", None)
    assert callable(method), "bounded persisted-source operation is missing"
    return method("root", purpose=purpose, scope=config(), quality_review=review(), **kwargs)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("aggregate", [False, True])
@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
def test_memory_persisted_actual_builder(
    aggregate: bool, purpose: str, monkeypatch: pytest.MonkeyPatch, backend: str, tmp_path: Path
) -> None:
    raw = stored(aggregate=aggregate)
    control = build(
        project_source(raw, ancestors=(), scope=config(), quality_review=review()), purpose
    )
    assert len(control.profiles) == 4
    repo = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "source.sqlite")
    )
    repo.save_job(raw)
    candidates = [{"id": "rule", "candidate_ip": "203.0.113.9", "score": 40}]
    repo.save_candidates("root", candidates)
    for name in ("get_job", "list_jobs", "get_candidates", "get_job_summary"):
        monkeypatch.setattr(repo, name, poison)
    snapshot = read(repo, purpose)
    assert set(type(snapshot).model_fields) == {"source", "candidates", "source_binding_sha256"}
    assert build(snapshot.source, purpose) == control
    expected = () if purpose == "APPROVAL" else (h.project_candidate(candidates[0], position=0),)
    assert snapshot.candidates == expected
    assert snapshot.source_binding_sha256 == h.source_binding_sha256(
        snapshot.source.source_binding(), purpose=purpose, candidates=expected
    )


def test_memory_oversize_before_copy_or_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = MemoryRepository()
    raw = stored()
    raw["flow_records"] *= 257
    repo.save_job(raw)
    monkeypatch.setattr("c2hunter_controller.repositories.deepcopy", poison)
    monkeypatch.setattr("c2hunter_controller.historical_source.project_source", poison)
    for name in ("get_job", "list_jobs", "get_candidates"):
        monkeypatch.setattr(repo, name, poison)
    with pytest.raises(ValueError, match="^BASELINE_SOURCE_LIMIT$"):
        read(repo)


def test_sqlite_oversize_before_transfer_or_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = SQLiteRepository(tmp_path / "source.sqlite")
    repo.save_job(stored())
    repo.connection.execute(
        "UPDATE job_flow_records SET data=?", ('["' + "x" * (8 * 1024 * 1024) + '"]',)
    )
    repo.connection.commit()
    monkeypatch.setattr("c2hunter_controller.historical_source.project_source", poison)
    for name in ("get_job", "list_jobs", "get_candidates"):
        monkeypatch.setattr(repo, name, poison)
    with pytest.raises(ValueError, match="^BASELINE_SOURCE_LIMIT$"):
        read(repo)
    assert not repo.connection.in_transaction
