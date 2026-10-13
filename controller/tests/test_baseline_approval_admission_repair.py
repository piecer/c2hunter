"""Actual publication admission, source mutation and first-failure observers."""

from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_approval_oracle_repair import repo as repo_fixture
from tests.test_historical_read_bounds import pad, put_flows, wire
from tests.test_historical_source import START, config, review, stored

repo = repo_fixture


def request_for(repo: Any, *, admitted: bool = True, revision: int = 0) -> g.ApprovalRequest:
    binding = (
        repo.preview_baseline_source(
            config().scope_id, "root", revision, "APPROVAL"
        ).source_binding_sha256
        if admitted
        else "0" * 64
    )
    return g.ApprovalRequest(
        expected_revision=revision,
        idempotency_key="caps",
        source_job_id="root",
        source_binding_sha256=binding,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="explicit synthetic review",
    )


def poison(*args: Any, **kw: Any) -> Any:
    raise AssertionError("forbidden later observer")


def nodes(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + sum(1 + nodes(v) for v in value.values())
    if isinstance(value, list):
        return 1 + sum(map(nodes, value))
    return 1


@pytest.mark.parametrize("axis", ["total", "lineage", "depth", "nodes", "context", "syn"])
@pytest.mark.parametrize("extra", [0, 1])
def test_public_source_remaining_caps(repo: Any, monkeypatch: Any, axis: str, extra: int) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    raw = stored()
    if axis == "lineage":
        length = 16 + extra
        for index in range(length):
            parent = stored()
            parent.update(
                id="root" if index == 0 else f"parent-{index}",
                parent_job_id=f"parent-{index + 1}" if index + 1 < length else None,
            )
            repo.save_job(parent)
    else:
        if axis == "depth":
            value: Any = 0
            for _ in range(14 + extra):
                value = [value]
            raw["flow_records"][0]["unused"] = value
        elif axis == "nodes":
            rows = [dict(row, unused=[]) for row in raw["flow_records"][:16]]
            quotient, rest = divmod(262144 + extra - nodes(rows), len(rows))
            for index, row in enumerate(rows):
                row["unused"] = [0] * (quotient + (index < rest))
            assert nodes(rows) == 262144 + extra
            raw["flow_records"] = rows
        elif axis == "context":
            raw["flow_records"][0]["packet_sizes"] = [1] * (128 + extra)
        elif axis == "syn":
            for row in raw["flow_records"]:
                row["tcp_syn_only_observations"] = [[0, index] for index in range(8)]
            if extra:
                raw["flow_records"][-1]["tcp_syn_only_observations"].append([0, 99])
        repo.save_job(raw)
        if axis == "total":
            rows = [pad(repo, raw["flow_records"][i % 32], 64000) for i in range(131)]
            remaining = 8 * 1024 * 1024 + extra - len(wire(repo, rows).encode())
            for row in rows:
                portion = min(remaining, 1536)
                row["unused"] += "x" * portion
                remaining -= portion
            assert remaining == 0 and len(wire(repo, rows).encode()) == 8 * 1024 * 1024 + extra
            put_flows(repo, rows)
    request = request_for(repo, admitted=not extra)
    if extra:
        monkeypatch.setattr(g, "produce_generation", poison)
        monkeypatch.setattr(bs.s, "source_from_binding", poison)
        code = "BASELINE_SOURCE_LINEAGE_INVALID" if axis == "lineage" else "BASELINE_SOURCE_LIMIT"
        with pytest.raises(bs.BaselineStorageError, match="^" + code + "$"):
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert repo.get_baseline_scope(config().scope_id).control_revision == 0
    else:
        assert repo.publish_baseline_source(config().scope_id, request, "reviewer", START).created


@pytest.mark.parametrize(
    "axis", ["order", "kind", "multiplicity", "sensor", "unknown-protocol", "missing", "bool"]
)
def test_actual_source_mutation_admission(repo: Any, monkeypatch: Any, axis: str) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    raw = stored()
    repo.save_job(raw)
    request = request_for(repo)
    if axis == "order":
        raw["flow_records"][0] = dict(reversed(list(raw["flow_records"][0].items())))
    elif axis == "kind":
        raw["flow_records"][0]["duration_seconds"] = 0.0
    elif axis == "multiplicity":
        raw["flow_records"].append(dict(raw["flow_records"][0]))
    elif axis == "sensor":
        raw["flow_records"][0]["sensor_id"] = "different"
    elif axis == "unknown-protocol":
        raw["flow_records"][0]["protocol"] = "CUSTOM"
    elif axis == "missing":
        del raw["flow_records"][0]["duration_seconds"]
    else:
        raw["flow_records"][0]["packet_count"] = True
    repo.save_job(raw)
    monkeypatch.setattr(b, "_dispersion", poison)
    with pytest.raises(bs.BaselineStorageError) as caught:
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert caught.value.code == (
        "BASELINE_SCOPE_MISMATCH"
        if axis == "sensor"
        else "BASELINE_SOURCE_INVALID"
        if axis in {"missing", "bool"}
        else "BASELINE_SOURCE_CHANGED"
    )
    assert repo.get_baseline_scope(config().scope_id).control_revision == 0


@pytest.mark.parametrize(
    "axis", ["state", "bytes", "lineage", "revision", "frozen", "binding", "quality", "duplicate"]
)
def test_first_failure_zero_later_observers(repo: Any, monkeypatch: Any, axis: str) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    raw = stored()
    repo.save_job(raw)
    request = request_for(repo)
    if axis == "duplicate":
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        # Same root also overlaps the durable watermark. Duplicate must win.
        request = g.ApprovalRequest.from_mapping(
            dict(request.to_mapping(), expected_revision=1, idempotency_key="second")
        )
    elif axis in {"state", "bytes", "lineage"}:
        raw.update(status="PARTIALLY_COMPLETED" if axis == "state" else "COMPLETED")
        if axis == "state":
            raw["flow_records"] *= 257
        elif axis == "bytes":
            raw["flow_records"][0]["unused"] = "x" * 65537
        else:
            raw["parent_job_id"] = "missing"
        repo.save_job(raw)
        request = request.model_copy(update={"expected_revision": 7})
    elif axis in {"revision", "frozen"}:
        if isinstance(repo, MemoryRepository):
            view = repo._baseline_scopes[config().scope_id]
            repo._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
                dict(view.to_mapping(), frozen=True)
            )
        else:
            repo.connection.execute("UPDATE baseline_scopes SET frozen=1")
            repo.connection.commit()
        request = request.model_copy(
            update={
                "expected_revision": 1 if axis == "revision" else 0,
                "source_binding_sha256": "0" * 64,
            }
        )
    elif axis == "binding":
        request = request.model_copy(
            update={
                "source_binding_sha256": "0" * 64,
                "quality_review": request.quality_review.model_copy(
                    update={"sensor_alias_asserted": True}
                ),
            }
        )
    else:
        raw["capture_incomplete"] = True
        repo.save_job(raw)
        request = request_for(repo)
    code = dict(
        state="SOURCE_STATE",
        bytes="SOURCE_LIMIT",
        lineage="SOURCE_LINEAGE_INVALID",
        revision="REVISION_CONFLICT",
        frozen="FROZEN",
        binding="SOURCE_CHANGED",
        quality="SOURCE_QUALITY",
        duplicate="SOURCE_DUPLICATE",
    )[axis]
    monkeypatch.setattr(b, "_dispersion", poison)
    monkeypatch.setattr(b, "build_behavior_windows_with_retained_keys", poison)
    if axis not in {"quality", "duplicate"}:
        monkeypatch.setattr(bs.s, "source_from_binding", poison)
        monkeypatch.setattr("uuid.uuid4", poison)
    if axis == "state":
        for name in ("_admit_rows", "_sqlite_flows"):
            monkeypatch.setattr(r, name, poison)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_" + code + "$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert repo.get_baseline_scope(config().scope_id).control_revision == (
        1 if axis == "duplicate" else 0
    )
