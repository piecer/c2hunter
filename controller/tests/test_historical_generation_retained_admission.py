"""Actual-source retained union admission, pruning and eligibility controls."""

from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

from tests.test_historical_generation import (
    advance,
    empty_scope,
    publish,
    snapshot_for,
    source_job,
)


def source(index: int, ports: range | tuple[int, ...], **kwargs: Any) -> Any:
    raw = source_job(index, **kwargs)
    raw["flow_records"] = [
        dict(row, destination_port=port) for port in ports for row in raw["flow_records"][:8]
    ]
    return raw


def observe_features(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    calls = []
    actual = b._dispersion

    def observe(values: list[float]) -> float:
        calls.append(tuple(values))
        return actual(values)

    monkeypatch.setattr(b, "_dispersion", observe)
    return calls


@pytest.mark.parametrize("aggregate", [False, True])
def test_actual_new_key_rejects_before_features(
    monkeypatch: pytest.MonkeyPatch, aggregate: bool
) -> None:
    scope = empty_scope()
    current = publish(snapshot_for(source(0, range(1000, 1128), aggregate=aggregate)), scope)
    scope = advance(scope, current)
    snap = snapshot_for(source(1, (1128,), aggregate=aggregate))
    calls = observe_features(monkeypatch)
    with pytest.raises(ValueError, match="BASELINE_PROFILE_LIMIT"):
        publish(snap, scope, current, index=2)
    assert calls == []


@pytest.mark.parametrize("prune", ["global16", "event30days"])
def test_pruning_old_only_key_allows_new_key(prune: str) -> None:
    scope = empty_scope()
    current = publish(snapshot_for(source(0, range(1000, 1128))), scope)
    scope = advance(scope, current)
    count = 16 if prune == "global16" else 2
    for index in range(1, count):
        # Old receipt alone carries1000; other127 keys survive its eviction.
        raw = source(index, range(1001, 1128))
        current = publish(snapshot_for(raw), scope, current, index=index + 1)
        scope = advance(scope, current)
    hours = None if prune == "global16" else 30 * 24 + 1
    result = publish(
        snapshot_for(source(count, (1128,), hours=hours)), scope, current, index=count + 1
    )
    assert len({w.key for w in result.windows}) == 128
    assert 1000 not in {w.key.service_port for w in result.windows}
    assert 1128 in {w.key.service_port for w in result.windows}


@pytest.mark.parametrize(
    "excluded", ["sparse", "common53", "common123", "no_service", "trusted", "suppressed", "retry"]
)
def test_excluded_incoming_keys_do_not_spend_retained_union(
    monkeypatch: pytest.MonkeyPatch, excluded: str
) -> None:
    scope = empty_scope()
    current = publish(snapshot_for(source(0, range(1000, 1128))), scope)
    scope = advance(scope, current)
    raw = source(1, (1127, 1128))
    new_rows = raw["flow_records"][8:]
    if excluded == "sparse":
        raw["flow_records"] = raw["flow_records"][:8] + new_rows[:7]
    elif excluded.startswith("common"):
        for row in new_rows:
            row["destination_port"] = int(excluded.removeprefix("common"))
    elif excluded == "no_service":
        for row in new_rows:
            row["destination_port"] = None
    elif excluded in {"suppressed", "retry"}:
        for row in new_rows:
            packets = 1000 if excluded == "suppressed" else 1
            row.update(
                packet_count=packets,
                total_bytes=packets * 60,
                duration_seconds=1 if excluded == "suppressed" else 0,
                tcp_flags={"syn": packets},
                tcp_flags_observed=True,
                tcp_syn_count=packets,
                tcp_syn_only_count=packets,
            )
            if excluded == "retry":
                row["tcp_syn_only_observations"] = [[0, 12345]]
    else:
        for row in new_rows:
            row["destination_ip"] = "203.0.113.77"
        raw["allowlist"] = [
            {"type": "IP", "value": "203.0.113.77", "description": "saved", "enabled": True}
        ]
    calls = observe_features(monkeypatch)
    result = publish(snapshot_for(raw), scope, current, index=2)
    assert len({w.key for w in result.windows}) == 128
    assert len(calls) == 2


def test_finite_zero_size_still_spends_union(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = empty_scope()
    current = publish(snapshot_for(source(0, range(1000, 1128), aggregate=True)), scope)
    scope = advance(scope, current)
    raw = source(1, (1128,), aggregate=True)
    for row in raw["flow_records"]:
        row.update(total_bytes=0, bidirectional=True)
    calls = observe_features(monkeypatch)
    with pytest.raises(ValueError, match="BASELINE_PROFILE_LIMIT"):
        publish(snapshot_for(raw), scope, current, index=2)
    assert calls == []
