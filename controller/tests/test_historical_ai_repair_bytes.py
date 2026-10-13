"""R4: exact canonical admission precedes encoder work on rejected input."""

import json

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import world


@pytest.mark.parametrize(
    "scalar", ["x" * (2 * 1024 * 1024), "한" * (1024 * 1024 + 1)], ids=["ascii", "korean"]
)
@pytest.mark.parametrize("entry", ["constructor", "mapping", "instance"])
def test_snapshot_scalar_rejected_before_encoding(scalar, entry, monkeypatch):
    snapshot = producer.build_historical_snapshot(dto.HistoricalAdmissionInput(**world()))
    raw = snapshot.to_mapping()
    raw["admitted_bundles"][0]["canonical_json"] = scalar
    value = snapshot.model_copy(update={"admitted_bundles": raw["admitted_bundles"]})
    calls = []
    original = json.encoder.encode_basestring

    def observed(text):
        if text is scalar:
            calls.append(1)
        return original(text)

    monkeypatch.setattr(json.encoder, "encode_basestring", observed)
    with pytest.raises(ValueError, match="BASELINE_RUN_SNAPSHOT_LIMIT"):
        if entry == "constructor":
            dto.HistoricalRunSnapshot(**raw)
        else:
            dto.HistoricalRunSnapshot.model_validate(value if entry == "instance" else raw)
    assert calls == []  # noqa: S101 - pytest assertion, not an authorization guard.


@pytest.mark.parametrize(
    "part,budget", [("baseline_comparisons", 256 * 1024), ("baseline_summary", 1024 * 1024)]
)
@pytest.mark.parametrize("text", ["x", "한", "😀", '"\\\n\t\x00', "<>&\u2028\u2029"])
@pytest.mark.parametrize("extra", [0, 1])
def test_exact_escaped_utf8_and_cumulative_limit_before_encoding(
    part, budget, text, extra, monkeypatch
):
    # Size-meter corpus, not a claim that padding is a semantically valid DTO.
    raw = {part: [text * 500] * 20}
    size = len(h.canonical_json(raw[part] if part == "baseline_comparisons" else raw).encode())
    raw[part].append("x" * (budget - size - 3 + extra))
    actual_size = len(
        h.canonical_json(raw[part] if part == "baseline_comparisons" else raw).encode()
    )
    assert actual_size == budget + extra  # noqa: S101 - pytest assertion, not an authorization guard.
    calls = []
    original = json.encoder.encode_basestring

    def observed(value):
        calls.append(1)
        return original(value)

    monkeypatch.setattr(json.encoder, "encode_basestring", observed)
    if extra:
        with pytest.raises(dto.HistoricalAIError, match="BASELINE_RUN_SNAPSHOT_LIMIT"):
            dto.validate_snapshot_sizes(raw)
        assert calls == []  # noqa: S101 - pytest assertion, not an authorization guard.
    else:
        dto.validate_snapshot_sizes(raw)
        assert calls  # noqa: S101 - pytest assertion, not an authorization guard.


@pytest.mark.parametrize(
    "axis", ["cycle", "depth", "nodes", "nonstring_key", "nonfinite", "surrogate", "unknown_scalar"]
)
def test_raw_meter_rejects_invalid_or_unbounded_shape_statically(axis, monkeypatch):
    if axis == "cycle":
        item = []
        item.append(item)
    elif axis == "depth":
        item = []
        for _ in range(40):
            item = [item]
    elif axis == "nodes":
        item = [None] * 262145
    elif axis == "nonstring_key":
        item = {1: "invalid"}
    elif axis == "nonfinite":
        item = float("nan")
    elif axis == "surrogate":
        item = "\ud800"
    else:
        item = {"not_json"}
    calls = []
    original = json.encoder.encode_basestring

    def observed(value):
        calls.append(1)
        return original(value)

    monkeypatch.setattr(json.encoder, "encode_basestring", observed)
    with pytest.raises(dto.HistoricalAIError, match="BASELINE_(RUN_SNAPSHOT_LIMIT|SOURCE_INVALID)"):
        dto.validate_snapshot_sizes({"baseline_summary": item})
    assert calls == []  # noqa: S101 - pytest assertion, not an authorization guard.
