"""Persistent regressions for the three independent source-projection findings."""

import copy
from dataclasses import replace

import pytest
from c2hunter_analysis import behavior_baseline as b
from test_historical_source import config, project, review, stored

from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_source as s


def build_bytes(source):
    request = s.source_build_input(
        source, scope=config(), quality_review=review(), source_receipt_id=None
    )
    result = b.build_behavior_windows(request)
    assert result.eligible_profile_count == 4
    return h.canonical_json(b.baseline_build_to_mapping(result))


@pytest.mark.parametrize("field", ["tcp_flags", "duration_seconds"])
@pytest.mark.parametrize("zero", [0.0, -0.0])
def test_signed_zero_comparison_identity_preserves_raw_binding(field, zero):
    raw = stored()
    raw["flow_records"][0][field] = {"ack": 0} if field == "tcp_flags" else 0
    first = project(raw)
    raw["flow_records"][0][field] = {"ack": zero} if field == "tcp_flags" else zero
    unchanged = copy.deepcopy(raw)
    second = project(raw)
    assert build_bytes(first) == build_bytes(second)
    assert first.feature_observation_sha256 == second.feature_observation_sha256
    assert first.observation_sha256 == second.observation_sha256
    assert h.source_binding_sha256(first.source_binding(), purpose="APPROVAL") != (
        h.source_binding_sha256(second.source_binding(), purpose="APPROVAL")
    )
    assert h.canonical_json(raw) == h.canonical_json(unchanged)


@pytest.mark.parametrize("value", [0.5, 1, 1.5, 2**31])
def test_nonzero_flags_keep_comparison_value_and_order(value):
    raw = stored()
    raw["flow_records"][0]["tcp_flags"] = {"z": value, "A": 1}
    source = project(raw)
    observation = s._observation(source.strict_flows[0], config().sensor_key)
    assert observation[s.OBSERVATION_FIELDS.index("tcp_flags")] == (("A", "1"), ("z", str(value)))
    assert raw["flow_records"][0]["tcp_flags"] == {"z": value, "A": 1}
    build_bytes(source)


@pytest.mark.parametrize("value", [True, float("inf"), float("nan"), -1, 2**63])
def test_flag_numeric_admission_unchanged(value):
    raw = stored()
    raw["flow_records"][0]["tcp_flags"] = {"ack": value}
    with pytest.raises(s.SourceInputError):
        project(raw)


def decode_source(value, route):
    if route == "constructor":
        return s.SourceProjection(**value)
    if route == "validate":
        return s.SourceProjection.model_validate(value)
    return s.SourceProjection.from_mapping(value)


@pytest.mark.parametrize("route", ["constructor", "validate", "mapping"])
@pytest.mark.parametrize("as_flow", [False, True])
@pytest.mark.parametrize(
    "bad",
    [
        {"offset_us": 0, "sequence": 7, "unexpected": "malformed"},
        {"offset_us": 0},
        {"sequence": 7},
        {"offset_us": True, "sequence": 7},
        {"offset_us": 0, "sequence": 7.0},
        {"offset_us": 0, "sequence": 2**32},
        [0, -1],
        [0],
        [0, 7, 8],
    ],
)
def test_closed_nested_syn_before_normalization(route, as_flow, bad, monkeypatch):
    raw = stored()
    raw["flow_records"][0]["tcp_syn_only_observations"] = [[0, 7], [0, 7]]
    source = project(raw)
    data = source.to_mapping()
    observations = [{"offset_us": 0, "sequence": 7}, bad]
    if as_flow:
        data["strict_flows"][0] = replace(
            source.strict_flows[0], tcp_syn_only_observations=observations
        )
    else:
        data["strict_flows"][0]["tcp_syn_only_observations"] = observations
    calls = []
    original = s.normalize_tcp_syn_observations

    def spy(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(s, "normalize_tcp_syn_observations", spy)
    with pytest.raises(ValueError):
        decode_source(data, route)
    # Pydantic may validate remaining rows after an error, but must never
    # send the malformed first row to the lossy legacy normalizer.
    assert not any(value is observations for value in calls)


@pytest.mark.parametrize("route", ["constructor", "validate", "mapping"])
@pytest.mark.parametrize("as_flow", [False, True])
@pytest.mark.parametrize("encoding", ["list", "tuple", "object"])
def test_legitimate_nested_syn_roundtrip_and_builder(route, as_flow, encoding):
    raw = stored()
    raw["flow_records"][0]["tcp_syn_only_observations"] = [
        {"offset_us": 0, "sequence": 0},
        {"offset_us": 1, "sequence": 2**32 - 1},
    ]
    source = project(raw)
    data = source.to_mapping()
    pairs = [[0, 0], [1, 2**32 - 1]]
    observations = (
        pairs
        if encoding == "list"
        else tuple(tuple(p) for p in pairs)
        if encoding == "tuple"
        else raw["flow_records"][0]["tcp_syn_only_observations"]
    )
    if as_flow:
        data["strict_flows"][0] = replace(
            source.strict_flows[0], tcp_syn_only_observations=observations
        )
    else:
        data["strict_flows"][0]["tcp_syn_only_observations"] = observations
    decoded = decode_source(data, route)
    assert decoded == source
    assert build_bytes(decoded) == build_bytes(source)


def count_boundary_calls(monkeypatch):
    calls = []
    for module, name in (
        (h, "project_original_flow"),
        (h, "_freeze"),
        (s, "normalize_tcp_syn_observations"),
        (b, "build_behavior_windows"),
    ):
        original = getattr(module, name)

        def spy(*args, _name=name, _original=original, **kwargs):
            calls.append(_name)
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, name, spy)
    return calls


def assert_limit(error):
    if isinstance(error, s.SourceInputError):
        assert error.code == "BASELINE_SOURCE_LIMIT"
    else:
        causes = [item["ctx"]["error"] for item in error.errors(include_input=False)]
        assert any(
            getattr(cause, "code", str(cause)) == "BASELINE_SOURCE_LIMIT" for cause in causes
        )


@pytest.mark.parametrize("bad_member", [False, True])
@pytest.mark.parametrize("single_row", [False, True])
def test_raw_cumulative_syn_limit_precedes_all_copies(monkeypatch, bad_member, single_row):
    raw = stored()
    raw["flow_records"][0]["tcp_syn_only_observations"] = [[0, 7]] * (257 if single_row else 256)
    if not single_row:
        raw["flow_records"][1]["tcp_syn_only_observations"] = [[0, 7]]
    if bad_member:
        raw["flow_records"][0]["tcp_syn_only_observations"][0] = {"unexpected": True}
    calls = count_boundary_calls(monkeypatch)
    with pytest.raises(s.SourceInputError, match="^BASELINE_SOURCE_LIMIT$"):
        project(raw)
    assert calls == []


@pytest.mark.parametrize("route", ["constructor", "validate", "mapping", "binding"])
def test_original_dto_cumulative_limit_precedes_copy(monkeypatch, route):
    source = project(stored())
    raw = stored()
    raw["flow_records"][0]["tcp_syn_only_observations"] = [[0, 7]] * 256
    raw["flow_records"][1]["tcp_syn_only_observations"] = [[0, 7]]
    original = h.project_original_job(raw)
    data = source.to_mapping()
    data["original"] = original.to_mapping()
    if route == "binding":
        binding_data = source.source_binding().to_mapping()
        binding_data["original"] = original
        binding = h.SourceBindingProjection.from_mapping(binding_data)
    calls = count_boundary_calls(monkeypatch)
    with pytest.raises(ValueError) as error:
        if route == "binding":
            s.source_from_binding(binding, scope=config(), quality_review=review())
        else:
            decode_source(data, route)
    assert_limit(error.value)
    assert calls == []


@pytest.mark.parametrize("route", ["constructor", "validate", "mapping"])
def test_strict_dto_cumulative_limit_precedes_copy(monkeypatch, route):
    data = project(stored()).to_mapping()
    data["strict_flows"][0]["tcp_syn_only_observations"] = [[0, 7]] * 256
    data["strict_flows"][1]["tcp_syn_only_observations"] = [{"unexpected": True}]
    calls = count_boundary_calls(monkeypatch)
    with pytest.raises(ValueError) as error:
        decode_source(data, route)
    assert_limit(error.value)
    assert calls == []


@pytest.mark.parametrize("route", ["raw", "constructor", "validate", "mapping"])
def test_row_cap_precedes_row_shape_and_copy(monkeypatch, route):
    if route == "raw":
        data = stored()
        data["flow_records"] = [None] * 8193
    else:
        data = project(stored()).to_mapping()
        data["original"]["flow_records"] = [None] * 8193
    calls = count_boundary_calls(monkeypatch)
    with pytest.raises(ValueError) as error:
        project(data) if route == "raw" else decode_source(data, route)
    assert_limit(error.value)
    assert calls == []


@pytest.mark.parametrize("object_pairs", [False, True])
def test_exact_cumulative_syn_limit_retains_duplicates(object_pairs):
    raw = stored()
    pair = {"offset_us": 0, "sequence": 7} if object_pairs else [0, 7]
    raw["flow_records"][0]["tcp_syn_only_observations"] = [pair] * 128
    raw["flow_records"][1]["tcp_syn_only_observations"] = [pair] * 128
    original_bytes = h.canonical_json(raw)
    source = project(raw)
    assert sum(len(flow.tcp_syn_only_observations or ()) for flow in source.strict_flows) == 256
    for route in ("constructor", "validate", "mapping"):
        assert decode_source(source.to_mapping(), route) == source
    rebuilt = s.source_from_binding(
        source.source_binding(), scope=config(), quality_review=review()
    )
    assert rebuilt == source
    assert h.canonical_json(raw) == original_bytes
    build_bytes(source)


@pytest.mark.parametrize("representation", ["job", "rows", "fields"])
@pytest.mark.parametrize("count", [256, 257])
def test_original_immutable_dto_forms_preserve_admission(representation, count, monkeypatch):
    raw = stored()
    raw["flow_records"][0]["tcp_syn_only_observations"] = [[0, 7]] * 256
    source = project(raw)
    if count == 257:
        raw["flow_records"][1]["tcp_syn_only_observations"] = [[0, 7]]
    original = h.project_original_job(raw)
    data = source.to_mapping()
    if representation == "job":
        data["original"] = original
    elif representation == "rows":
        data["original"]["flow_records"] = original.flow_records
    else:
        for row, frozen in zip(
            data["original"]["flow_records"], original.flow_records, strict=True
        ):
            row["fields"] = frozen.fields
    calls = count_boundary_calls(monkeypatch)
    if count == 257:
        with pytest.raises(ValueError) as error:
            s.SourceProjection.model_validate(data)
        assert_limit(error.value)
        assert calls == []
    else:
        decoded = s.SourceProjection.model_validate(data)
        assert decoded == source
        build_bytes(decoded)


@pytest.mark.parametrize("bad", [None, {}, "bad", (1, 2)])
def test_raw_syn_container_not_repaired(bad, monkeypatch):
    raw = stored()
    raw["flow_records"][0]["tcp_syn_only_observations"] = bad
    if bad is None:
        build_bytes(project(raw))
    else:
        calls = count_boundary_calls(monkeypatch)
        with pytest.raises(s.SourceInputError, match="^BASELINE_SOURCE_INVALID$"):
            project(raw)
        assert calls == []
