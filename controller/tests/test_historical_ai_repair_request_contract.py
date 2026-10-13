"""Post-GREEN sibling/semantic characterization; not additional RED claims."""

import hashlib
import json
import warnings
from datetime import UTC, datetime, timedelta, timezone

import pytest

from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as builder
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from tests import test_historical_ai_repair_request_admission as admission

clean = admission.clean
copied = admission.copied

STRING_PATHS = (
    "analysis_job_id",
    "actor",
    "run_id",
    "provider",
    "model_name",
    "prompt_name",
    "prompt_version",
    "prompt_hash",
    "input_schema_version",
    "output_schema_version",
    "request_fingerprint",
    "payload.idempotency_key",
    "payload.analysis_kind",
    "payload.language",
    "payload.discovery_mode",
    "payload.baseline_mode",
    "payload.baseline_reference.scope_id",
    "payload.baseline_reference.generation_id",
    "payload.baseline_reference.target_source_binding_sha256",
    "payload.baseline_reference.quality_review.note",
)


def invoke(clean, request, boundary):
    value, saved, commitment = clean
    if boundary == "builder":
        return builder.build_historical_snapshot(value.model_copy(update={"request": request}))
    return dto.decode_historical_snapshot(
        saved, request=request, expected_snapshot_sha256=commitment
    )


def observe_work(monkeypatch):
    calls = {"encoding": [], "copy": [], "fingerprint": [], "selector": []}

    def wrap(original, key):
        def observed(*args, **kwargs):
            calls[key].append(1)
            return original(*args, **kwargs)

        return observed

    for owner, name, key in (
        (json.encoder, "encode_basestring", "encoding"),
        (g, "_unmodel", "copy"),
        (dto, "request_fingerprint", "fingerprint"),
        (ai_discovery, "select_shadow_candidates", "selector"),
    ):
        monkeypatch.setattr(owner, name, wrap(getattr(owner, name), key))
    return calls


@pytest.mark.parametrize("boundary", ["builder", "decoder"])
@pytest.mark.parametrize("path", STRING_PATHS)
def test_every_string_slot_rejects_large_scalar_before_work(clean, path, boundary, monkeypatch):
    request = copied(clean[0].request, path, "한" * 1048577)
    calls = observe_work(monkeypatch)
    code = "BASELINE_SOURCE_LIMIT" if boundary == "builder" else "HISTORICAL_SNAPSHOT_INVALID"
    with pytest.raises(dto.HistoricalAIError, match="^" + code + "$"):
        invoke(clean, request, boundary)
    assert all(not entries for entries in calls.values())  # noqa: S101


@pytest.mark.parametrize("boundary", ["builder", "decoder"])
@pytest.mark.parametrize(
    ("path", "bad"),
    [
        ("provider", "x" * 201),
        ("payload.baseline_reference.scope_id", "x" * 37),
        ("payload.baseline_reference.quality_review.note", "x" * 513),
        ("payload.allow_remote", 1),
        ("payload.candidate_limit", True),
        ("payload.baseline_reference.expected_revision", 1.0),
        ("payload.baseline_reference.quality_review.sensor_alias_asserted", 0),
        ("payload.baseline_reference.quality_review.representative_window_asserted", 1),
    ],
    ids=[
        "identifier201",
        "uuid37",
        "note513",
        "int-bool",
        "bool-int",
        "float-int",
        "int-alias",
        "int-literal",
    ],
)
def test_bounded_malformed_fields_are_invalid_before_work(clean, path, bad, boundary, monkeypatch):
    request = copied(clean[0].request, path, bad)
    calls = observe_work(monkeypatch)
    code = "BASELINE_SOURCE_INVALID" if boundary == "builder" else "HISTORICAL_SNAPSHOT_INVALID"
    with pytest.raises(dto.HistoricalAIError, match="^" + code + "$"):
        invoke(clean, request, boundary)
    assert all(not entries for entries in calls.values())  # noqa: S101


@pytest.mark.parametrize("boundary", ["builder", "decoder"])
@pytest.mark.parametrize("entry", ["model", "mapping"])
@pytest.mark.parametrize(
    "path",
    ["", "payload", "payload.baseline_reference", "payload.baseline_reference.quality_review"],
)
def test_unknown_closed_fields_are_not_dropped(clean, path, entry, boundary, monkeypatch):
    request = clean[0].request
    target = request
    for name in path.split(".") if path else []:
        target = getattr(target, name)
    bad = target.model_copy(update={"unexpected": "secret-marker" * 100000})
    if entry == "mapping":
        bad = {**vars(target), "unexpected": "secret-marker" * 100000}
    # Top-level exact-class contract is deliberately retained.
    request = copied(request, path, bad) if path else bad
    calls = observe_work(monkeypatch)
    code = "BASELINE_SOURCE_INVALID" if boundary == "builder" else "HISTORICAL_SNAPSHOT_INVALID"
    with pytest.raises(dto.HistoricalAIError, match="^" + code + "$"):
        invoke(clean, request, boundary)
    assert all(not entries for entries in calls.values())  # noqa: S101


@pytest.mark.parametrize("boundary", ["builder", "decoder"])
@pytest.mark.parametrize(
    "path",
    [
        "payload",
        "payload.baseline_reference",
        "payload.baseline_reference.quality_review",
        "payload.baseline_reference.quality_review.note",
    ],
)
@pytest.mark.parametrize("count", [0, 1, 1048577])
@pytest.mark.parametrize("kind", [list, tuple])
def test_request_has_no_array_slots_and_does_not_visit_members(
    clean, path, count, kind, boundary, monkeypatch
):
    bad = kind(["ordinary member"] * count)
    request = copied(clean[0].request, path, bad)
    calls = observe_work(monkeypatch)
    code = "BASELINE_SOURCE_INVALID" if boundary == "builder" else "HISTORICAL_SNAPSHOT_INVALID"
    with pytest.raises(dto.HistoricalAIError, match="^" + code + "$"):
        invoke(clean, request, boundary)
    assert all(not entries for entries in calls.values())  # noqa: S101
    assert len(bad) == count  # noqa: S101


@pytest.mark.parametrize("shape", ["width", "missing", "integer-key", "cycle"])
def test_raw_nested_mapping_is_closed_without_copy(clean, shape, monkeypatch):
    original = clean[0].request
    raw = original.payload.baseline_reference.quality_review.to_mapping()
    if shape == "width":
        raw.update({str(i): "unused" for i in range(10000)})
    elif shape == "missing":
        raw.pop("note")
    elif shape == "integer-key":
        raw[1] = raw.pop("note")
    else:
        raw["note"] = raw
    request = copied(original, "payload.baseline_reference.quality_review", raw)
    calls = observe_work(monkeypatch)
    with pytest.raises(dto.HistoricalAIError, match="^BASELINE_SOURCE_INVALID$"):
        invoke(clean, request, "builder")
    # Missing required data is bounded and is still rejected authoritatively.
    if shape != "missing":
        assert all(not entries for entries in calls.values())  # noqa: S101


@pytest.mark.parametrize(
    "mutation", ["none", "fingerprint", "mode", "review-control", "review-range"]
)
def test_authoritative_validation_and_fingerprint_are_not_replaced(clean, mutation, monkeypatch):
    original = clean[0].request
    request = original
    if mutation == "fingerprint":
        request = copied(original, "request_fingerprint", "b" * 64)
    elif mutation == "mode":
        request = copied(original, "payload.analysis_kind", "DDOS_ATTACK")
    elif mutation == "review-control":
        request = copied(original, "payload.baseline_reference.quality_review.note", "bad\nline")
    elif mutation == "review-range":
        request = copied(
            original, "payload.baseline_reference.quality_review.clock_offset_bound_ms", 2001
        )
    calls = observe_work(monkeypatch)
    validated = []
    real = dto.HistoricalAdmissionRequest.model_validate_json

    def validate(raw, *args, **kwargs):
        validated.append(raw)
        return real(raw, *args, **kwargs)

    monkeypatch.setattr(dto.HistoricalAdmissionRequest, "model_validate_json", validate)
    if mutation == "none":
        result = dto.checked_request(request)
        assert result == original and result is not original  # noqa: S101
        assert calls["copy"] and calls["fingerprint"]  # noqa: S101
    else:
        with pytest.raises(ValueError):
            dto.checked_request(request)
        if mutation == "fingerprint":
            assert calls["fingerprint"]  # noqa: S101
    assert len(validated) == 1 and calls["encoding"]  # noqa: S101
    assert original == clean[0].request  # noqa: S101


@pytest.mark.parametrize("entry", ["models", "mapping", "defaults"])
def test_normal_revalidation_preserves_bytes_order_types_and_detaches(clean, entry):
    original = clean[0].request
    before = json.dumps(original, ensure_ascii=False, allow_nan=False, default=dto._model_json)
    raw = original.payload.to_mapping()
    if entry == "defaults":
        for name in ("candidate_limit", "analysis_kind", "language", "allow_remote"):
            raw.pop(name)
    request = original if entry == "models" else copied(original, "payload", raw)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        admitted = dto.checked_request(request)
        assert admitted == original  # noqa: S101
        assert admitted.to_mapping() == original.to_mapping()  # noqa: S101
        assert admitted.model_dump(mode="python") == original.model_dump(mode="python")  # noqa: S101
        assert (  # noqa: S101 - pytest assertion.
            json.dumps(admitted, ensure_ascii=False, allow_nan=False, default=dto._model_json)
            == before
        )
    assert caught == []  # noqa: S101
    raw["baseline_reference"]["quality_review"]["note"] = "changed by caller"
    assert admitted == original  # noqa: S101
    assert type(admitted.payload.baseline_reference.quality_review.clock_offset_bound_ms) is int  # noqa: S101


@pytest.mark.parametrize("entry", ["utc", "offset", "text", "long-fraction"])
def test_datetime_accepted_representation_is_unchanged(clean, entry):
    original = clean[0].request
    date = original.admitted_at
    if entry == "offset":
        date = date.astimezone(timezone(timedelta(hours=9)))
    elif entry == "text":
        date = "2026-01-06T09:00:00.000000+09:00"
    elif entry == "long-fraction":
        date = "2026-01-06T00:00:00." + "0" * 1000 + "Z"
    assert original.admitted_at == datetime(2026, 1, 6, tzinfo=UTC)  # noqa: S101
    assert dto.checked_request(copied(original, "admitted_at", date)) == original  # noqa: S101


def test_original_seed_and_canonical_producer_digest_match_unchanged576(clean):
    value, saved, commitment = clean
    # Independently recorded in unchanged576-accepted10, before the repair.
    assert commitment == "626717d6b6d24d749579f614e7dde14277d56dead8223203c9dcdd59e6f648c2"  # noqa: S101
    assert hashlib.sha256(saved.encode()).hexdigest() == commitment  # noqa: S101
    rebuilt = builder.build_historical_snapshot(value)
    assert h.canonical_json(rebuilt.to_mapping()) == saved  # noqa: S101
    decoded = dto.decode_historical_snapshot(
        saved, request=value.request, expected_snapshot_sha256=commitment
    )
    assert len(decoded) == len(rebuilt.admitted_bundles)  # noqa: S101
