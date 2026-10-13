"""Actual default-separator request budgets and legal boundary controls.

Meter-only escaping cases are not claims that control characters are legal
Identifier/ReasonText values. Authoritative validators retain those refusals.
"""

import hashlib
import json

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as builder
from c2hunter_controller import historical_baseline as h
from tests import test_historical_ai_repair_request_admission as admission
from tests.test_historical_ai_repair_request_contract import invoke, observe_work

clean = admission.clean
copied = admission.copied


def actual_encoding(request, *, compact=False):
    options = {"separators": (",", ":")} if compact else {}
    return json.dumps(
        request, ensure_ascii=False, allow_nan=False, default=dto._model_json, **options
    )


def observe_budget(monkeypatch):
    seen = []
    real = dto._CanonicalBudget

    class ObservedBudget(real):
        def __init__(self, limit):
            super().__init__(limit)
            seen.append(self)

    monkeypatch.setattr(dto, "_CanonicalBudget", ObservedBudget)
    return seen


@pytest.mark.parametrize(
    "text",
    ["", "plain", "é", "한", "🦉", '"\\', "\b\f\n\r\t", "\x00\x1f", "\u2028\u2029", '한🦉"\\\x01'],
    ids=[
        "empty",
        "ascii",
        "two-byte",
        "korean",
        "non-bmp",
        "quote-slash",
        "short-controls",
        "long-controls",
        "separators",
        "mixed",
    ],
)
@pytest.mark.parametrize("raw_mapping", [False, True])
def test_meter_only_corpus_matches_actual_default_separators(clean, text, raw_mapping, monkeypatch):
    request = copied(clean[0].request, "payload.baseline_reference.quality_review.note", text)
    if raw_mapping:
        request = copied(request, "payload", request.payload.to_mapping())
    expected = len(actual_encoding(request).encode())
    compact = len(actual_encoding(request, compact=True).encode())
    observed = observe_budget(monkeypatch)
    dto._request_preflight(request)
    assert len(observed) == 1  # noqa: S101
    assert observed[0].size == expected and expected > compact  # noqa: S101


@pytest.mark.parametrize("revision", [0, 2**63 - 1])
@pytest.mark.parametrize("boolean", [False, True])
@pytest.mark.parametrize("reviewed", [False, True])
def test_meter_numeric_null_and_boolean_tokens(clean, revision, boolean, reviewed, monkeypatch):
    request = copied(clean[0].request, "payload.baseline_reference.expected_revision", revision)
    request = copied(request, "payload.allow_remote", boolean)
    if not reviewed:
        request = copied(request, "payload.baseline_reference.quality_review", None)
    observed = observe_budget(monkeypatch)
    dto._request_preflight(request)
    assert observed[0].size == len(actual_encoding(request).encode())  # noqa: S101


@pytest.mark.parametrize("boundary", ["checked", "builder", "decoder"])
@pytest.mark.parametrize("excess", [0, 1])
def test_legal_long_fraction_attains_exact_request_budget(clean, boundary, excess, monkeypatch):
    original = clean[0].request
    prefix = "2026-01-06T00:00:00."
    short = copied(original, "admitted_at", prefix + "0Z")
    padding = 16384 - len(actual_encoding(short).encode())
    request = copied(original, "admitted_at", prefix + "0" * (1 + padding + excess) + "Z")
    encoded = actual_encoding(request)
    assert len(encoded.encode()) == 16384 + excess  # noqa: S101
    # Existing _utc/fromisoformat and the real authoritative request validator
    # accept arbitrary trailing zero fractional precision without new fields.
    assert dto.HistoricalAdmissionRequest.model_validate_json(encoded) == original  # noqa: S101
    calls = observe_work(monkeypatch)
    if excess:
        code = "HISTORICAL_SNAPSHOT_INVALID" if boundary == "decoder" else "BASELINE_SOURCE_LIMIT"
        with pytest.raises(dto.HistoricalAIError, match="^" + code + "$"):
            if boundary == "checked":
                dto.checked_request(request)
            else:
                invoke(clean, request, boundary)
        assert all(not entries for entries in calls.values())  # noqa: S101
    else:
        if boundary == "checked":
            assert dto.checked_request(request) == original  # noqa: S101
        else:
            result = invoke(clean, request, boundary)
            assert result is not None  # noqa: S101
            if boundary == "builder":
                assert h.canonical_json(result.to_mapping()) == clean[1]  # noqa: S101
        assert calls["encoding"] and calls["fingerprint"]  # noqa: S101


@pytest.mark.parametrize("character", ["x", "é", "한", "🦉", '"', "\\", "\u2028"])
def test_maximal_legal_identifier_and_note_controls_reach_both_public_paths(clean, character):
    value, _, _ = clean
    original = value.request
    request = original
    for path in (
        "actor",
        "provider",
        "model_name",
        "prompt_name",
        "prompt_version",
        "payload.idempotency_key",
    ):
        request = copied(request, path, character * 200)
    request = copied(request, "payload.baseline_reference.quality_review.note", character * 512)
    fingerprint = dto.request_fingerprint(request.analysis_job_id, request.actor, request.payload)
    request = copied(request, "request_fingerprint", fingerprint)
    # Real validation, not a claim that a changed model_copy was already valid.
    request = dto.checked_request(request)
    snapshot = builder.build_historical_snapshot(value.model_copy(update={"request": request}))
    saved = h.canonical_json(snapshot.to_mapping())
    commitment = hashlib.sha256(saved.encode()).hexdigest()
    result = dto.decode_historical_snapshot(
        saved, request=request, expected_snapshot_sha256=commitment
    )
    assert len(result) == len(snapshot.admitted_bundles)  # noqa: S101
    assert snapshot.baseline_request == request.payload  # noqa: S101
    assert value.request == original  # noqa: S101


def test_normalized_closed_request_has_a_structural_ceiling_below_16k(clean, monkeypatch):
    request = clean[0].request
    identifier_paths = (
        "analysis_job_id",
        "actor",
        "provider",
        "model_name",
        "prompt_name",
        "prompt_version",
        "payload.idempotency_key",
    )
    for path in identifier_paths:
        request = copied(request, path, "🦉" * 200)
    request = copied(request, "payload.baseline_reference.quality_review.note", "🦉" * 512)
    request = copied(request, "payload.baseline_reference.expected_revision", 2**63 - 1)
    request = copied(
        request, "payload.baseline_reference.quality_review.clock_offset_bound_ms", 2000
    )
    request = copied(
        request,
        "request_fingerprint",
        dto.request_fingerprint(request.analysis_job_id, request.actor, request.payload),
    )
    request = dto.HistoricalAdmissionRequest.model_validate_json(actual_encoding(request))
    observed = observe_budget(monkeypatch)
    dto._request_preflight(request)
    size = len(actual_encoding(request).encode())
    # All seven Identifier maxima and ReasonText max use the largest legal UTF-8
    # width (4); legal escaping costs at most2. UUIDs/digests/literals/UTC output
    # have fixed widths; revision has19 digits, clock4, candidate_limit1.
    assert (  # noqa: S101 - pytest assertion.
        len(identifier_paths) == 7
        and all(len(getattr(request, name)) == 200 for name in identifier_paths[:6])
    )
    assert observed[0].size == size < 16384  # noqa: S101
    assert len(request.payload.baseline_reference.quality_review.note) == 512  # noqa: S101
