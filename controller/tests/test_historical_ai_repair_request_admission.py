"""SS-C1-01: ordinary copied seeds are admitted before scalar encoding."""

import hashlib
import json

import pytest

from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as builder
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import world


@pytest.fixture(scope="module")
def clean():
    value = dto.HistoricalAdmissionInput(**world())
    snapshot = builder.build_historical_snapshot(value)
    saved = h.canonical_json(snapshot.to_mapping())
    return value, saved, hashlib.sha256(saved.encode()).hexdigest()


def copied(request, path, value):
    name, *rest = path.split(".", 1)
    child = copied(getattr(request, name), rest[0], value) if rest else value
    return request.model_copy(update={name: child})


@pytest.mark.parametrize(
    ("boundary", "path", "character", "length"),
    [
        ("builder", "actor", "x", 2097152),
        ("builder", "actor", "한", 1048577),
        ("decoder", "actor", "한", 1048577),
        ("builder", "payload.baseline_reference.quality_review.note", "한", 1048577),
        ("decoder", "payload.baseline_reference.quality_review.note", "한", 1048577),
    ],
)
@pytest.mark.parametrize("oversized", [False, True])
def test_copied_seed_scalar_is_gated_before_encoding(
    clean, boundary, path, character, length, oversized, monkeypatch
):
    value, saved, commitment = clean
    original = value.request
    scalar = original
    for name in path.split("."):
        scalar = getattr(scalar, name)
    if oversized:
        scalar = character * length
    request = copied(original, path, scalar) if oversized else original
    encoded = []
    selected = []
    encoder = json.encoder.encode_basestring
    selector = ai_discovery.select_shadow_candidates

    def observe(text):
        if text is scalar:
            encoded.append(len(text))
        return encoder(text)

    def select(*args, **kwargs):
        selected.append(1)
        return selector(*args, **kwargs)

    monkeypatch.setattr(json.encoder, "encode_basestring", observe)
    monkeypatch.setattr(ai_discovery, "select_shadow_candidates", select)

    def invoke():
        if boundary == "builder":
            return builder.build_historical_snapshot(value.model_copy(update={"request": request}))
        return dto.decode_historical_snapshot(
            saved, request=request, expected_snapshot_sha256=commitment
        )

    if oversized:
        code = "BASELINE_SOURCE_LIMIT" if boundary == "builder" else "HISTORICAL_SNAPSHOT_INVALID"
        with pytest.raises(dto.HistoricalAIError, match="^" + code + "$"):
            invoke()
        assert encoded == []  # noqa: S101
        assert selected == []  # noqa: S101
    else:
        assert invoke() is not None  # noqa: S101
        assert encoded  # noqa: S101
        assert selected == ([1] if boundary == "builder" else [])  # noqa: S101
    assert request.request_fingerprint == original.request_fingerprint  # noqa: S101
    assert hashlib.sha256(saved.encode()).hexdigest() == commitment  # noqa: S101
