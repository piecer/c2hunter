"""R3: raw collection counts precede real member validation."""

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import rule, world


@pytest.fixture(scope="module")
def admission_fields():
    return world()


@pytest.mark.parametrize("count", [1, 2048, 2049])
@pytest.mark.parametrize("kind", [list, tuple])
@pytest.mark.parametrize("entry", ["constructor", "mapping", "instance"])
def test_candidate_count_before_copy_and_hydration(
    admission_fields, count, kind, entry, monkeypatch
):
    rows = kind(h.project_candidate(rule(identifier=f"r{i}"), position=i) for i in range(count))
    fields = {**admission_fields, "candidates": rows}
    if entry == "instance":
        value = dto.HistoricalAdmissionInput(**admission_fields).model_copy(
            update={"candidates": rows}
        )
    visits = []
    actual = h._validate_candidate_fields

    def observed(item):
        visits.append(1)
        return actual(item)

    monkeypatch.setattr(h, "_validate_candidate_fields", observed)

    def construct():
        if entry == "constructor":
            return dto.HistoricalAdmissionInput(**fields)
        return dto.HistoricalAdmissionInput.model_validate(value if entry == "instance" else fields)

    if count > 2048:
        with pytest.raises(ValueError):
            construct()
        assert visits == []  # noqa: S101 - pytest assertion, not an authorization guard.
    else:
        result = construct()
        assert len(result.candidates) == count  # noqa: S101 - pytest assertion, not an authorization guard.
        assert len(visits) == count  # noqa: S101 - pytest assertion, not an authorization guard.
        assert type(result.candidates) is tuple  # noqa: S101 - pytest assertion, not an authorization guard.


def test_malformed_present_candidate_collection_is_static(admission_fields):
    with pytest.raises(ValueError, match="BASELINE_SOURCE_INVALID"):
        dto.HistoricalAdmissionInput(**{**admission_fields, "candidates": {}})
