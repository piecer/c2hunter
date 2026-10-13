"""A4 semantic regressions: unchanged reviewer wires and actual producer bytes.

The JSON corpus maps every original RED identity to its exact saved envelope.
Decoder tests require structural validation, not a later expected-row mismatch.
No source lookup, producer substitute, or worker/model invocation is involved.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import historical_evidence as h

FIXTURES = Path(__file__).parent / "fixtures"
CASES = json.loads((FIXTURES / "historical_evidence_semantic_cases.json").read_text())
PRODUCER = json.loads((FIXTURES / "historical_evidence_producer_cases.json").read_text())
PRODUCER += json.loads((FIXTURES / "historical_evidence_temporal_producer_cases.json").read_text())
CASE_IDS = [case["finding"] + "-" + case["original_case"] for case in CASES]
FAMILIES = ("recurrence", "size_dispersion", "outbound_share")


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


def parse_reference(ref):
    cls = h.UsableReference if ref["availability"] == "USABLE" else h.UnusableReference
    return cls.model_validate_json(canonical(ref))


def reference_of(saved):
    return json.loads(saved["canonical_json"])["historical_reference"]


def checked_envelope(saved):
    encoded = saved["canonical_json"].encode()
    assert canonical(json.loads(saved["canonical_json"])) == saved["canonical_json"]
    assert saved["metadata"]["canonical_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert saved["metadata"]["byte_size"] == len(encoded)
    assert saved["metadata"]["estimated_tokens"] == (len(encoded) + 2) // 3


def decode(saved, *, comparisons=()):
    ref = reference_of(saved)
    raw = json.loads(saved["canonical_json"])
    return h.decode_admitted_bundle(
        saved,
        expected_candidate_id=saved["candidate_id"],
        facts=h.ReferenceFacts.model_validate_json(canonical(ref["facts"])),
        comparisons=comparisons,
        source_references=tuple(h.CompactSourceReference(**s) for s in ref["source_references"]),
        local_warnings=tuple(raw["evidence"][0]["metrics"]["local_warnings"]),
    )


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_original_semantic_wire_rejected_by_ordinary_constructor(case):
    saved = case["saved"]
    checked_envelope(saved)
    with pytest.raises(ValidationError):
        parse_reference(reference_of(saved))


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_original_semantic_wire_rejected_typed_before_row_reconciliation(case):
    saved = case["saved"]
    checked_envelope(saved)
    with pytest.raises(h.HistoricalEvidenceError) as exc:
        decode(saved)
    assert exc.value.code == "HISTORICAL_SNAPSHOT_INVALID"
    # Empty expected rows deliberately cannot excuse poison: rejection MUST be
    # the saved body's semantic validator, before expected-row reconciliation.
    assert isinstance(exc.value.__cause__, ValidationError)


@pytest.mark.parametrize("case", PRODUCER, ids=[c["case"] for c in PRODUCER])
def test_frozen_actual_producer_bytes_roundtrip(case):
    assert case["producer_sha256"] == (
        "aab2e569a96b748fa000c3dea91f74c1997859571540a6f729c92bafd999e20d"
    )
    saved = case["admitted"]
    checked_envelope(saved)
    rows = tuple(
        h.ProfileComparison.model_validate_json(canonical(row))
        for row in case["mapping"]["comparisons"]
    )
    restored = decode(saved, comparisons=rows)
    assert ai.canonical_bundle_json(restored) == saved["canonical_json"]
    assert restored.metadata.model_dump(mode="json") == saved["metadata"]


def positive():
    return deepcopy(next(c["admitted"] for c in PRODUCER if c["case"] == "agreement"))


def save_raw(saved, raw):
    saved = deepcopy(saved)
    saved["canonical_json"] = canonical(raw)
    encoded = saved["canonical_json"].encode()
    saved["metadata"].update(
        canonical_sha256=hashlib.sha256(encoded).hexdigest(),
        byte_size=len(encoded),
        estimated_tokens=(len(encoded) + 2) // 3,
    )
    return saved


def roundtrip_reference(ref):
    parsed = parse_reference(ref)
    saved = positive()
    raw = json.loads(saved["canonical_json"])
    raw["historical_reference"] = ref
    saved = save_raw(saved, raw)
    rows = (parsed.comparison,) if parsed.comparison is not None else ()
    assert ai.canonical_bundle_json(decode(saved, comparisons=rows)) == saved["canonical_json"]
    local = ai.build_unfinalized_evidence_bundle(
        {"id": saved["candidate_id"], "candidate_ip": "203.0.113.91", "score": 80}
    )
    finalized = h.finalize_historical_bundle(
        local,
        reference=parsed,
        factors=(),
        source_references=parsed.source_references,
        local_warnings=(),
    )
    assert finalized.historical_reference.model_dump(mode="json") == ref
    return parsed


def unavailable(ref, status="INCOMPATIBLE"):
    row = ref["comparison"]
    row["status"] = status
    row["historical_anomaly_score"] = 0.0
    for feature in row["features"].values():
        feature.update(
            status=status,
            reference_median=None,
            reference_scale=None,
            robust_z=None,
            drifting=False,
        )
        if status in {"INCOMPATIBLE", "MISSING"}:
            feature["eligible_window_ids"] = []
    row["source_window_ids"] = sorted(
        {wid for f in row["features"].values() for wid in f["eligible_window_ids"]}
    )
    ref["source_references"] = [
        s for s in ref["source_references"] if s["source_receipt_id"] in row["source_window_ids"]
    ]
    ref.update(availability="UNUSABLE", cause="COMPARISON_UNAVAILABLE", historical_factor_types=[])
    return ref


@pytest.mark.parametrize(
    "reason",
    [
        "TRUSTED_PEERS_EXCLUDED",
        "COMMON_SERVICES_EXCLUDED",
        "SERVICE_PORT_UNAVAILABLE",
        "INSUFFICIENT_STREAM_SAMPLES",
        "PACKET_TIMING_UNAVAILABLE",
        "DIRECTION_BALANCE_UNAVAILABLE",
    ],
)
def test_unrelated_stream_reason_does_not_veto_selected_profile(reason):
    ref = reference_of(positive())
    ref["facts"]["limitations"] = sorted(set(ref["facts"]["limitations"]) | {reason})
    assert roundtrip_reference(ref).comparison.status == "READY"


@pytest.mark.parametrize(
    "reason",
    [
        "TARGET_REVIEW_REQUIRED",
        "TARGET_PARTIAL_CAPTURE",
        "SOURCE_CLOCK_UNCERTAIN",
        "INSUFFICIENT_STREAM_SAMPLES",
    ],
)
def test_legal_veto_retains_measured_current_without_reference_claims(reason):
    ref = reference_of(positive())
    currents = [f["current"] for f in ref["comparison"]["features"].values()]
    unavailable(ref)
    ref["comparison"]["limitations"] = sorted(set(ref["comparison"]["limitations"]) | {reason})
    ref["facts"]["limitations"] = sorted(set(ref["facts"]["limitations"]) | {reason})
    parsed = roundtrip_reference(ref)
    assert [f.current for f in parsed.comparison.features.ordered()] == [0.0, 0.8, 0.5]
    assert sorted(currents) == sorted([0.0, 0.8, 0.5])
    assert parsed.comparison.historical_anomaly_score == 0
    assert parsed.source_references == ()


@pytest.mark.parametrize("cause", ["NO_PROFILE", "COMMUNICATION_STATUS"])
@pytest.mark.parametrize(
    "reason",
    [
        "TARGET_REVIEW_REQUIRED",
        "TARGET_PARTIAL_CAPTURE",
        "SOURCE_CLOCK_UNCERTAIN",
    ],
)
def test_global_veto_preserves_null_comparison_forms(cause, reason):
    ref = reference_of(positive())
    ref.update(
        availability="UNUSABLE",
        cause=cause,
        comparison=None,
        source_references=[],
        historical_factor_types=[],
    )
    ref["facts"]["limitations"] = sorted(set(ref["facts"]["limitations"]) | {reason})
    assert parse_reference(ref).comparison is None


def stamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def timed_reference(*, age, span, count=3, status="READY"):
    ref = reference_of(positive())
    cutoff = datetime.fromisoformat(ref["facts"]["target_event_start"])
    newest = cutoff - age
    oldest = newest - span
    refs = ref["source_references"][:count]
    for i, source in enumerate(refs):
        end = newest - timedelta(seconds=(count - 1 - i) * 60)
        start = oldest if i == 0 else end - timedelta(seconds=1)
        source.update(event_start=stamp(start), event_end=stamp(end))
    ref["source_references"] = refs
    ids = [s["source_receipt_id"] for s in refs]
    ref["comparison"]["source_window_ids"] = ids
    for f in ref["comparison"]["features"].values():
        f["eligible_window_ids"] = ids
    if status != "READY":
        unavailable(ref, status)
    return ref


@pytest.mark.parametrize("axis", ["age", "span"])
@pytest.mark.parametrize("microseconds", [-1, 0, 1])
def test_saved_temporal_inclusive_boundaries(axis, microseconds):
    age = (
        timedelta(days=7) + timedelta(microseconds=microseconds)
        if axis == "age"
        else timedelta(days=1)
    )
    span = (
        timedelta(days=1) + timedelta(microseconds=microseconds)
        if axis == "span"
        else timedelta(days=2)
    )
    status = (
        "STALE"
        if axis == "age" and microseconds > 0
        else ("INSUFFICIENT" if axis == "span" and microseconds < 0 else "READY")
    )
    assert (
        roundtrip_reference(timed_reference(age=age, span=span, status=status)).comparison.status
        == status
    )


@pytest.mark.parametrize(
    "age,span,count,wrong",
    [
        (timedelta(days=7, microseconds=1), timedelta(days=2), 3, "READY"),
        (timedelta(days=7), timedelta(days=2), 3, "STALE"),
        (timedelta(days=1), timedelta(days=1, microseconds=-1), 3, "READY"),
        (timedelta(days=1), timedelta(days=1), 3, "INSUFFICIENT"),
        (timedelta(days=8), timedelta(hours=1), 1, "INSUFFICIENT"),
        (timedelta(days=8), timedelta(hours=1), 3, "INSUFFICIENT"),
        (timedelta(days=1), timedelta(hours=1), 1, "STALE"),
    ],
    ids=[
        "stale-ready",
        "inclusive-seven-stale",
        "short-ready",
        "inclusive-span-insufficient",
        "stale-before-count",
        "stale-before-span",
        "fresh-short-stale",
    ],
)
def test_false_temporal_status_rejected_from_saved_receipts(age, span, count, wrong):
    ref = timed_reference(age=age, span=span, count=count, status=wrong)
    with pytest.raises(ValidationError):
        parse_reference(ref)
    saved = positive()
    raw = json.loads(saved["canonical_json"])
    raw["historical_reference"] = ref
    with pytest.raises(h.HistoricalEvidenceError) as exc:
        decode(save_raw(saved, raw))
    assert exc.value.code == "HISTORICAL_SNAPSHOT_INVALID"
    assert isinstance(exc.value.__cause__, ValidationError)


@pytest.mark.parametrize("count", [1, 2, 3])
def test_stale_precedes_short_span_and_count(count):
    ref = timed_reference(
        age=timedelta(days=8), span=timedelta(hours=1), count=count, status="STALE"
    )
    assert roundtrip_reference(ref).comparison.status == "STALE"


def test_ready_only_newest_must_be_fresh_and_span_uses_oldest_start():
    ref = timed_reference(age=timedelta(days=1), span=timedelta(days=10))
    # Even an old *end* may be stale; freshness is the newest end only.
    oldest = ref["source_references"][0]
    oldest["event_end"] = stamp(
        datetime.fromisoformat(oldest["event_start"]) + timedelta(seconds=1)
    )
    assert roundtrip_reference(ref).comparison.status == "READY"
    # At 24h, end-to-end span is <24h, but newest-end to oldest-start is enough.
    ref = timed_reference(age=timedelta(days=1), span=timedelta(days=1))
    assert roundtrip_reference(ref).comparison.status == "READY"


@pytest.mark.parametrize("condition", ["stale", "short"])
@pytest.mark.parametrize("poison", [False, True])
def test_each_family_uses_its_own_receipt_times_not_union(condition, poison):
    ref = timed_reference(
        age=timedelta(days=8 if condition == "stale" else 1),
        span=timedelta(days=2) if condition == "stale" else timedelta(hours=1),
    )
    original = ref["source_references"]
    other = reference_of(positive())["source_references"]
    for i, source in enumerate(other):
        source["source_receipt_id"] = f"20000000-0000-0000-0000-{i:012d}"
    ref["source_references"] = original + other
    row = ref["comparison"]
    for family in ("size_dispersion", "outbound_share"):
        row["features"][family]["eligible_window_ids"] = [s["source_receipt_id"] for s in other]
    row["source_window_ids"] = sorted(s["source_receipt_id"] for s in ref["source_references"])
    if poison:
        with pytest.raises(ValidationError):
            parse_reference(ref)
    else:
        row["features"]["recurrence"].update(
            status="STALE" if condition == "stale" else "INSUFFICIENT",
            reference_median=None,
            reference_scale=None,
            robust_z=None,
            drifting=False,
        )
        assert roundtrip_reference(ref).comparison.status == "READY"


@pytest.mark.parametrize(
    "reason",
    [
        "TARGET_REVIEW_REQUIRED",
        "TARGET_PARTIAL_CAPTURE",
        "SOURCE_CLOCK_UNCERTAIN",
    ],
)
@pytest.mark.parametrize("status", ["missing", "stale", "insufficient"])
def test_global_veto_requires_incompatible_even_without_positive_factors(reason, status):
    ref = reference_of(next(c["admitted"] for c in PRODUCER if c["case"] == status))
    ref["facts"]["limitations"] = sorted(set(ref["facts"]["limitations"]) | {reason})
    with pytest.raises(ValidationError):
        parse_reference(ref)


@pytest.mark.parametrize("value", [0.0, 1.0])
def test_share_domain_endpoints_remain_valid(value):
    ref = reference_of(positive())
    ref["comparison"]["features"]["outbound_share"].update(current=value, reference_median=value)
    assert roundtrip_reference(ref).comparison.features.outbound_share.current == value


def test_family_eligible_plus_future_exact_limit():
    ref = reference_of(positive())
    ref["comparison"]["features"]["recurrence"]["excluded_future_count"] = 13
    assert roundtrip_reference(ref).comparison.features.recurrence.excluded_future_count == 13


def test_null_measurements_preserve_whole_profile_missing_precedence():
    ref = reference_of(next(c["admitted"] for c in PRODUCER if c["case"] == "missing"))
    row = ref["comparison"]
    row["key"]["observation_kind"] = "AGGREGATE"
    row["features"]["recurrence"]["current"] = None
    row["features"]["outbound_share"]["current"] = None
    for obj in (row, ref["facts"]):
        obj["limitations"] = sorted(
            set(obj["limitations"])
            | {
                "PACKET_TIMING_UNAVAILABLE",
                "DIRECTION_BALANCE_UNAVAILABLE",
            }
        )
    assert roundtrip_reference(ref).comparison.status == "MISSING"


def test_nonfinite_feature_unavailable_is_not_inferred_ready_from_receipts():
    ref = reference_of(positive())
    feature = ref["comparison"]["features"]["recurrence"]
    feature.update(
        status="INCOMPATIBLE",
        reference_median=None,
        reference_scale=None,
        robust_z=None,
        drifting=False,
        eligible_window_ids=[],
    )
    reason = "NONFINITE_FEATURE_UNAVAILABLE"
    for obj in (ref["facts"], ref["comparison"]):
        obj["limitations"] = sorted(set(obj["limitations"]) | {reason})
    assert roundtrip_reference(ref).comparison.features.recurrence.current == 0.0
