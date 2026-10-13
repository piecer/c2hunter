"""A4 wire fixtures, not execution of the separately owned pure producer."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

import c2hunter_controller.ai_analysis as ai
import c2hunter_controller.historical_evidence as history
from c2hunter_controller.ai_analysis import (
    CandidateEvidenceBundle,
    build_evidence_bundle,
    canonical_bundle_json,
)

ASSERTIONS = sorted(
    [
        "ADMIN_ASSERTED_IDENTITY",
        "PRODUCER_COMPLETENESS_UNKNOWN",
        "RETROSPECTIVE_NOT_AS_WAS",
        "HISTORY_MATCH_IS_NOT_BENIGN",
        "PEER_PRIMARY_STREAM_ONLY",
    ]
)


def candidate():
    return {"id": "rule-1", "candidate_ip": "203.0.113.7", "score": 42}


def facts():
    return {
        "schema_version": "historical-baseline-v1",
        "scope_id": "00000000-0000-0000-0000-000000000001",
        "scope_kind": "EVALUATION",
        "scope_config_sha256": "a" * 64,
        "scope_revision": 0,
        "scope_state": "EMPTY",
        "frozen_at_admission": False,
        "generation_id": None,
        "generation_sha256": None,
        "target_source_binding_sha256": "b" * 64,
        "target_event_start": "2026-10-09T00:00:00.000000Z",
        "target_event_end": "2026-10-09T00:01:00.000000Z",
        "admitted_at": "2026-10-10T00:00:00.000000Z",
        "comparison_semantics": "RETROSPECTIVE_APPROVED_REFERENCE",
        "identity_assurance": "ADMIN_ASSERTED",
        "quality_assurance": "UNREVIEWED",
        "producer_completeness": "UNKNOWN",
        "limitations": ASSERTIONS,
    }


def no_profile():
    return {
        "availability": "UNUSABLE",
        "facts": facts(),
        "cause": "NO_PROFILE",
        "comparison": None,
        "source_references": [],
        "historical_factor_types": [],
    }


def test_off_exact_baseline_bytes_and_null_aliases():
    bundle = build_evidence_bundle(candidate())
    assert hashlib.sha256(canonical_bundle_json(bundle).encode()).hexdigest() == (
        "685f95cb93b95fd6ae961d271e1756e9f0d07fd1fb925fbf5bb0304b38b4e20f"
    )
    assert hashlib.sha256(bundle.model_dump_json(by_alias=True).encode()).hexdigest() == (
        "e61c1f7bfa6f81c6c0a8c4e78b93ec6e26b25fc730e170ba75fe748d1b23253e"
    )
    assert hashlib.sha256(json.dumps(bundle.model_dump(), sort_keys=True).encode()).hexdigest() == (
        "a69f94f556a2c4e4521efda81a09eadfd4ae5a4c94447c68087f211135e1c2ab"
    )
    assert "historical_reference" not in bundle.model_dump()
    assert bundle.model_dump()["candidate"]["severity"] is None
    assert "summary" in bundle.model_dump(by_alias=True)["evidence"][0]


def test_no_profile_is_closed_valid_without_fabricated_comparison():
    raw = build_evidence_bundle(candidate()).model_dump(mode="json", by_alias=True)
    raw["historical_reference"] = no_profile()
    bundle = CandidateEvidenceBundle.model_validate_json(json.dumps(raw))
    assert bundle.model_dump(mode="json")["historical_reference"] == no_profile()
    for field, value in [("unexpected", 1), ("historical_factor_types", ["invented"])]:
        poisoned = json.loads(json.dumps(raw))
        poisoned["historical_reference"][field] = value
        with pytest.raises(ValueError):
            CandidateEvidenceBundle.model_validate_json(json.dumps(poisoned))


def sources():
    return [
        {
            "source_receipt_id": f"00000000-0000-0000-0000-{i:012d}",
            "source_job_id": f"source-{i}",
            "event_start": f"2026-10-0{i}T00:00:00.000000Z",
            "event_end": f"2026-10-0{i}T00:01:00.000000Z",
            "approved_at": "2026-10-08T00:00:00.000000Z",
            "source_binding_sha256": str(i) * 64,
        }
        for i in range(1, 4)
    ]


def comparison(drifting=2, port=443):
    ids = [s["source_receipt_id"] for s in sources()]
    features = {}
    for i, family in enumerate(("recurrence", "size_dispersion", "outbound_share")):
        z = 4.0 if i < drifting else 0.0
        features[family] = {
            "status": "READY",
            "current": 0.2 if z else 0.0,
            "reference_median": 0.0,
            "reference_scale": 0.05,
            "robust_z": z,
            "eligible_window_ids": ids,
            "excluded_future_count": 0,
            "drifting": bool(z),
        }
    return {
        "key": {
            "scope_config_sha256": "a" * 64,
            "sensor_key": "sensor",
            "internal_host_ip": "10.0.0.1",
            "host_epoch": "epoch-1",
            "peer_ip": "203.0.113.7",
            "protocol": "TCP",
            "service_port": port,
            "observation_kind": "PACKET",
            "feature_version": "behavior-window-v1",
        },
        "status": "READY",
        "limitations": [],
        "source_window_ids": ids,
        "features": features,
        "historical_anomaly_score": drifting * 14.0 if drifting >= 2 else 0.0,
    }


FACTOR_TYPES = [
    "BEHAVIOR_HISTORICAL_RECURRENCE_CHANGE",
    "BEHAVIOR_HISTORICAL_RECORD_SIZE_DISPERSION_CHANGE",
    "BEHAVIOR_HISTORICAL_DIRECTION_BALANCE_CHANGE",
]


def usable(drifting=2):
    f = facts()
    f.update(
        scope_state="HAS_REFERENCE",
        generation_id=f["scope_id"],
        generation_sha256="c" * 64,
        quality_assurance="ANALYST_ASSERTED",
        limitations=sorted([*ASSERTIONS, "HUMAN_ASSERTED_CLOCK_BOUND"]),
    )
    return {
        "availability": "USABLE",
        "facts": f,
        "comparison": comparison(drifting),
        "source_references": sources(),
        "historical_factor_types": sorted(FACTOR_TYPES[:drifting]) if drifting >= 2 else [],
    }


def parse_reference(reference):
    raw = build_evidence_bundle(candidate()).model_dump(mode="json", by_alias=True)
    raw["historical_reference"] = reference
    return CandidateEvidenceBundle.model_validate_json(json.dumps(raw))


@pytest.mark.parametrize("drifting", [0, 1, 2, 3])
def test_usable_ready_family_gate_and_finite_closed_wire(drifting):
    ref = usable(drifting)
    parsed = parse_reference(ref)
    assert parsed.model_dump(mode="json")["historical_reference"] == ref
    for path, value in [
        (("comparison", "selected"), True),
        (("comparison", "features", "recurrence", "robust_z"), float("nan")),
        (("comparison", "features", "recurrence", "reference_median"), None),
        (("comparison", "historical_anomaly_score"), 14.0),
        (("facts", "scope_revision"), True),
        (("source_references",), []),
    ]:
        bad = deepcopy(ref)
        target = bad
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        with pytest.raises(ValueError):
            parse_reference(bad)


def test_unavailable_retains_distinct_support_and_null_statistics():
    ref = usable(0)
    # Match the actual producer's stale target envelope (producer-stale.json).
    # The former October 9 target made October 3 support fresh, not STALE.
    ref["facts"]["target_event_start"] = "2026-10-15T00:00:00.000000Z"
    ref["facts"]["target_event_end"] = "2026-10-15T00:01:00.000000Z"
    ref["facts"]["admitted_at"] = "2026-10-16T00:01:00.000000Z"
    ref.update(availability="UNUSABLE", cause="COMPARISON_UNAVAILABLE")
    ref["comparison"]["status"] = "STALE"
    for feature in ref["comparison"]["features"].values():
        feature.update(status="STALE", reference_median=None, reference_scale=None, robust_z=None)
    ref["comparison"]["features"]["outbound_share"]["eligible_window_ids"] = []
    ref["comparison"]["features"]["outbound_share"]["status"] = "MISSING"
    assert parse_reference(ref).model_dump(mode="json")["historical_reference"] == ref
    ref["comparison"]["features"]["recurrence"]["drifting"] = True
    with pytest.raises(ValueError):
        parse_reference(ref)


def factor_items(ref):
    result = []
    for family, kind, suffix in zip(
        ("recurrence", "size_dispersion", "outbound_share"),
        FACTOR_TYPES,
        ("RECURRENCE", "SIZE", "DIRECTION"),
        strict=True,
    ):
        if kind not in ref["historical_factor_types"]:
            continue
        feature = ref["comparison"]["features"][family]
        result.append(
            ai.EvidenceItem(
                id=f"E-C2H-HIST-{suffix}",
                type=kind,
                summary=f"Pure fixture explanation: {family}",
                contribution=14.0,
                metrics={
                    **{
                        k: feature[k]
                        for k in ("current", "reference_median", "reference_scale", "robust_z")
                    },
                    "reference": f"/historical_reference/comparison/features/{family}",
                },
            )
        )
    return tuple(result)


def finalize(ref=None, *, source=None, warnings=("NO_HISTORICAL_BASELINE", "CLOCK_SKEW")):
    assert callable(getattr(history, "finalize_historical_bundle", None)), (
        "protected finalizer absent"
    )
    reference = parse_reference(ref or usable()).historical_reference
    assert callable(getattr(ai, "build_unfinalized_evidence_bundle", None)), (
        "prefinalized seam absent"
    )
    bundle = ai.build_unfinalized_evidence_bundle(source or candidate())
    return history.finalize_historical_bundle(
        bundle,
        reference=reference,
        factors=factor_items(ref or usable()),
        source_references=tuple(history.CompactSourceReference.model_validate(s) for s in sources())
        if reference.facts.generation_id is not None
        else (),
        local_warnings=warnings,
    )


def test_protected_finalizer_uses_prefinalized_builder_and_exact_sources(monkeypatch):
    assert callable(getattr(history, "finalize_historical_bundle", None)), (
        "protected finalizer absent"
    )
    # Parse fixtures before poisoning the unrelated legacy finalizer.
    ref = parse_reference(usable()).historical_reference
    monkeypatch.setattr(ai, "_finalize_bundle", lambda *_: pytest.fail("destructive legacy path"))
    source = candidate()
    source["evidence"] = [
        {"type": "BEHAVIOR_COVERAGE", "description": "History disabled"},
        {"type": "LOCAL", "description": "local", "metrics": {"a": 1}},
    ]
    original = ai.build_unfinalized_evidence_bundle(source)
    before = original.model_dump()
    result = history.finalize_historical_bundle(
        original,
        reference=ref,
        factors=factor_items(usable()),
        source_references=tuple(
            history.CompactSourceReference.model_validate(s) for s in sources()
        ),
        local_warnings=("NO_HISTORICAL_BASELINE", "CLOCK_SKEW"),
    )
    assert original.model_dump() == before
    assert [e.evidence_id for e in result.evidence[:3]] == [
        "E-C2H-HIST-COVERAGE",
        "E-C2H-HIST-RECURRENCE",
        "E-C2H-HIST-SIZE",
    ]
    assert result.evidence[0].metrics == {
        "reference": "/historical_reference",
        "local_warnings": ["CLOCK_SKEW"],
    }
    assert [e.evidence_type for e in result.evidence] == [
        "BEHAVIOR_COVERAGE",
        *FACTOR_TYPES[:2],
        "LOCAL",
    ]
    assert sum(e.contribution for e in result.evidence[1:3]) == 28
    for name in (
        "candidate",
        "all_flow_summary",
        "candidate_flow_summary",
        "data_quality",
        "safety_notice",
    ):
        assert getattr(result, name) == getattr(original, name)
    canonical = canonical_bundle_json(result).encode()
    assert result.metadata.canonical_sha256 == hashlib.sha256(canonical).hexdigest()
    assert result.metadata.byte_size == len(canonical)
    assert result.metadata.estimated_tokens == (len(canonical) + 2) // 3


def test_finalizer_rejects_missing_positive_factor_and_receipt_mismatch():
    assert callable(getattr(history, "finalize_historical_bundle", None)), (
        "protected finalizer absent"
    )
    ref = parse_reference(usable()).historical_reference
    original = ai.build_unfinalized_evidence_bundle(candidate())
    source_refs = tuple(history.CompactSourceReference.model_validate(s) for s in sources())
    kwargs = dict(
        reference=ref,
        factors=factor_items(usable()),
        source_references=source_refs,
        local_warnings=(),
    )
    for changes in [
        dict(factors=kwargs["factors"][:1]),
        dict(source_references=source_refs[:2]),
        dict(
            source_references=(
                source_refs[0].model_copy(update={"source_job_id": "other"}),
                *source_refs[1:],
            )
        ),
    ]:
        with pytest.raises(ValueError):
            history.finalize_historical_bundle(original, **{**kwargs, **changes})


def test_one_family_agreement_no_profile_and_communication_finalization():
    for ref in (usable(0), usable(1), no_profile()):
        result = finalize(ref)
        assert not any(e.evidence_type.startswith("BEHAVIOR_HISTORICAL_") for e in result.evidence)
    operational = no_profile()
    operational["cause"] = "COMMUNICATION_STATUS"
    source = {**candidate(), "candidate_kind": "COMMUNICATION_STATUS"}
    assert finalize(operational, source=source).historical_reference.comparison is None
    with pytest.raises(ValueError):
        finalize(usable(), source=source)


def reducer_input(seed):
    bundle = ai.build_unfinalized_evidence_bundle(candidate())
    count = 50 if seed == 35 else seed % 12 + 1
    bundle.evidence = [
        ai.EvidenceItem(id=f"E-LOCAL-{i}", type="LOCAL", summary="한" * (40 + seed * 20))
        for i in range(count)
    ]
    n = 100 if seed == 35 else seed % 7
    bundle.protocol_context = ai.ProtocolContext(
        domains=[f"{i}:" + "도" * 500 for i in range(n)],
        tls_fingerprints=[f"{i}:" + "t" * 500 for i in range(n)],
        certificate_fingerprints=[f"{i}:" + "c" * 500 for i in range(n)],
        tcp_flags={f"flag-{i:03d}": i for i in range(128 if seed == 35 else seed % 5)},
    )
    return bundle


def linear_oracle(bundle):
    ref = usable()
    raw = bundle.model_dump(mode="json", by_alias=True, exclude={"metadata"})
    protected = finalize(ref).model_dump(mode="json", by_alias=True)["evidence"][:3]
    raw["historical_reference"] = ref
    raw["evidence"] = protected + raw["evidence"]
    reduced = False
    while True:
        text = json.dumps(
            raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        if (
            len(raw["evidence"]) <= 50
            and len(text.encode()) <= 65536
            and (len(text.encode()) + 2) // 3 <= 8192
        ):
            return text, reduced
        reduced = True
        if len(raw["evidence"]) > 3:
            raw["evidence"].pop()
            continue
        for field in ("domains", "tls_fingerprints", "certificate_fingerprints"):
            if raw["protocol_context"][field]:
                raw["protocol_context"][field].pop()
                break
        else:
            flags = raw["protocol_context"]["tcp_flags"]
            if flags:
                del flags[max(flags)]
            else:
                raise ValueError("mandatory oversized")


@pytest.mark.parametrize("seed", range(36))
def test_binary_reducer_matches_linear_oracle_with_logarithmic_encodes(seed, monkeypatch):
    bundle = reducer_input(seed)
    before = bundle.model_dump()
    expected, reduced = linear_oracle(bundle)
    ref = parse_reference(usable()).historical_reference
    encodes = []
    original_encoder = history._canonical

    def meter(value):
        if isinstance(value, dict) and "candidate" in value:
            encodes.append(1)
        return original_encoder(value)

    monkeypatch.setattr(history, "_canonical", meter)
    result = history.finalize_historical_bundle(
        bundle,
        reference=ref,
        factors=factor_items(usable()),
        source_references=tuple(
            history.CompactSourceReference.model_validate(s) for s in sources()
        ),
        local_warnings=("NO_HISTORICAL_BASELINE", "CLOCK_SKEW"),
    )
    assert canonical_bundle_json(result) == expected
    assert result.metadata.reduced == reduced
    assert bundle.model_dump() == before
    assert len(encodes) <= 13
    assert len(result.evidence) <= 50
    if seed == 35:
        assert result.metadata.reduced
        assert result.historical_reference.model_dump(mode="json") == usable()


def test_count_cap_reduction_and_impossible_protected_block():
    source = {**candidate(), "evidence": [{"type": "X", "description": "x"}] * 50}
    result = finalize(source=source)
    assert len(result.evidence) == 50
    assert result.metadata.reduced
    source = {**candidate(), "internal_hosts": ["한" * 512] * 50}
    with pytest.raises(history.HistoricalEvidenceError, match="BASELINE_RUN_SNAPSHOT_LIMIT"):
        finalize(source=source)


def test_reducer_rejects_unbounded_inputs_before_encoding(monkeypatch):
    ref = parse_reference(usable()).historical_reference
    bundle = reducer_input(0)
    bundle.protocol_context.tcp_flags = {str(i): i for i in range(129)}
    calls = []
    original = history._canonical

    def meter(value):
        if isinstance(value, dict) and "candidate" in value:
            calls.append(1)
        return original(value)

    monkeypatch.setattr(history, "_canonical", meter)
    with pytest.raises(ValueError):
        history.finalize_historical_bundle(
            bundle,
            reference=ref,
            factors=factor_items(usable()),
            source_references=tuple(
                history.CompactSourceReference.model_validate(s) for s in sources()
            ),
            local_warnings=(),
        )
    assert calls == []


def test_postselection_provenance_survives_rule_history_merge_and_local_winner():
    from c2hunter_controller.ai_discovery import select_shadow_candidates

    assert callable(getattr(history, "reference_for_selected_peer", None)), (
        "postselection resolver absent"
    )
    positive = comparison(2, 8443)
    agreement = comparison(0, 443)
    rows = tuple(
        history.ProfileComparison.model_validate_json(json.dumps(c)) for c in [agreement, positive]
    )
    selected, _, _ = select_shadow_candidates(
        [candidate()],
        [{**candidate(), "behavior_anomaly_score": 80, "comparison_key": positive["key"]}],
        limit=1,
    )
    assert selected[0]["score"] == 42
    assert selected[0]["behavior_anomaly_score"] == 80
    assert selected[0]["discovery_origin"] == "RULE_AND_BEHAVIOR"
    assert "comparison_key" not in selected[0]
    common = dict(
        facts=history.ReferenceFacts.model_validate_json(json.dumps(usable()["facts"])),
        comparisons=rows,
        source_references=tuple(
            history.CompactSourceReference.model_validate(s) for s in sources()
        ),
    )
    ref = history.reference_for_selected_peer(
        external_ip=selected[0]["candidate_ip"],
        candidate_kind="C2",
        historical_comparison_key=rows[1].key,
        **common,
    )
    assert ref.comparison == rows[1]
    assert ref.comparison.historical_anomaly_score == 28
    fallback = history.reference_for_selected_peer(
        external_ip=selected[0]["candidate_ip"],
        candidate_kind="C2",
        historical_comparison_key=None,
        **{**common, "comparisons": (rows[0],)},
    )
    assert fallback.comparison == rows[0]
    no_match = history.reference_for_selected_peer(
        external_ip="203.0.113.8",
        candidate_kind="C2",
        historical_comparison_key=None,
        **common,
    )
    assert no_match.cause == "NO_PROFILE"
    operational = history.reference_for_selected_peer(
        external_ip=selected[0]["candidate_ip"],
        candidate_kind="COMMUNICATION_STATUS",
        historical_comparison_key=rows[1].key,
        **common,
    )
    assert operational.cause == "COMMUNICATION_STATUS"
    assert operational.comparison is None
    assert operational.source_references == ()


def saved_bundle(bundle):
    return {
        "candidate_id": bundle.candidate.candidate_id,
        "canonical_json": canonical_bundle_json(bundle),
        "metadata": bundle.metadata.model_dump(mode="json"),
    }


def decode(saved, *, refs=None, facts_override=None, comparisons_override=None):
    assert callable(getattr(history, "decode_admitted_bundle", None)), "saved decoder absent"
    return history.decode_admitted_bundle(
        saved,
        expected_candidate_id="rule-1",
        facts=facts_override or parse_reference(usable()).historical_reference.facts,
        comparisons=comparisons_override
        or (history.ProfileComparison.model_validate_json(json.dumps(comparison())),),
        source_references=refs
        if refs is not None
        else tuple(history.CompactSourceReference.model_validate(s) for s in sources()),
        local_warnings=("CLOCK_SKEW",),
    )


def test_saved_decoder_exact_roundtrip_and_immutable_envelope():
    saved = saved_bundle(finalize())
    result = decode(saved)
    assert canonical_bundle_json(result) == saved["canonical_json"]
    assert result.metadata.model_dump(mode="json") == saved["metadata"]
    envelope = history.AdmittedBundle.model_validate(saved)
    with pytest.raises(ValueError):
        envelope.metadata.byte_size = 1
    with pytest.raises(ValueError):
        result.historical_reference.facts.scope_kind = "OPERATIONAL"
    assert result.historical_reference.facts.scope_kind == "EVALUATION"


@pytest.mark.parametrize(
    "poison",
    [
        "extra_envelope",
        "extra_metadata",
        "id",
        "hash",
        "bytes",
        "tokens",
        "storage",
        "bool_size",
        "noncanonical",
        "duplicate",
        "null_reference",
        "missing_factor",
        "factor_points",
        "factor_metric",
        "factor_reference",
        "coverage",
        "coverage_warnings",
        "body_id",
        "unknown_body",
        "nan",
        "source_binding",
        "scope_kind",
        "comparison",
        "missing_receipt",
        "missing_comparison",
    ],
)
def test_saved_decoder_poisoning_fails_typed_without_capabilities(poison):
    saved = saved_bundle(finalize())
    raw = json.loads(saved["canonical_json"])
    kwargs = {}
    if poison == "extra_envelope":
        saved["ignored"] = 1
    elif poison == "extra_metadata":
        saved["metadata"]["ignored"] = 1
    elif poison == "id":
        saved["candidate_id"] = "other"
    elif poison in {"hash", "bytes", "tokens", "storage", "bool_size"}:
        key, value = {
            "hash": ("canonical_sha256", "0" * 64),
            "bytes": ("byte_size", 1),
            "tokens": ("estimated_tokens", 1),
            "storage": ("storage_backend", "MINIO_OBJECT"),
            "bool_size": ("byte_size", True),
        }[poison]
        saved["metadata"][key] = value
    elif poison == "noncanonical":
        saved["canonical_json"] += " "
    elif poison == "duplicate":
        saved["canonical_json"] = saved["canonical_json"].replace(
            "{", '{"schema_version":"1.0",', 1
        )
    elif poison == "missing_receipt":
        kwargs["refs"] = ()
    elif poison == "missing_comparison":
        kwargs["comparisons_override"] = (
            history.ProfileComparison.model_validate_json(json.dumps(comparison(0))),
        )
    else:
        if poison == "null_reference":
            raw["historical_reference"] = None
        elif poison == "missing_factor":
            raw["evidence"].pop(1)
        elif poison == "factor_points":
            raw["evidence"][1]["contribution"] = 13
        elif poison == "factor_metric":
            raw["evidence"][1]["metrics"]["robust_z"] = 5
        elif poison == "factor_reference":
            raw["evidence"][1]["metrics"]["reference"] = "/wrong"
        elif poison == "coverage":
            raw["evidence"][0]["summary"] = "All verified benign"
        elif poison == "coverage_warnings":
            raw["evidence"][0]["metrics"]["local_warnings"] = []
        elif poison == "body_id":
            raw["candidate"]["candidate_id"] = "other"
        elif poison == "unknown_body":
            raw["data_quality"]["unexpected"] = True
        elif poison == "nan":
            raw["evidence"][-1]["metrics"]["x"] = float("nan")
        elif poison == "source_binding":
            raw["historical_reference"]["source_references"][0]["source_binding_sha256"] = "f" * 64
        elif poison == "scope_kind":
            raw["historical_reference"]["facts"]["scope_kind"] = "OPERATIONAL"
        elif poison == "comparison":
            raw["historical_reference"]["comparison"]["key"]["service_port"] = 8443
        saved["canonical_json"] = json.dumps(
            raw, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        # Valid byte/hash metadata cannot excuse semantic poison.
        encoded = saved["canonical_json"].encode()
        saved["metadata"].update(
            canonical_sha256=hashlib.sha256(encoded).hexdigest(),
            byte_size=len(encoded),
            estimated_tokens=(len(encoded) + 2) // 3,
        )
    assert callable(getattr(history, "decode_admitted_bundle", None)), "saved decoder absent"
    with pytest.raises(history.HistoricalEvidenceError, match="HISTORICAL_SNAPSHOT_INVALID"):
        decode(saved, **kwargs)


def test_exact_token_boundary_protects_mandatory_content():
    ref = parse_reference(no_profile()).historical_reference
    bundle = ai.build_unfinalized_evidence_bundle(candidate())
    bundle.evidence = [ai.EvidenceItem(id="OLD", type="BEHAVIOR_COVERAGE", summary="old")]
    bundle.safety_notice = ""
    kwargs = dict(reference=ref, factors=(), source_references=(), local_warnings=())
    minimum = history.finalize_historical_bundle(bundle, **kwargs)
    bundle.safety_notice = "x" * (24576 - minimum.metadata.byte_size)
    result = history.finalize_historical_bundle(bundle, **kwargs)
    assert result.metadata.byte_size == 24576
    assert result.metadata.estimated_tokens == 8192
    assert not result.metadata.reduced
    bundle.safety_notice += "x"
    with pytest.raises(history.HistoricalEvidenceError, match="BASELINE_RUN_SNAPSHOT_LIMIT"):
        history.finalize_historical_bundle(bundle, **kwargs)


def test_nonfinite_optional_values_must_not_be_trimmed_into_valid_prefix():
    bundle = reducer_input(35)
    bundle.evidence[-1].metrics["nonfinite"] = float("inf")
    with pytest.raises(ValueError):
        history.finalize_historical_bundle(
            bundle,
            reference=parse_reference(usable()).historical_reference,
            factors=factor_items(usable()),
            source_references=(),
            local_warnings=(),
        )


def test_finalizer_rejects_boolean_statistics_and_noncanonical_mutated_scores():
    ref = parse_reference(usable()).historical_reference
    source_refs = tuple(history.CompactSourceReference.model_validate(s) for s in sources())
    bundle = ai.build_unfinalized_evidence_bundle(candidate())
    factors = factor_items(usable())
    factors[0].metrics["reference_median"] = False
    with pytest.raises(ValueError):
        history.finalize_historical_bundle(
            bundle, reference=ref, factors=factors, source_references=source_refs, local_warnings=()
        )
    # An int is canonically serialized as float by Pydantic; a string is not.
    bundle.candidate.existing_c2hunter_score = "42"  # Deliberately bypass assignment validation.
    with pytest.warns(UserWarning, match="Pydantic serializer"), pytest.raises(ValueError):
        history.finalize_historical_bundle(
            bundle,
            reference=ref,
            factors=factor_items(usable()),
            source_references=source_refs,
            local_warnings=(),
        )


def test_stale_and_insufficient_require_real_support_and_current():
    for status in ("STALE", "INSUFFICIENT"):
        feature = {
            **comparison()["features"]["recurrence"],
            "status": status,
            "reference_median": None,
            "reference_scale": None,
            "robust_z": None,
            "drifting": False,
        }
        assert history.FeatureComparison.model_validate_json(json.dumps(feature)).status == status
        for change in ({"eligible_window_ids": []}, {"current": None}):
            with pytest.raises(ValueError):
                history.FeatureComparison.model_validate_json(json.dumps({**feature, **change}))


def test_unreviewed_cannot_claim_ready_historical_comparison():
    ref = usable(0)
    ref["facts"]["quality_assurance"] = "UNREVIEWED"
    ref["facts"]["limitations"] = ASSERTIONS
    with pytest.raises(ValueError):
        parse_reference(ref)


def test_uppercase_protocol_is_not_restricted_to_identifier_syntax():
    key = comparison()["key"]
    key["protocol"] = "IPV6-ICMP"
    assert history.ProfileKey.model_validate(key).protocol == "IPV6-ICMP"
    for value in ("tcp", "TCP\u0085"):
        with pytest.raises(ValueError):
            history.ProfileKey.model_validate({**key, "protocol": value})


def rich_local_input():
    # C2 parent erratum: order-sensitive cutoff BEFORE filter/key shortening.
    metrics = {"Raw_Payload": "secret", **{f"k{i:02d}": i for i in range(40, -1, -1)}}
    metrics["nested"] = {"z": 1, "a": 2}
    source = {
        **candidate(),
        "evidence": [{"type": "LOCAL", "description": "한글 evidence", "metrics": metrics}],
    }
    job = {
        "flow_records": [
            {
                "source_ip": "10.0.0.1",
                "destination_ip": "203.0.113.7",
                "timestamp": "2026-10-09T00:00:00Z",
                "direction": "OUTBOUND",
                "protocol": "TCP",
                "packet_count": 2,
                "total_bytes": 4096,
                "Raw_Payload": "do not retain",
                "domain": "example.invalid",
            }
        ],
        "operations": {"failed_sensors": ["sensor-1"], "warnings": ["CLOCK_SKEW"]},
    }
    return source, job


def test_prefinalized_extraction_preserves_local_order_and_sensitive_presence():
    source, job = rich_local_input()
    original = deepcopy((source, job))
    pre = ai.build_unfinalized_evidence_bundle(source, job=job)
    off = ai.build_evidence_bundle(source, job=job)
    assert original == (source, job)
    assert pre.evidence[0].metrics == {f"k{i:02d}": i for i in range(40, 11, -1)}
    assert pre.data_quality.payload_fields_excluded == 1
    assert canonical_bundle_json(pre) == canonical_bundle_json(off)
    assert hashlib.sha256(canonical_bundle_json(off).encode()).hexdigest() == (
        "9c702ab8846e58ed5324d5a08fbccd9f02e3b1670476fb7f921a876d2ed0adda"
    )
    assert hashlib.sha256(off.model_dump_json(by_alias=True).encode()).hexdigest() == (
        "d75a378c2b5d23f2886237f5ce7d74f3dce10754e23d0fce68f9ffb41b8edbe7"
    )
    result = history.finalize_historical_bundle(
        pre,
        reference=parse_reference(usable()).historical_reference,
        factors=factor_items(usable()),
        source_references=tuple(
            history.CompactSourceReference.model_validate(s) for s in sources()
        ),
        local_warnings=("CLOCK_SKEW",),
    )
    for field in (
        "candidate",
        "all_flow_summary",
        "candidate_flow_summary",
        "data_quality",
        "safety_notice",
    ):
        assert getattr(result, field) == getattr(off, field)
    assert result.evidence[-1] == off.evidence[0]
    assert "secret" not in canonical_bundle_json(result)


@pytest.mark.parametrize(
    "change",
    [
        "extra_feature",
        "missing_nullable",
        "generation_pair",
        "duplicate_sources",
        "oversize_sources",
        "oversize_reference",
        "reason_cap",
    ],
)
def test_closed_reference_structural_poison(change):
    ref = usable()
    if change == "extra_feature":
        ref["comparison"]["features"]["unknown"] = {}
    elif change == "missing_nullable":
        del ref["comparison"]["features"]["recurrence"]["reference_median"]
    elif change == "generation_pair":
        ref["facts"]["generation_sha256"] = None
    elif change == "duplicate_sources":
        ref["source_references"].append(ref["source_references"][0])
    elif change in {"oversize_sources", "oversize_reference"}:
        refs = [
            {
                **sources()[0],
                "source_receipt_id": f"00000000-0000-0000-0000-{i:012d}",
                "source_job_id": "한" * 200,
            }
            for i in range(1, 18 if change == "oversize_sources" else 17)
        ]
        ref["source_references"] = refs
        ids = [s["source_receipt_id"] for s in refs]
        ref["comparison"]["source_window_ids"] = ids
        for feature in ref["comparison"]["features"].values():
            feature["eligible_window_ids"] = ids
    elif change == "reason_cap":
        ref["facts"]["limitations"] = ASSERTIONS * 7
    with pytest.raises(ValueError):
        parse_reference(ref)


@pytest.mark.parametrize("kind", ["C2", "COMMUNICATION_STATUS"])
def test_saved_unusable_null_profile_roundtrip_without_source_or_generation(kind):
    ref = no_profile()
    if kind == "COMMUNICATION_STATUS":
        ref["cause"] = kind
    result = finalize(ref, source={**candidate(), "candidate_kind": kind})
    restored = history.decode_admitted_bundle(
        saved_bundle(result),
        expected_candidate_id="rule-1",
        facts=result.historical_reference.facts,
        comparisons=(),
        source_references=(),
        local_warnings=("CLOCK_SKEW",),
    )
    assert canonical_bundle_json(restored) == canonical_bundle_json(result)


def test_saved_roundtrip_after_sqlite_reopen_has_no_history_dependency(tmp_path):
    # Only byte-storage roundtrip, not the unwired production worker or repository.
    import sqlite3

    saved = saved_bundle(finalize())
    db = tmp_path / "saved.sqlite"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE saved (value TEXT NOT NULL)")
        connection.execute("INSERT INTO saved VALUES (?)", (json.dumps(saved),))
    with sqlite3.connect(db) as connection:
        stored = json.loads(connection.execute("SELECT value FROM saved").fetchone()[0])
    decoded = decode(stored)
    assert canonical_bundle_json(decoded) == saved["canonical_json"]
    assert decoded.historical_reference.facts.scope_kind == "EVALUATION"


def test_protected_factor_metrics_admitted_before_optional_sequence():
    factors = factor_items(usable())
    factors[0].metrics.update({f"extra{i}": i for i in range(129)})
    with pytest.raises(ValueError):
        history.finalize_historical_bundle(
            ai.build_unfinalized_evidence_bundle(candidate()),
            reference=parse_reference(usable()).historical_reference,
            factors=factors,
            source_references=tuple(
                history.CompactSourceReference.model_validate(s) for s in sources()
            ),
            local_warnings=(),
        )


def test_null_generation_cannot_use_nonempty_saved_manifest():
    reference = parse_reference(no_profile()).historical_reference
    with pytest.raises(ValueError):
        history.finalize_historical_bundle(
            ai.build_unfinalized_evidence_bundle(candidate()),
            reference=reference,
            factors=(),
            source_references=tuple(
                history.CompactSourceReference.model_validate(s) for s in sources()
            ),
            local_warnings=(),
        )
