"""Real persisted preview policy, exact hashes and nonmutating projection."""

from typing import Any

import pytest

import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_read as r
from tests import test_baseline_scope_storage as storage_fixtures
from tests.test_baseline_scope_storage import PREVIEW_KEYS
from tests.test_historical_source import START, config, review, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


@pytest.mark.parametrize("kind", ["OPERATIONAL", "EVALUATION"])
@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("quality", ["clean", "partial", "incomplete", "clock", "offset", "zero"])
def test_no_review_policy_matrix(
    scope_repo: Any, monkeypatch: Any, kind: str, purpose: str, quality: str
) -> None:
    repo = scope_repo
    cfg = h.ScopeConfig.from_mapping(
        dict(
            config().to_mapping(),
            kind=kind,
            stored_sensor_id="sensor" if kind == "OPERATIONAL" else None,
        )
    )
    scope, _ = repo.create_baseline_scope(cfg, "admin", START)
    raw = stored()
    if quality == "partial":
        raw["status"] = "PARTIALLY_COMPLETED"
    if quality == "incomplete":
        raw["capture_incomplete"] = True
    if quality == "clock":
        raw["capture_quality"] = {"clock_skew_detected": True}
    if quality in ("offset", "zero"):
        raw["operations"] = {
            "sensors": {"sensor": {"clock_offset_ms": -3000 if quality == "offset" else 0}}
        }
    repo.save_job(raw)
    repo.save_candidates(
        "root", [{"id": "rule", "candidate_ip": "203.0.113.9", "score": 20, "excluded": True}]
    )
    for name in (
        "get_job",
        "get_job_summary",
        "get_candidates",
        "list_jobs",
        "read_historical_source",
    ):
        monkeypatch.setattr(
            repo, name, lambda *_a, **_k: pytest.fail("generic/public nested source read")
        )
    with monkeypatch.context() as guard:
        guard.setattr(
            "c2hunter_controller.historical_source.source_build_input",
            lambda *_a, **_k: pytest.fail("fabricated review authority"),
        )
        if purpose == "APPROVAL":
            guard.setattr(r, "_sqlite_candidates", lambda *_: pytest.fail("APPROVAL candidate SQL"))
            guard.setattr(r, "_pg_candidates", lambda *_: pytest.fail("APPROVAL candidate SQL"))
        result = repo.preview_baseline_source(cfg.scope_id, "root", 0, purpose)
    assert set(result.to_mapping()) == PREVIEW_KEYS
    assert result.profile_count == result.eligible_profile_count == 4
    assert result.excluded_profile_count == 0 and result.flow_count == 32
    assert result.admissible == (quality in ("clean", "zero"))
    expected = {"ADMIN_ASSERTED_IDENTITY", "PRODUCER_COMPLETENESS_UNKNOWN"}
    if quality in ("partial", "incomplete"):
        expected.add(
            "SOURCE_PARTIAL_CAPTURE" if purpose == "APPROVAL" else "TARGET_PARTIAL_CAPTURE"
        )
    if quality in ("clock", "offset"):
        expected.add("SOURCE_CLOCK_UNCERTAIN")
    assert result.reasons == tuple(sorted(expected))
    assert result.known_partial == (quality in ("partial", "incomplete"))
    assert result.stored_clock_offset_ms == (
        -3000 if quality == "offset" else 0 if quality == "zero" else None
    )
    assert repo.get_baseline_scope(cfg.scope_id) == scope
    # Re-enable only the reviewed public entry for an actual same-purpose hash oracle.
    method = type(repo).read_historical_source.__get__(repo)
    actual_review = h.QualityReview.from_mapping(
        dict(review().to_mapping(), sensor_alias_asserted=kind == "EVALUATION")
    )
    if quality == "partial" and purpose == "APPROVAL":
        with pytest.raises(ValueError, match="BASELINE_SOURCE_STATE"):
            method("root", purpose=purpose, scope=cfg, quality_review=actual_review)
    else:
        later = method("root", purpose=purpose, scope=cfg, quality_review=actual_review)
        assert result.source_binding_sha256 == later.source_binding_sha256
        assert result.observation_sha256 == later.source.observation_sha256
        assert result.feature_observation_sha256 == later.source.feature_observation_sha256
    if kind == "EVALUATION":
        with pytest.raises(ValueError, match="BASELINE_SCOPE_MISMATCH"):
            method("root", purpose="COMPARISON", scope=cfg, quality_review=None)


@pytest.mark.parametrize(
    "source_case",
    ["upload", "same-sensor", "empty", "sparse", "trusted", "missing-port", "network"],
)
def test_structural_preview_source_cases(scope_repo: Any, source_case: str) -> None:
    cfg = h.ScopeConfig.from_mapping(
        dict(config().to_mapping(), kind="EVALUATION", stored_sensor_id=None)
    )
    raw = stored()
    expected = (4, 4, 0)
    if source_case == "upload":
        digest = "a" * 64
        raw.update(
            source_type="PCAP_UPLOAD",
            mode="PCAP_UPLOAD",
            dataset_id="pcap:" + digest,
            source={"sha256": digest, "capture_format": "PCAP", "captured_packet_count": 32},
        )
    if source_case == "same-sensor":
        cfg = h.ScopeConfig.from_mapping(dict(cfg.to_mapping(), sensor_key="sensor"))
    if source_case == "empty":
        raw["flow_records"] = []
        expected = (0, 0, 0)
    if source_case == "sparse":
        raw["flow_records"] = raw["flow_records"][:7]
        expected = (1, 0, 1)
    if source_case == "trusted":
        raw["allowlist"] = [
            {
                "type": "IP",
                "value": "203.0.113.9",
                "description": "saved trusted peer",
                "enabled": True,
            }
        ]
        expected = (4, 0, 4)
    if source_case == "missing-port":
        for row in raw["flow_records"]:
            row.pop("destination_port")
        expected = (2, 0, 2)
    if source_case == "network":
        raw["internal_networks"] = ["10.0.0.0/16"]
    scope_repo.create_baseline_scope(cfg, "admin", START)
    scope_repo.save_job(raw)
    if source_case == "network":
        with pytest.raises(ValueError, match="^BASELINE_SCOPE_MISMATCH$"):
            scope_repo.preview_baseline_source(cfg.scope_id, "root", 0, "APPROVAL")
        return
    result = scope_repo.preview_baseline_source(cfg.scope_id, "root", 0, "APPROVAL")
    assert (
        result.profile_count,
        result.eligible_profile_count,
        result.excluded_profile_count,
    ) == expected
    assert result.admissible == (expected[1] > 0)
    assert result.actual_sensor_id == "sensor"


@pytest.mark.parametrize(
    "fault,code",
    [
        ("rows", "BASELINE_SOURCE_LIMIT"),
        ("malformed", "BASELINE_SOURCE_INVALID"),
        ("lineage", "BASELINE_SOURCE_LINEAGE_INVALID"),
        ("state", "BASELINE_SOURCE_STATE"),
        ("module", "BASELINE_SOURCE_INVALID"),
    ],
)
def test_partial_does_not_bypass_admission(
    scope_repo: Any, fault: str, code: str, monkeypatch: Any
) -> None:
    raw = stored()
    raw["status"] = "PARTIALLY_COMPLETED"
    if fault in ("rows", "state", "module"):
        raw["flow_records"] *= 257
    if fault == "malformed":
        raw["flow_records"][-1]["packet_count"] = True
    if fault == "lineage":
        raw["parent_job_id"] = "missing-parent"
    if fault == "state":
        raw["status"] = "FAILED"
    if fault == "module":
        raw["analysis"]["module"] = "ddos_attack"
    scope_repo.create_baseline_scope(config(), "admin", START)
    scope_repo.save_job(raw)
    if fault in ("state", "module"):
        monkeypatch.setattr(
            r, "_sqlite_flows", lambda *_: pytest.fail("state gate after flow read")
        )
        monkeypatch.setattr(r, "_pg_flows", lambda *_: pytest.fail("state gate after flow read"))
        monkeypatch.setattr(
            r, "_admit_rows", lambda *_a, **_k: pytest.fail("state gate after flow read")
        )
    with pytest.raises(ValueError, match="^" + code + "$"):
        scope_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
