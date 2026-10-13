"""Generation-to-real-comparison identity controls, synthetic only."""

import hashlib
from pathlib import Path

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import historical_generation as g
from c2hunter_controller.historical_source import source_build_input
from tests.test_historical_generation import (
    advance,
    empty_scope,
    producer_args,
    publish,
    snapshot_for,
    source_job,
)
from tests.test_historical_source import review


def test_canonical_producer_fixture_freshness() -> None:
    raw = (Path(__file__).parent / "fixtures" / "historical-generation-v1.json").read_bytes()
    args = producer_args()
    document = g.produce_generation(**args)
    assert raw == g.generation_json(document).encode()
    decoded = g.decode_generation(
        raw.decode(),
        byte_size=len(raw),
        content_sha256=hashlib.sha256(raw).hexdigest(),
        scope=args["scope"].config,
    )
    assert decoded == document
    assert "content_sha256" not in decoded.to_mapping()
    assert "byte_size" not in decoded.to_mapping()


@pytest.mark.parametrize(
    "case,expected",
    [
        ("matching", "READY"),
        ("dataset", "MISSING"),
        ("peer", "MISSING"),
        ("port", "MISSING"),
        ("aggregate", "MISSING"),
        ("root", "INSUFFICIENT"),
    ],
)
def test_real_target_source_identity_controls(case: str, expected: str) -> None:
    scope, document = empty_scope(), None
    for index in range(3):
        raw = source_job(index)
        # Independently observed windows, one curated dataset; root identity is still unique.
        raw["dataset_id"] = "curated-dataset"
        document = publish(snapshot_for(raw), scope, document, index=index + 1)
        scope = advance(scope, document)
    raw = source_job(4, aggregate=case == "aggregate")
    if case in {"dataset", "root"}:
        raw["dataset_id"] = "curated-dataset"
    if case == "root":
        raw["id"] = "root-0"
        # Dataset exclusion applies to all references, so use individually distinct datasets
        # in this control instead; bind the exact root/dataset from the first real receipt.
        scope, document = empty_scope(), None
        for index in range(3):
            document = publish(snapshot_for(source_job(index)), scope, document, index=index + 1)
            scope = advance(scope, document)
        raw["dataset_id"] = "dataset-0"
    if case == "peer":
        for row in raw["flow_records"]:
            row["destination_ip"] = "198.51.100.25"
    if case == "port":
        for row in raw["flow_records"]:
            row["destination_port"] = 444
    source = snapshot_for(raw).source
    request = source_build_input(
        source, scope=scope.config, quality_review=review(), source_receipt_id=None
    )
    view = g.generation_view(document)
    document = g.decode_generation(
        g.generation_json(document),
        content_sha256=view.content_sha256,
        byte_size=view.byte_size,
        scope=scope.config,
    )
    result = b.compare_behavior_windows(
        target=b.build_behavior_windows(request),
        reference=g.generation_reference(document, scope=scope.config),
        scope=request.scope,
        target_observation=b.ObservationIdentity(
            source.root_identity, source.original.dataset_id, source.feature_observation_sha256
        ),
        target_event_start=source.event_start,
        target_event_end=source.event_end,
        target_vetoes=(),
    )
    assert {p.status for p in result.comparisons} == {expected}
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result
