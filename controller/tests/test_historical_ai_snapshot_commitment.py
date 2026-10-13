"""An owning record commitment is independent of its supplied/rehashed body.

The DTO schema deliberately contains no self-digest. Later lifecycle adapters
must retain an immutable trusted envelope; this test does not invent persistence.
"""

import hashlib
import inspect
import json

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import world


def test_independent_owning_commitment_rejects_valid_but_foreign_saved_bytes():
    value = dto.HistoricalAdmissionInput(**world())
    result = producer.build_historical_snapshot(value)
    wire = h.canonical_json(result.to_mapping())
    assert (
        "expected_snapshot_sha256" in inspect.signature(dto.decode_historical_snapshot).parameters
    ), (
        "saved full receipts/dataset have no independent owner commitment; "
        "a self-hash is insufficient"
    )
    committed = hashlib.sha256(wire.encode()).hexdigest()
    assert dto.decode_historical_snapshot(
        wire, request=value.request, expected_snapshot_sha256=committed
    )
    for change in ("dataset", "receipt_note", "receipt_reason", "receipt_rehashed"):
        foreign = json.loads(wire)
        if change == "dataset":
            foreign["dataset_id"] = "other-dataset"
        elif change == "receipt_note":
            foreign["baseline_sources"][0]["quality_review"]["note"] = "other review"
        elif change == "receipt_reason":
            foreign["baseline_sources"][0]["reason"] = "other approval"
        else:
            foreign["baseline_sources"][0]["observation_sha256"] = "f" * 64
        forged = h.canonical_json(foreign)
        assert hashlib.sha256(forged.encode()).hexdigest() != committed
        with pytest.raises(dto.HistoricalAIError, match="HISTORICAL_SNAPSHOT_INVALID"):
            dto.decode_historical_snapshot(
                forged, request=value.request, expected_snapshot_sha256=committed
            )
