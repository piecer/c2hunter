"""Cross-runtime JOB leaves and schemas are tested using actual output bytes."""

import json

import pytest

from c2hunter_controller.ai_investigation_contract import Evidence, canonical_bytes
from c2hunter_controller.ai_job_investigation_runtime_schema import JobRun
from tests.test_ai_job_investigation_fixtures import producer_fixtures


def test_public_schema_required_members_and_integral_reused_leaves():
    outputs = producer_fixtures()
    schema = JobRun.model_json_schema()
    assert set(schema["required"]) == set(schema["properties"])
    raw = outputs["run_completed"][:-1]
    # Preserve raw token spellings through the actual Python JSON decoder.
    for key in ("tool_calls", "source_records", "matched", "retained"):
        data = json.loads(raw)
        text = raw.decode()
        import re

        altered = re.sub(r'("' + key + r'":)(\d+)', r"\g<1>\2e0", text)
        assert altered != text
        assert JobRun.model_validate_json(altered).model_dump(mode="json") == data
    from c2hunter_controller import ai_job_investigation_runtime_schema as contracts

    parser = getattr(contracts, "parse_job_evidence", None)
    assert callable(parser), "JOB evidence numeric adapter missing"
    raw = outputs["evidence_protocol"][:-1]
    changed = raw.replace(b'"matched":1', b'"matched":1e0')
    assert changed != raw
    assert parser(changed) == Evidence.model_validate_json(raw)
    with pytest.raises(ValueError):
        Evidence.model_validate_json(changed)  # old IP/raw decoder remains strict
    with pytest.raises(ValueError):
        parser(changed.replace(b'"matched":1e0', b'"matched":true'))
    with pytest.raises(ValueError):
        parser(raw.replace(b'"matched":1', b'"matched":1,"matched":1'))
    assert canonical_bytes(parser(raw).model_dump(mode="json")) == raw
