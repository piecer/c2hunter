"""Combined raw candidate cardinality, before selector peer deduplication."""

from copy import deepcopy
from ipaddress import ip_address

import pytest

from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from tests.historical_ai_fixtures import job, rule, world


@pytest.mark.parametrize(
    "count,extra_peer,reject", [(2047, False, False), (2048, False, True), (2047, True, True)]
)
def test_combined_and_generated_overflow_before_real_selector(
    count, extra_peer, reject, monkeypatch
):
    candidates = [rule()]
    candidates.extend(
        rule(str(ip_address("198.18.0.1") + i), f"rule-{i}", 1) for i in range(count - 1)
    )
    target = job()
    if extra_peer:
        other = deepcopy(target["flow_records"])
        for row in other:
            for field in ("source_ip", "destination_ip"):
                if row[field] == "203.0.113.9":
                    row[field] = "203.0.113.10"
        target["flow_records"].extend(other)
        # Neither generated peer overlaps stored legacy; legacy reaches 2049.
        candidates[0]["candidate_ip"] = "198.19.0.1"
    value = dto.HistoricalAdmissionInput(**world(target=target, candidates=candidates))
    calls = []
    actual = ai_discovery.select_shadow_candidates

    def observed(*args, **kwargs):
        calls.append(tuple(len(arg) for arg in args))
        return actual(*args, **kwargs)

    monkeypatch.setattr(ai_discovery, "select_shadow_candidates", observed)
    if reject:
        with pytest.raises(dto.HistoricalAIError) as caught:
            producer.build_historical_snapshot(value)
        assert caught.value.code == "BASELINE_CANDIDATE_LIMIT"
        assert calls == []
    else:
        result = producer.build_historical_snapshot(value)
        assert calls == [(2047, 1)]
        assert result.selection_summary.candidate_pool_count == 2047
        assert len(result.candidate_ids) == 5
        assert len(result.selection_inventory) == 2047
