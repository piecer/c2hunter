from copy import deepcopy

from test_ddos_attack import PARAMETERS, distributed_tcp

from c2hunter_analysis.ddos_attack import analyze_ddos_attack


def test_emitted_predicate_is_evaluated_not_a_histogram():
    rows = distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    report = analyze_ddos_attack(rows, parameters=PARAMETERS)
    candidate = report["findings"][0]["signature_candidates"][0]
    assert report["version"] == "ddos-attack-report-v4"
    evaluation = candidate["evaluation"]
    predicate = evaluation["predicate"]
    # Independent replay of the actual emitted conjunction, not producer booleans.
    matched = sum(
        row["destination_ip"] == predicate["target_ip"]
        and row["direction"] == predicate["direction"]
        and row["protocol"] == predicate["protocol"]
        and row["destination_port"] in predicate["destination_ports"]
        and all(row["tcp_flags"].get(k) == v for k, v in predicate["tcp_flags"].items())
        for row in rows
    )
    assert matched == 100
    assert evaluation["attack"]["matched_records"] == matched
    assert evaluation["attack"]["matched_packets"] == matched
    assert evaluation["normal"]["status"] == "UNMEASURED"
    assert evaluation["normal"]["result"] is None
    assert evaluation["normal"]["reference"] is None
    assert candidate["confidence"] == "low"
    assert candidate["requires_human_approval"] is True
    assert evaluation["predicate"]["length"] is None
    assert rows == distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})

    aggregate = deepcopy(rows)
    for row in aggregate:
        row["packet_count"] = 10
        row["total_bytes"] = 1000
        row["tcp_syn_count"] = row["tcp_syn_only_count"] = 10
    result = analyze_ddos_attack(aggregate, parameters=PARAMETERS)
    counts = result["findings"][0]["signature_candidates"][0]["evaluation"]["attack"]
    assert counts["matched_records"] == counts["matched_packets"] == 0
    assert counts["unknown_records"] == 100
    assert counts["unknown_packets"] == 1000
    assert counts["packet_match_rate"] is None


def test_candidate_encoded_byte_budget_exact_and_minus_one(monkeypatch):
    import pytest

    from c2hunter_analysis import ddos_signatures as signatures

    rows = distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    report = analyze_ddos_attack(rows, parameters=PARAMETERS)
    candidate = report["findings"][0]["signature_candidates"][0]
    size = len(signatures.encoded(candidate["evaluation"]))
    monkeypatch.setattr(signatures, "MAX_EVALUATION_BYTES", size)
    assert analyze_ddos_attack(rows, parameters=PARAMETERS) == report
    monkeypatch.setattr(signatures, "MAX_EVALUATION_BYTES", size - 1)
    with pytest.raises(ValueError, match="byte limit"):
        analyze_ddos_attack(rows, parameters=PARAMETERS)


def test_total_candidate_publication_has_an_encoded_byte_limit(monkeypatch):
    import pytest

    from c2hunter_analysis import ddos_signatures as signatures

    rows = distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    report = analyze_ddos_attack(rows, parameters=PARAMETERS)
    size = sum(len(signatures.encoded(f["signature_candidates"])) for f in report["findings"])
    monkeypatch.setattr(signatures, "MAX_PUBLICATION_BYTES", size, raising=False)
    assert analyze_ddos_attack(rows, parameters=PARAMETERS) == report
    monkeypatch.setattr(signatures, "MAX_PUBLICATION_BYTES", size - 1)
    with pytest.raises(ValueError, match="publication byte limit"):
        analyze_ddos_attack(rows, parameters=PARAMETERS)


def test_evidence_references_distinguish_time_and_sensor():
    from c2hunter_analysis.ddos_signatures import digest, project

    rows = distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    assert digest(project(rows[0])) != digest(project(rows[4]))
    changed = dict(rows[0], sensor_id="another-sensor")
    assert digest(project(rows[0])) != digest(project(changed))


def test_normalized_address_and_legacy_single_record_defaults():
    rows = distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    for row in rows:
        row["destination_ip"] = "FD00::AB"
        row.pop("packet_count")
    report = analyze_ddos_attack(rows, parameters=PARAMETERS, internal_cidrs=["fd00::/8"])
    result = report["findings"][0]["signature_candidates"][0]["evaluation"]["attack"]
    assert result["matched_records"] == 100
    assert result["matched_packets"] == 100


def test_unsupported_metadata_is_unknown_not_eligible_nonmatch():
    from c2hunter_analysis.ddos_signatures import match, project

    rows = distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    report = analyze_ddos_attack(rows, parameters=PARAMETERS)
    predicate = report["findings"][0]["signature_candidates"][0]["evaluation"]["predicate"]
    for field, value in [("direction", "UNSUPPORTED"), ("protocol", 6), ("destination_ip", 123)]:
        row = project(dict(rows[0], **{field: value}))
        assert match(predicate, row) is None


def test_length_semantics_never_substitute_frame_ip_or_payload():
    from c2hunter_analysis.ddos_signatures import match, project

    row = project(distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})[0])
    predicate = {
        "target_ip": "10.0.0.10",
        "direction": "INBOUND",
        "protocol": "TCP",
        "source_ports": None,
        "destination_ports": [443],
        "tcp_flags": None,
        "length": {"field": "CAPTURED_FRAME_BYTES", "minimum": 100, "maximum": 100},
        "protocol_fields": {},
    }
    assert match(predicate, row) is True
    predicate["length"]["field"] = "TRANSPORT_PAYLOAD_BYTES"
    assert match(predicate, row) is False
    predicate["length"]["field"] = "IP_BYTES"
    assert match(predicate, row) is None
    predicate["length"] = None
    predicate["protocol_fields"] = {"icmp_type": 8}
    assert match(predicate, row) is None


def test_sample_exact_limit_plus_one_and_order_are_truthful():
    from c2hunter_analysis.ddos_signatures import MAX_RECORDS, EvidenceSample, evaluate

    rows = distributed_tcp({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    rows = (rows * 6)[: MAX_RECORDS + 1]
    sample, reversed_sample = EvidenceSample(), EvidenceSample()
    for row in rows[:MAX_RECORDS]:
        sample.add(row)
    assert len(sample.records) == MAX_RECORDS
    assert sample.omitted == 0
    sample.add(rows[-1])
    for row in reversed(rows):
        reversed_sample.add(row)
    assert sample.omitted == 1
    assert sample.records == reversed_sample.records
    report = analyze_ddos_attack(rows, parameters=PARAMETERS)
    evaluation = report["findings"][0]["signature_candidates"][0]["evaluation"]
    assert evaluation["attack"] == evaluate(evaluation["predicate"], sample)
    assert evaluation["attack"]["matched_packets"] == MAX_RECORDS
    assert evaluation["attack"]["omitted_records"] == 1
