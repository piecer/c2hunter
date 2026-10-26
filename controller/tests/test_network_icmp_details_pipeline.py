"""ICMP details survive actual worker persistence without entering AI input."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "web/tests"))
from network_icmp_fixture import build_bundle  # noqa: E402


def test_two_router_worker_sqlite_public_get_and_ai_privacy():
    value = build_bundle()["case"]
    report = value["report"]
    issue = next(i for i in report["issues"] if i["pattern"] == "icmp_errors")
    example = issue["examples"][0]
    assert issue["event_count"] == example["event_count"] == 2
    assert "icmp_details" in example, (
        "actual outer reporters are missing from saved public evidence"
    )
    detail = example["icmp_details"]
    assert [s["reporter_ip"] for s in detail["samples"]] == ["192.0.2.1", "192.0.2.2"]
    assert [s["code"] for s in detail["samples"]] == [1, 3]
    assert all(s["packet_reference"] is None for s in detail["samples"])
    assert example["facts"]["icmp_code"] == 1
    assert value["job"]["network_anomaly"] == report
    import json

    ai = json.dumps(value["ai"])
    for address in ("192.0.2.1", "192.0.2.2", "10.0.0.1", "203.0.113.1"):
        assert address not in ai
    assert "query" not in ai and "icmp_details" not in ai
    legacy = json.loads((ROOT / "web/tests/fixtures/network-icmp-legacy.json").read_text())
    new_legacy = json.loads(json.dumps(report))
    for item in new_legacy["issues"]:
        for retained in item["examples"]:
            retained.pop("icmp_details", None)
    assert new_legacy == legacy


def test_actual_pipeline_repeat_bytes_ipv6_ai_and_source_origins():
    import json

    from network_epoch_fixture import canonical

    first, second = build_bundle(), build_bundle()
    for key in ("case", "ipv6"):
        a, b = first[key], second[key]
        assert canonical(a["report"]) == canonical(b["report"])
        assert canonical(a["ai"]) == canonical(b["ai"])
        assert a["job"]["id"] != b["job"]["id"]
        assert a["report"] == a["worker_result"]["network_anomaly"] == a["job"]["network_anomaly"]
        assert all(Path(p).is_relative_to(ROOT) for p in first["origins"].values())
        ai = canonical(a["ai"])
        for row in a["typed_records"]:
            assert row["source_ip"] not in ai and row["destination_ip"] not in ai
        assert "raw_packet" not in ai and "icmp_details" not in ai
    assert len(first["maximum_ai"]["issues"]) <= 20
    assert (
        len(json.dumps(first["maximum_ai"], ensure_ascii=False, separators=(",", ":")).encode())
        <= 24000
    )
    assert "192.0.2." not in canonical(first["maximum_ai"])
