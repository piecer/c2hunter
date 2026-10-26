"""Portable real producer/public projection witness, without a model or sockets."""

import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_epoch_worker_public_ai_projection(tmp_path):
    path = ROOT / "web/tests/network_epoch_fixture.py"
    spec = importlib.util.spec_from_file_location("epoch_fixture", path)
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    first, second = fixture.build_bundle(), fixture.build_bundle()
    assert first["source"]["live_capture_exercised"] is False
    assert first["source"]["model_invoked"] is False
    assert all(Path(p).is_relative_to(ROOT) for p in first["source"]["module_origins"].values())
    captures = fixture.packet_captures()
    for name, case in first["cases"].items():
        repeat = second["cases"][name]
        assert fixture.canonical(case["report"]) == fixture.canonical(repeat["report"])
        assert fixture.canonical(case["ai"]) == fixture.canonical(repeat["ai"])
        assert case["typed_records"] == repeat["typed_records"]
        assert case["pcap_sha256"] == hashlib.sha256(captures[name]).hexdigest()
        assert case["pcap_sha256"] == case["job"]["source"]["sha256"]
        assert case["job"]["source_type"] == case["job"]["mode"] == "PCAP_UPLOAD"
        assert case["public_response"]["status_code"] == 200
        assert case["job"]["network_anomaly"] == case["worker_result"]["network_anomaly"]
        assert case["report"] == case["job"]["network_anomaly"]
        assert case["ai"]["warnings"] == case["report"]["warnings"]
        assert "flow_records" not in case["job"]
        assert all(row["packet_evidence_complete"] is True for row in case["typed_records"])
        (tmp_path / f"{name}.pcap").write_bytes(captures[name])
    positive = first["cases"]["recovered"]
    report = positive["report"]
    assert {i["pattern"]: i["event_count"] for i in report["issues"]} == {"syn_retransmissions": 1}
    assert report["summary"]["verdict"] == "anomaly_observed"
    assert report["summary"]["tracking_limited_records"] == 1
    assert report["summary"]["incomplete_records"] == 1
    assert report["summary"]["counts_are_lower_bounds"] is True
    assert report["summary"]["truncated"] is True
    assert report["summary"]["coverage_complete"] is False
    assert set(report["warnings"]) == {"CORRELATION_LIMIT_REACHED", "PARSER_SKIPPED_PACKETS"}
    assert positive["parsed"]["skipped"] == positive["job"]["source"]["skipped_packet_count"] == 1
    assert positive["parsed"]["parsed"] == len(positive["typed_records"])
    assert positive["parsed"]["captured"] == positive["parsed"]["parsed"] + 1
    measurement = report["issues"][0]["examples"][0]["measurements"]
    assert "CORRELATION_LIMIT_REACHED" in measurement["reasons"]
    assert measurement["observed_rtt_ms"]["count"] == 1
    assert measurement["rtt_sources"] == {"syn_ack": 1, "data_ack": 0}
    assert positive["ai"]["summary"]["tracking_limited_records"] == 1
    assert positive["ai"]["summary"]["counts_are_lower_bounds"] is True
    assert positive["ai"]["summary"]["coverage_complete"] is False
    assert positive["ai"]["issues"][0]["event_count"] == 1
    old = first["cases"]["suppressed"]["report"]
    assert old["issues"] == []
    assert old["summary"]["tracking_limited_records"] == 3
    assert old["summary"]["verdict"] == "insufficient_evidence"
    normal = first["cases"]["normal"]["report"]
    assert normal["issues"] == []
    assert normal["warnings"] == []
    assert normal["summary"]["coverage_complete"] is True
    assert normal["summary"]["verdict"] == "no_clear_anomaly"
