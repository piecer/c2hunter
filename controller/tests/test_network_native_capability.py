"""Current native producer capability, not a LIVE capture/lifecycle simulation."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PCAP = ROOT / "sensor/internal/flowbatch/testdata/network_capability_six.pcap"
FIXTURE = ROOT / "web/tests/network_native_capability_fixture.py"


def test_network_native_capability(tmp_path, monkeypatch):
    """Fresh Go bytes → schema/ingestion → real worker → serialized public GET."""
    monkeypatch.syspath_prepend(str(ROOT / "analysis/tests"))
    import test_network_anomaly as packets

    assert Path(packets.__file__).resolve() == ROOT / "analysis/tests/test_network_anomaly.py"
    syn = packets.frame()
    data = packets.frame(flags=24, seq=101, payload=b"abc")
    expected = packets.capture(
        syn,
        syn,
        packets.frame(flags=18, seq=500, ack=101, reverse=True),
        data,
        data,
        packets.frame(flags=16, seq=501, ack=104, reverse=True),
        start_time=datetime.fromtimestamp(1700000000, UTC),
    )
    assert PCAP.read_bytes() == expected
    go = shutil.which("go")
    assert go is not None, (
        "Installed Go plus cached dependencies are required; never skip this witness"
    )
    output = tmp_path / "native-batch.json"
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("C2HUNTER_") and key not in {"GOFLAGS", "GOWORK"}
    }
    for name in ("gocache", "gotmp", "tmp"):
        (tmp_path / name).mkdir()
    env.update(
        GOTOOLCHAIN="local",
        GOPROXY="off",
        GOSUMDB="off",
        GOTELEMETRY="off",
        GOENV="off",
        GOWORK="off",
        GOCACHE=str(tmp_path / "gocache"),
        GOTMPDIR=str(tmp_path / "gotmp"),
        TMPDIR=str(tmp_path / "tmp"),
        C2HUNTER_NETWORK_CAPABILITY_OUTPUT=str(output),
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONPATH=os.pathsep.join(
            str(ROOT / path)
            for path in ("controller/src", "analysis/src", "sensor/worker/src", "analysis/tests")
        ),
    )
    command = [
        go,
        "test",
        "./internal/flowbatch",
        "-run",
        "^TestNetworkAggregateCapabilityFixture$",
        "-count=1",
    ]
    produced = subprocess.run(
        command, cwd=ROOT / "sensor", env=env, capture_output=True, text=True, timeout=180
    )
    assert produced.returncode == 0, produced.stdout + produced.stderr
    assert output.is_file(), "A no-tests-to-run Go success is not producer evidence"
    raw_batch = output.read_bytes()
    # The export path is invocation-owned and exclusive: rerun must not overwrite it.
    refused = subprocess.run(
        command, cwd=ROOT / "sensor", env=env, capture_output=True, text=True, timeout=60
    )
    assert refused.returncode != 0
    assert "file exists" in refused.stdout + refused.stderr
    assert output.read_bytes() == raw_batch
    generated = subprocess.run(
        [sys.executable, str(FIXTURE), "--batch-file", str(output), "--pcap-file", str(PCAP)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert generated.returncode == 0, generated.stderr
    bundle = json.loads(generated.stdout)
    assert set(bundle) == {"schema_version", "source", "native", "pcap"}
    assert set(bundle["native"]) == {
        "batch",
        "typed_records",
        "ingestion",
        "worker_result",
        "job",
        "public_response",
    }
    assert set(bundle["pcap"]) == {"typed_records", "worker_result", "job", "public_response"}
    assert bundle["schema_version"] == "network-native-capability-fixture-v1"
    source = bundle["source"]
    assert source["pcap_sha256"] == hashlib.sha256(expected).hexdigest()
    assert source["native_batch_sha256"] == hashlib.sha256(raw_batch).hexdigest()
    assert source["native_packet_count"] == 6
    assert source["native_record_count"] == 2
    assert source["live_capture_exercised"] is False
    assert Path(source["pcap_file"]) == PCAP
    assert Path(source["batch_file"]) == output
    assert all(Path(path).is_relative_to(ROOT) for path in source["module_origins"].values())
    batch = json.loads(raw_batch)
    native = bundle["native"]
    assert native["batch"] == batch
    assert sum(row["packet_count"] for row in native["typed_records"]) == 6
    assert all(row["packet_evidence_complete"] is False for row in native["typed_records"])
    assert all("packet_evidence_complete" not in row for row in batch["flows"])
    assert native["ingestion"]["record_count"] == 2
    assert native["job"]["mode"] == "HISTORICAL"
    assert native["job"]["source_type"] == "SENSOR_CAPTURE"
    report = native["job"]["network_anomaly"]
    assert report["summary"]["scanned_records"] == 2
    assert report["summary"]["evaluated_records"] == 0
    assert report["summary"]["incomplete_records"] == 2
    assert report["summary"]["verdict"] == "insufficient_evidence"
    assert report["summary"]["coverage_complete"] is False
    assert "SENSOR_CAPTURE_QUALITY_UNAVAILABLE" in report["warnings"]
    assert report["issues"] == []
    pcap = bundle["pcap"]
    assert pcap["job"]["mode"] == pcap["job"]["source_type"] == "PCAP_UPLOAD"
    assert pcap["job"]["source"]["sha256"] == source["pcap_sha256"]
    assert pcap["job"]["source"]["captured_packet_count"] == 6
    assert pcap["job"]["source"]["parsed_packet_count"] == 6
    assert pcap["job"]["source"]["skipped_packet_count"] == 0
    positive = pcap["job"]["network_anomaly"]
    assert positive["summary"]["evaluated_records"] == 6
    assert positive["summary"]["incomplete_records"] == 0
    assert positive["summary"]["verdict"] == "anomaly_observed"
    assert {issue["pattern"]: issue["event_count"] for issue in positive["issues"]} == {
        "syn_retransmissions": 1,
        "data_retransmissions": 1,
    }
    for case in (native, pcap):
        assert case["public_response"]["status_code"] == 200
        assert case["public_response"]["method"] == "GET"
        assert case["job"]["status"] == "COMPLETED"
        assert case["job"]["candidate_count"] == 0
        assert "flow_records" not in case["job"]
        assert case["job"]["network_anomaly"] == case["worker_result"]["network_anomaly"]
        assert case["worker_result"]["candidates"] == []
