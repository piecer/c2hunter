"""Offline checksum-valid PCAP -> schema -> worker -> SQLite/public GET -> AI input.

No native LIVE evidence or model invocation is simulated. Only queue delivery is
in-memory. Report/input bytes are deterministic; real public job IDs/times vary.
Run from any cwd; --projection omits raw rows only from the Web transport bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def packet_captures() -> dict[str, bytes]:
    sys.path.insert(0, str(ROOT / "analysis/tests"))
    import test_network_anomaly as packets

    assert (
        Path(packets.__file__).resolve()
        == ROOT / "analysis/tests/test_network_anomaly.py"
    )
    syn = packets.frame(seq=100)
    response = packets.frame(flags=18, seq=500, ack=101, reverse=True)
    payloads = [
        packets.frame(flags=24, seq=101 + i, payload=struct.pack("!I", i))
        for i in range(4097)
    ]
    # Validate the actual bytes, including each TCP pseudoheader checksum.
    for wire in [syn, response, *payloads, packets.frame(seq=900000)]:
        assert packets.internet_checksum(wire[14:34]) == 0
        pseudo = wire[26:34] + struct.pack("!BBH", 0, 6, len(wire) - 34)
        assert packets.internet_checksum(pseudo + wire[34:]) == 0
    unsupported = bytes.fromhex("00112233445566778899aabb88b5") + bytes(28)
    base = [syn, response, *payloads, unsupported]
    frames = {
        "recovered": [*base, packets.frame(seq=900000), packets.frame(seq=900000)],
        "suppressed": [*base, syn, syn],
        "normal": [
            syn,
            response,
            packets.frame(flags=24, seq=101, payload=b"abc"),
            packets.frame(flags=16, seq=501, ack=104, reverse=True),
        ],
    }
    return {
        name: packets.capture(
            *items,
            start_time=datetime.fromtimestamp(1700000000, UTC),
            interval=timedelta(milliseconds=1),
        )
        for name, items in frames.items()
    }


class _Queue:
    def __init__(self) -> None:
        self.jobs: list[dict[str, Any]] = []
        self.results: list[dict[str, Any]] = []
        self.acked: list[str] = []

    def ready(self) -> bool:
        return True

    def enqueue(self, job: dict[str, Any]) -> None:
        self.jobs.append(job)
        assert len(self.jobs) == 1

    def claim_result(self, timeout: int = 0) -> dict[str, Any] | None:
        del timeout
        return self.results.pop(0) if self.results else None

    def ack_result(self, receipt: str) -> None:
        self.acked.append(receipt)

    def recover(self) -> int:
        return 0


def _public_case(name: str, content: bytes) -> dict[str, Any]:
    from c2hunter_analysis.pcap import parse_pcap
    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.network_ai import build_network_input
    from c2hunter_controller.repositories import SQLiteRepository
    from c2hunter_controller.schemas import FlowRecord
    from c2hunter_worker.analysis import execute_analysis
    from fastapi.testclient import TestClient

    digest = hashlib.sha256(content).hexdigest()
    parsed = parse_pcap(
        content,
        sensor_id=f"pcap-upload:{digest[:12]}",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
        retain_network_evidence=True,
    )
    rows = [
        FlowRecord.model_validate(row).model_dump(mode="json") for row in parsed.records
    ]
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url="memory://",
        redis_url="memory://",
        clickhouse_url="memory://",
        s3_endpoint="memory://",
        api_auth_required=False,
        inline_flow_records_enabled=False,
        pcap_posting_index_enabled=False,
        pcap_offset_index_live_enabled=False,
    )
    queue = _Queue()
    with TemporaryDirectory(prefix="network-epoch-") as temporary:
        database = Path(temporary) / "epoch.sqlite3"
        with closing(SQLiteRepository(database)) as repo:
            app = create_app(settings, repo, queue=queue)
            with closing(TestClient(app)) as client:
                created = client.post(
                    "/api/v1/pcap-analysis-jobs",
                    params={
                        "name": f"Offline bounded epoch {name}",
                        "filename": f"epoch-{name}.pcap",
                        "analysis_module": "network_anomaly",
                        "internal_networks": "10.0.0.0/8",
                        "idempotency_key": f"epoch-{name}",
                    },
                    content=content,
                    headers={"content-type": "application/vnd.tcpdump.pcap"},
                )
                assert created.status_code == 201, created.text
                job_id = created.json()["id"]
                loaded = repo.get_job(job_id)
                assert loaded is not None
                typed = [
                    FlowRecord.model_validate(row).model_dump(mode="json")
                    for row in loaded["flow_records"]
                ]
                assert typed == rows
                assert (
                    loaded["source"]["captured_packet_count"]
                    == parsed.captured_packet_count
                )
                assert (
                    loaded["source"]["skipped_packet_count"]
                    == parsed.skipped_packet_count
                )
                result = execute_analysis(loaded)
                queue.results.append(
                    {
                        "receipt": job_id,
                        "job_id": job_id,
                        "status": "COMPLETED",
                        "result": result,
                    }
                )
                assert app.state.process_results_once() is True
                assert queue.acked == [job_id]
                assert queue.jobs == [{"id": job_id}]
                assert queue.results == []
                assert repo.get_job_capture(job_id) == content
        with closing(SQLiteRepository(database)) as reopened:
            with closing(
                TestClient(create_app(settings, reopened, queue=_Queue()))
            ) as client:
                path = f"/api/v1/analysis-jobs/{job_id}"
                response = client.get(path)
                assert response.status_code == 200, response.text
                job = response.json()
                assert job["status"] == "COMPLETED"
                assert "flow_records" not in job
                report = job["network_anomaly"]
                assert report == result["network_anomaly"]
    ai = build_network_input(report)
    assert ai["warnings"] == report["warnings"]
    return {
        "pcap_sha256": digest,
        "pcap_bytes": len(content),
        "parsed": {
            "captured": parsed.captured_packet_count,
            "parsed": parsed.parsed_packet_count,
            "skipped": parsed.skipped_packet_count,
        },
        "typed_records": rows,
        "typed_records_sha256": hashlib.sha256(canonical(rows).encode()).hexdigest(),
        "worker_result": result,
        "job": job,
        "report": report,
        "ai": ai,
        "public_response": {"method": "GET", "path": path, "status_code": 200},
        "report_sha256": hashlib.sha256(canonical(report).encode()).hexdigest(),
        "ai_sha256": hashlib.sha256(canonical(ai).encode()).hexdigest(),
    }


def build_bundle() -> dict[str, Any]:
    sys.path[:0] = [
        str(ROOT / p) for p in ("controller/src", "analysis/src", "sensor/worker/src")
    ]
    cases = {
        name: _public_case(name, content) for name, content in packet_captures().items()
    }
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in list(sys.modules.items())
        if name.startswith(
            ("c2hunter_analysis", "c2hunter_controller", "c2hunter_worker")
        )
        and getattr(module, "__file__", None)
    }
    assert origins and all(Path(path).is_relative_to(ROOT) for path in origins.values())
    return {
        "schema_version": "network-epoch-fixture-v1",
        "source": {
            "module_origins": origins,
            "live_capture_exercised": False,
            "model_invoked": False,
            "producer": "checksum-valid synthetic PCAP -> parse_pcap -> FlowRecord -> execute_analysis",
            "public_transport": "ASGI GET after result consumption and SQLite reopen",
            "native_aggregate_capability": "unchanged unsupported; no packet evidence fabricated",
            "variable_fields": "public job UUIDs and lifecycle timestamps only; report and AI input deterministic",
        },
        "cases": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projection", action="store_true")
    args = parser.parse_args()
    bundle = build_bundle()
    if args.projection:
        for case in bundle["cases"].values():
            del case["typed_records"]
            del case["worker_result"]
    print(canonical(bundle))


if __name__ == "__main__":
    main()
