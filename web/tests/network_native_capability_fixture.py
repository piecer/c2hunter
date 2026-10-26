"""Portable current-producer capability fixture; no LIVE socket or model call.

CLI: python web/tests/network_native_capability_fixture.py --batch-file B --pcap-file P
B is the unmodified flowbatch.Encode output of TestNetworkAggregateCapabilityFixture;
P is its exact synthetic testdata/network_capability_six.pcap. The Go test creates B
exclusively via C2HUNTER_NETWORK_CAPABILITY_OUTPUT; this adapter only reads B and P.

stdout is one network-native-capability-fixture-v1 JSON object, with exactly:
  schema_version, source, native, pcap.
source binds paths/hashes/counts/module origins and explicitly denies LIVE proof.
native contains batch, typed_records, ingestion, worker_result, job, public_response.
pcap contains typed_records, worker_result, job, public_response.
Both job values are actual serialized GET responses from an owned local ASGI app,
after real API admission, worker execution, result consumption and SQLite reopening.
No dictionary is relabeled LIVE: native admission is SENSOR_CAPTURE/HISTORICAL.
Go's {batch_id, flows} is explicitly adapted to HTTP {batch_id, records}, matching
sensor/internal/transport/http.go; records are not augmented before ingestion.
Only queue delivery is an in-memory test double, not the worker/report/HTTP routes.
Synthetic database state lives in an auto-cleaned temporary directory. Job UUIDs
and lifecycle timestamps are genuinely generated, so whole bundles vary per run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PCAP_SHA256 = "aa5cd301f6bcccaf6bd2f5d454780c83c21cc2df5bcd2b8a9d207db51e7d76bf"


class _Queue:
    """Bounded local queue transport; controller and worker remain unmodified."""

    def __init__(self) -> None:
        self.jobs: list[dict[str, Any]] = []
        self.results: list[dict[str, Any]] = []
        self.acked: list[str] = []

    def ready(self) -> bool:
        return True

    def enqueue(self, job: dict[str, Any]) -> None:
        self.jobs.append(job)
        assert len(self.jobs) <= 2

    def claim_result(self, timeout: int = 0) -> dict[str, Any] | None:
        del timeout
        return self.results.pop(0) if self.results else None

    def ack_result(self, receipt: str) -> None:
        self.acked.append(receipt)

    def recover(self) -> int:
        return 0


def build_bundle(batch_file: Path, pcap_file: Path) -> dict[str, Any]:
    sys.path[:0] = [
        str(ROOT / path)
        for path in ("controller/src", "analysis/src", "sensor/worker/src")
    ]
    from c2hunter_analysis.pcap import parse_pcap
    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.repositories import SQLiteRepository
    from c2hunter_controller.schemas import FlowRecord
    from c2hunter_controller.storage import MemoryFlowStore
    from c2hunter_worker.analysis import execute_analysis
    from fastapi.testclient import TestClient

    batch_file, pcap_file = batch_file.resolve(), pcap_file.resolve()
    # Closed tiny fixture, not a general capture importer.
    assert batch_file.stat().st_size <= 65_536
    assert pcap_file.stat().st_size == 450
    raw_batch, content = batch_file.read_bytes(), pcap_file.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    assert digest == PCAP_SHA256, "Not the owned six-frame synthetic PCAP"
    batch = json.loads(raw_batch)
    assert set(batch) == {"batch_id", "flows"}
    assert isinstance(batch["batch_id"], str) and len(batch["batch_id"]) == 64
    assert isinstance(batch["flows"], list) and len(batch["flows"]) == 2
    native_rows = [
        FlowRecord.model_validate(row).model_dump(mode="json") for row in batch["flows"]
    ]
    assert sum(row["packet_count"] for row in native_rows) == 6
    assert all(row["sensor_id"] == "s1" for row in native_rows)
    assert all(row["packet_evidence_complete"] is False for row in native_rows)
    assert all("packet_evidence_complete" not in row for row in batch["flows"])
    parsed = parse_pcap(
        content,
        sensor_id=f"pcap-upload:{digest[:12]}",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
        retain_network_evidence=True,
    )
    pcap_rows = [
        FlowRecord.model_validate(row).model_dump(mode="json") for row in parsed.records
    ]
    assert (
        parsed.captured_packet_count
        == parsed.parsed_packet_count
        == len(pcap_rows)
        == 6
    )
    assert parsed.skipped_packet_count == 0

    # All storage/services are explicitly local. No dotenv or external auth setup.
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
    with TemporaryDirectory(prefix="network-native-capability-") as temporary:
        database = Path(temporary) / "capability.sqlite3"
        with closing(SQLiteRepository(database)) as repo:
            # Admission identity only: no invented heartbeat/drop/clock observations.
            repo.upsert_sensor({"sensor_id": "s1"})
            token = "synthetic-network-capability-fixture"
            repo.save_sensor_credential(
                {
                    "sensor_id": "s1",
                    "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                }
            )
            app = create_app(settings, repo, flow_store=MemoryFlowStore(), queue=queue)
            # No lifespan startup: explicitly drive only the two queue deliveries.
            with closing(TestClient(app)) as client:
                response = client.post(
                    "/api/v1/sensors/s1/flow-batches",
                    json={"batch_id": batch["batch_id"], "records": batch["flows"]},
                    headers={"X-Sensor-Token": token},
                )
                assert response.status_code == 202, response.text
                ingestion = response.json()
                assert ingestion == {
                    "batch_id": batch["batch_id"],
                    "accepted": True,
                    "duplicate": False,
                    "record_count": 2,
                }
                start = min(
                    datetime.fromisoformat(row["timestamp"]) for row in native_rows
                )
                native_created = client.post(
                    "/api/v1/analysis-jobs",
                    json={
                        "name": "Synthetic native aggregate capability (offline)",
                        "idempotency_key": "native-capability",
                        "sensor_ids": ["s1"],
                        "mode": "HISTORICAL",
                        "start_time": start.isoformat(),
                        "end_time": (start + timedelta(seconds=1)).isoformat(),
                        "capture": {"directions": ["INBOUND", "OUTBOUND", "UNKNOWN"]},
                        "analysis": {"module": "network_anomaly"},
                        "internal_networks": ["10.0.0.0/8"],
                    },
                )
                assert native_created.status_code == 201, native_created.text
                pcap_created = client.post(
                    "/api/v1/pcap-analysis-jobs",
                    params={
                        "name": "Synthetic same-byte PCAP positive control",
                        "filename": "network_capability_six.pcap",
                        "analysis_module": "network_anomaly",
                        "internal_networks": "10.0.0.0/8",
                        "idempotency_key": "pcap-capability",
                    },
                    content=content,
                    headers={"content-type": "application/vnd.tcpdump.pcap"},
                )
                assert pcap_created.status_code == 201, pcap_created.text
                cases: dict[str, Any] = {}
                for name, created, rows in (
                    ("native", native_created.json(), native_rows),
                    ("pcap", pcap_created.json(), pcap_rows),
                ):
                    assert created["status"] == "ANALYZING"
                    job_id = created["id"]
                    loaded = repo.get_job(job_id)
                    assert loaded is not None
                    typed = [
                        FlowRecord.model_validate(row).model_dump(mode="json")
                        for row in loaded["flow_records"]
                    ]
                    assert typed == rows, (
                        "Admission changed or omitted producer records"
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
                    assert job_id in queue.acked
                    cases[name] = {"typed_records": typed, "worker_result": result}
                assert queue.jobs == [
                    {"id": native_created.json()["id"]},
                    {"id": pcap_created.json()["id"]},
                ]
                assert queue.results == []
                assert len(queue.acked) == 2
                assert repo.get_job_capture(pcap_created.json()["id"]) == content
            # Reopen durable data and invoke the actual public projection/serializer.
        with closing(SQLiteRepository(database)) as reopened:
            with closing(
                TestClient(create_app(settings, reopened, queue=_Queue()))
            ) as public:
                for name, created in (
                    ("native", native_created),
                    ("pcap", pcap_created),
                ):
                    path = f"/api/v1/analysis-jobs/{created.json()['id']}"
                    response = public.get(path)
                    assert response.status_code == 200, response.text
                    job = response.json()
                    assert job["status"] == "COMPLETED"
                    assert (
                        job["network_anomaly"]
                        == cases[name]["worker_result"]["network_anomaly"]
                    )
                    assert "flow_records" not in job
                    cases[name].update(
                        job=job,
                        public_response={
                            "method": "GET",
                            "path": path,
                            "status_code": 200,
                        },
                    )

    native_report = cases["native"]["job"]["network_anomaly"]
    assert native_report["summary"]["evaluated_records"] == 0
    assert native_report["summary"]["incomplete_records"] == 2
    assert native_report["summary"]["verdict"] == "insufficient_evidence"
    assert "SENSOR_CAPTURE_QUALITY_UNAVAILABLE" in native_report["warnings"]
    assert native_report["issues"] == []
    positive = cases["pcap"]["job"]["network_anomaly"]
    assert positive["summary"]["evaluated_records"] == 6
    assert positive["summary"]["verdict"] == "anomaly_observed"
    assert {issue["pattern"]: issue["event_count"] for issue in positive["issues"]} == {
        "syn_retransmissions": 1,
        "data_retransmissions": 1,
    }
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in list(sys.modules.items())
        if name.startswith(
            ("c2hunter_controller", "c2hunter_analysis", "c2hunter_worker")
        )
        and getattr(module, "__file__", None)
    }
    assert origins and all(Path(path).is_relative_to(ROOT) for path in origins.values())
    cases["native"].update(batch=batch, ingestion=ingestion)
    return {
        "schema_version": "network-native-capability-fixture-v1",
        "source": {
            "pcap_file": str(pcap_file),
            "pcap_sha256": digest,
            "batch_file": str(batch_file),
            "native_batch_sha256": hashlib.sha256(raw_batch).hexdigest(),
            "native_packet_count": sum(row["packet_count"] for row in native_rows),
            "native_record_count": len(native_rows),
            "live_capture_exercised": False,
            "native_producer": "capture.NewOfflineReader -> flow.NewAggregator -> flowbatch.New/Encode",
            "native_admission": "HISTORICAL snapshot of native aggregates; not a LIVE lifecycle",
            "batch_adapter": "Go flows -> HTTP records; no per-record evidence augmentation",
            "public_transport": "local ASGI TestClient GET after worker result and SQLite reopen",
            "module_origins": origins,
        },
        **cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-file", type=Path, required=True)
    parser.add_argument("--pcap-file", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            build_bundle(args.batch_file, args.pcap_file),
            sort_keys=True,
            allow_nan=False,
        )
    )


if __name__ == "__main__":
    main()
