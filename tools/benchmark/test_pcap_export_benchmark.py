import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).with_name("pcap_export.py")
spec = importlib.util.spec_from_file_location("pcap_export_benchmark", MODULE)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class PcapExportBenchmarkTest(unittest.TestCase):
    def test_rss_bytes_converts_linux_kib_to_bytes(self):
        usage = type("Usage", (), {"ru_maxrss": 12_345})()

        with (
            patch.object(sys, "platform", "linux"),
            patch.object(benchmark.resource, "getrusage", return_value=usage),
        ):
            self.assertEqual(benchmark._rss_bytes(), 12_345 * 1024)

    def test_rss_bytes_preserves_darwin_bytes(self):
        usage = type("Usage", (), {"ru_maxrss": 12_345})()

        with (
            patch.object(sys, "platform", "darwin"),
            patch.object(benchmark.resource, "getrusage", return_value=usage),
        ):
            self.assertEqual(benchmark._rss_bytes(), 12_345)

    def test_plan_preserves_the_approved_twelve_stage_sequence(self):
        plan = (
            Path(__file__).parents[2]
            / "docs/pcap-export-performance-implementation-plan.md"
        )
        rows = [line for line in plan.read_text().splitlines() if line.startswith("| ")]
        change_boundaries = [row.split("|")[2].strip() for row in rows[1:]]

        self.assertEqual(
            change_boundaries,
            [
                "Baseline benchmark + metrics.",
                "`get_job_summary` lazy loading + direct candidate + job-scoped segment query.",
                "Repository streaming source API.",
                "Export-only lightweight decoder.",
                "Decode-time one-pass filtering.",
                "Spooled boundary-aware writer.",
                "Streaming artifact save/download.",
                "Small-sync/large-durable-async hybrid.",
                "Offline upload structural packet-offset index.",
                "LIVE segment background structural indexing.",
                "Candidate/filter posting index.",
                "Safe index-driven coalesced range reads.",
            ],
        )

    def test_workload_fingerprint_does_not_bind_the_implementation_name(self):
        fingerprint = benchmark.workload_fingerprint(
            packet_count=8,
            seed=5,
            source_sha256="abc",
        )

        self.assertEqual(
            fingerprint,
            benchmark.workload_fingerprint(packet_count=8, seed=5, source_sha256="abc"),
        )

    def test_bounded_run_emits_machine_readable_stage_and_volume_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            report = benchmark.run(packet_count=64, output_dir=Path(directory), seed=17)

            self.assertEqual(report["schema_version"], 1)
            self.assertEqual(report["implementation"], "spooled-boundary-aware-v1")
            self.assertEqual(report["workload"]["seed"], 17)
            self.assertEqual(report["counters"]["packets"]["source"], 64)
            self.assertEqual(report["counters"]["packets"]["exported"], 64)
            self.assertGreater(report["counters"]["bytes"]["source"], 0)
            self.assertGreater(report["counters"]["bytes"]["output"], 0)
            self.assertGreater(report["peak_rss_bytes"], 0)
            self.assertEqual(report["writer"]["input_passes"], 1)
            self.assertTrue(report["writer"]["rolled_over"])
            self.assertEqual(
                report["writer"]["artifact_sha256"], report["workload"]["output_sha256"]
            )
            self.assertEqual(
                report["writer"]["artifact_size_bytes"],
                report["counters"]["bytes"]["output"],
            )
            self.assertEqual(
                list(report["stages"]),
                [
                    "source_read",
                    "hash",
                    "frame",
                    "decode",
                    "filter",
                    "write",
                    "save",
                    "total",
                ],
            )
            for stage in report["stages"].values():
                self.assertGreaterEqual(stage["duration_seconds"], 0)
                self.assertGreater(stage["rss_bytes"], 0)
                self.assertIn("packets", stage)
                self.assertIn("bytes", stage)

            saved = json.loads(Path(directory, "pcap-export-baseline.json").read_text())
            self.assertEqual(
                saved["workload"]["source_sha256"], report["workload"]["source_sha256"]
            )
            self.assertEqual(
                saved["workload"]["output_sha256"], report["workload"]["output_sha256"]
            )

    def test_stage12_report_uses_production_factory_and_has_exact_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            report = benchmark.run_stage12(
                output_dir=Path(directory), packet_count=24, seed=31
            )

        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(
            report["implementation"], "stage12-production-indexed-factory-v1"
        )
        descriptions = report["schema_descriptions"]
        self.assertIn(
            "final execution bytes avoided versus sequential",
            descriptions["source_bytes_saved"],
        )
        self.assertIn("null", descriptions["indexed"])
        self.assertIn("null", descriptions["parity"])
        self.assertIn(
            "candidate packet payload requests", descriptions["original_request_count"]
        )
        self.assertIn(
            "complete admitted range plan", descriptions["coalesced_range_count"]
        )
        self.assertIn(
            "range calls actually issued", descriptions["attempted_range_count"]
        )
        self.assertIn("bytes actually returned", descriptions["received_range_bytes"])
        self.assertIn("authoritative final output", descriptions["final_artifact"])
        self.assertEqual(
            [item["workload"] for item in report["workloads"]],
            [
                "sparse",
                "clustered",
                "dense_fallback",
                "multi_source_live",
                "pcapng_multi_interface",
                "range_limit_plus_one",
                "short_read",
                "version_drift",
            ],
        )
        exact = {
            "workload",
            "path",
            "fallback_reason",
            "indexed_support_reason",
            "plan_available",
            "selected_packet_count",
            "original_request_count",
            "coalesced_range_count",
            "selected_bytes",
            "planned_range_bytes",
            "attempted_range_count",
            "attempted_range_bytes",
            "received_range_bytes",
            "fetched_bytes",
            "source_bytes",
            "source_bytes_saved",
            "amplification",
            "source_fraction",
            "source_count",
            "source_ids",
            "range_source_ids",
            "interface_count",
            "sequential",
            "indexed",
            "final_artifact",
            "parity",
            "peak_rss_bytes",
            "stages",
        }
        indexed_names = {
            "sparse",
            "clustered",
            "multi_source_live",
            "pcapng_multi_interface",
        }
        for item in report["workloads"]:
            self.assertEqual(set(item), exact)
            self.assertGreater(item["original_request_count"], 0)
            self.assertGreater(item["selected_bytes"], 0)
            self.assertEqual(
                item["source_bytes_saved"],
                0
                if item["path"] == "fallback"
                else max(0, item["source_bytes"] - item["fetched_bytes"]),
            )
            self.assertEqual(
                item["source_fraction"],
                item["fetched_bytes"] / max(1, item["source_bytes"]),
            )
            self.assertEqual(
                set(item["sequential"]),
                {"artifact_sha256", "artifact_size_bytes", "packet_count"},
            )
            self.assertEqual(
                set(item["final_artifact"]),
                {"artifact_sha256", "artifact_size_bytes", "packet_count"},
            )
            self.assertGreater(item["peak_rss_bytes"], 0)
            if item["plan_available"]:
                self.assertEqual(item["indexed_support_reason"], "supported")
                self.assertIsInstance(item["coalesced_range_count"], int)
                self.assertIsInstance(item["planned_range_bytes"], int)
                self.assertEqual(
                    item["amplification"],
                    {
                        "numerator": item["planned_range_bytes"],
                        "denominator": max(1, item["selected_bytes"]),
                        "value": item["planned_range_bytes"]
                        / max(1, item["selected_bytes"]),
                    },
                )
            else:
                self.assertEqual(
                    item["indexed_support_reason"], item["fallback_reason"]
                )
                self.assertIsNone(item["coalesced_range_count"])
                self.assertIsNone(item["planned_range_bytes"])
                self.assertIsNone(item["amplification"])
            if item["workload"] in indexed_names:
                self.assertEqual(item["path"], "indexed")
                self.assertIsNotNone(item["indexed"])
                self.assertEqual(item["final_artifact"], item["indexed"])
                self.assertTrue(all(item["parity"].values()))
                self.assertEqual(item["fetched_bytes"], item["received_range_bytes"])
            else:
                self.assertEqual(item["path"], "fallback")
                self.assertIsNone(item["indexed"])
                self.assertIsNone(item["parity"])
                self.assertEqual(item["final_artifact"], item["sequential"])
                self.assertEqual(item["source_bytes_saved"], 0)
                self.assertGreaterEqual(item["fetched_bytes"], item["source_bytes"])
        sparse, clustered = report["workloads"][:2]
        self.assertTrue(sparse["plan_available"])
        self.assertTrue(clustered["plan_available"])
        self.assertLess(
            clustered["coalesced_range_count"], clustered["original_request_count"]
        )
        multi_source = report["workloads"][3]
        self.assertEqual(multi_source["source_count"], 2)
        self.assertEqual(len(set(multi_source["source_ids"])), 2)
        self.assertEqual(
            set(multi_source["range_source_ids"]), set(multi_source["source_ids"])
        )
        self.assertGreaterEqual(multi_source["coalesced_range_count"], 2)
        pcapng = report["workloads"][4]
        self.assertEqual(pcapng["interface_count"], 2)
        self.assertEqual(pcapng["indexed_support_reason"], "supported")
        resource_cases = (report["workloads"][2], report["workloads"][5])
        for item in resource_cases:
            self.assertEqual(item["fallback_reason"], "resource_limit")
            self.assertFalse(item["plan_available"])
            self.assertEqual(item["attempted_range_count"], 0)
            self.assertEqual(item["attempted_range_bytes"], 0)
            self.assertEqual(item["received_range_bytes"], 0)
        short_read, version_drift = report["workloads"][6:]
        self.assertEqual(short_read["fallback_reason"], "range_short")
        self.assertEqual(version_drift["fallback_reason"], "version_drift")
        for item in (short_read, version_drift):
            self.assertTrue(item["plan_available"])
            self.assertGreater(item["attempted_range_count"], 0)
            self.assertGreater(item["attempted_range_bytes"], 0)
        self.assertGreater(short_read["received_range_bytes"], 0)
        self.assertLess(
            short_read["received_range_bytes"], short_read["attempted_range_bytes"]
        )
        self.assertEqual(version_drift["received_range_bytes"], 0)

    def test_seeded_workload_is_comparable_and_comparison_reports_ratios(self):
        with (
            tempfile.TemporaryDirectory() as first,
            tempfile.TemporaryDirectory() as second,
        ):
            baseline = benchmark.run(packet_count=32, output_dir=Path(first), seed=23)
            current = benchmark.run(packet_count=32, output_dir=Path(second), seed=23)

            comparison = benchmark.compare_reports(current, baseline)

            self.assertTrue(comparison["compatible"])
            self.assertEqual(
                current["workload"]["source_sha256"],
                baseline["workload"]["source_sha256"],
            )
            self.assertEqual(
                current["workload"]["output_sha256"],
                baseline["workload"]["output_sha256"],
            )
            self.assertEqual(
                current["workload"]["fingerprint"], baseline["workload"]["fingerprint"]
            )
            self.assertEqual(
                Path(first, "pcap-export-baseline.pcap").read_bytes(),
                Path(second, "pcap-export-baseline.pcap").read_bytes(),
            )
            self.assertEqual(
                comparison["workload_fingerprint"], baseline["workload"]["fingerprint"]
            )
            self.assertEqual(
                set(comparison["duration_ratio_by_stage"]), set(baseline["stages"])
            )
            self.assertGreater(comparison["total_duration_ratio"], 0)

            incompatible = benchmark.compare_reports(
                benchmark.run(packet_count=32, output_dir=Path(second), seed=24),
                baseline,
            )
            self.assertFalse(incompatible["compatible"])
            self.assertEqual(incompatible["duration_ratio_by_stage"], {})
            self.assertIsNone(incompatible["total_duration_ratio"])


if __name__ == "__main__":
    unittest.main()
