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
