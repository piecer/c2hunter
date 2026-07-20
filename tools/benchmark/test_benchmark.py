import importlib.util
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

MODULE = Path(__file__).with_name("benchmark.py")
spec = importlib.util.spec_from_file_location("benchmark", MODULE)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class BenchmarkTest(unittest.TestCase):
    def test_window_keeps_bounded_recent_series_samples(self):
        window = benchmark.RepresentativeFlowWindow(limit=20)
        for index in range(12):
            window.offer(
                benchmark.Flow(
                    "sensor",
                    benchmark.START + timedelta(seconds=index * 60),
                    "10.0.0.1",
                    benchmark.C2_IP,
                    40000,
                    443,
                    "UDP",
                    "OUTBOUND",
                )
            )

        self.assertEqual(len(window.flows), benchmark.SUSPICIOUS_SERIES_SAMPLES)
        self.assertEqual(
            [flow.timestamp for flow in window.flows],
            [benchmark.START + timedelta(seconds=index * 60) for index in range(4, 12)],
        )

    def test_streams_exact_count_and_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            result = benchmark.run(
                packet_count=10_003,
                chunk_size=1_000,
                output_dir=Path(directory),
                seed=7,
            )
            self.assertEqual(result["packets_processed"], 10_003)
            self.assertEqual(result["chunks_processed"], 11)
            self.assertTrue(result["streaming"])
            self.assertEqual(result["packet_loss"], 0)
            self.assertGreater(result["flows_generated"], 0)
            self.assertNotIn("detector_counts", result)
            self.assertEqual(result["schema_version"], 2)
            self.assertLessEqual(
                result["analysis_input"]["representative_flows"],
                result["analysis_input"]["representative_flow_limit"],
            )
            self.assertEqual(
                result["analysis_input"]["measurement_scope"],
                "all packets streamed; detectors scored a bounded representative Flow window",
            )
            execution = result["analysis_engine"]["detector_execution"]
            self.assertEqual(
                len(execution), result["analysis_engine"]["detectors_configured"]
            )
            self.assertTrue(all(item["executed"] for item in execution))
            self.assertTrue(
                all(
                    item["implementation_type"].startswith("c2hunter_analysis.")
                    for item in execution
                )
            )
            self.assertTrue(all(item["version"] for item in execution))
            self.assertTrue(all("evidence_types" in item for item in execution))
            self.assertEqual(
                result["evidence"]["total"],
                sum(result["evidence"]["counts_by_type"].values()),
            )
            self.assertEqual(
                result["analysis_engine"]["run_detectors_function"],
                "c2hunter_analysis.detectors.run_detectors",
            )
            self.assertEqual(
                result["analysis_engine"]["score_candidates_function"],
                "c2hunter_analysis.scoring.score_candidates",
            )
            self.assertTrue(result["analysis_engine"]["package_version"])
            self.assertTrue(result["scoring"]["executed"])
            saved = json.loads(Path(directory, "benchmark-1m.json").read_text())
            self.assertEqual(saved["packets_processed"], 10_003)
            markdown = Path(directory, "benchmark-1m.md").read_text()
            self.assertIn("Peak RSS", markdown)
            self.assertIn("Bounded analysis input", markdown)
            self.assertIn("Implementation type", markdown)


if __name__ == "__main__":
    unittest.main()
