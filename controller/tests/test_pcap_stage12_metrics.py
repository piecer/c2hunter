from __future__ import annotations

from typing import Any

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from c2hunter_controller import pcap_export_worker as worker_module
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_export_metrics import PcapExportMetrics
from c2hunter_controller.pcap_export_service import PcapExportDependencies
from c2hunter_controller.repositories import MemoryRepository


def _observe(metrics: PcapExportMetrics, **changes: Any) -> None:
    values: dict[str, Any] = {
        "path": "indexed",
        "fallback_reason": "none",
        "shadow_parity": "not_applicable",
        "requested_range_count": 7,
        "coalesced_range_count": 3,
        "selected_payload_bytes": 100,
        "fetched_bytes": 150,
        "source_total_bytes": 1000,
    }
    values.update(changes)
    metrics.rollout_observer(**values)


def test_rollout_metrics_increment_exact_totals_and_bounded_labels() -> None:
    registry = CollectorRegistry()
    metrics = PcapExportMetrics(registry)

    _observe(metrics)
    _observe(
        metrics,
        path="fallback",
        fallback_reason="range_missing",
        shadow_parity="not_applicable",
        requested_range_count=0,
        coalesced_range_count=0,
        selected_payload_bytes=0,
        fetched_bytes=0,
    )
    _observe(
        metrics,
        path="shadow",
        shadow_parity="mismatch",
        requested_range_count=4,
        coalesced_range_count=2,
        selected_payload_bytes=40,
        fetched_bytes=100,
        source_total_bytes=200,
    )
    text = generate_latest(registry).decode()

    assert 'c2hunter_pcap_indexed_export_executions_total{path="indexed"} 1.0' in text
    assert 'c2hunter_pcap_indexed_export_executions_total{path="fallback"} 1.0' in text
    assert 'c2hunter_pcap_indexed_export_executions_total{path="shadow"} 1.0' in text
    assert 'c2hunter_pcap_indexed_export_fallback_total{reason="range_missing"} 1.0' in text
    assert "c2hunter_pcap_indexed_export_requested_ranges_total 11.0" in text
    assert "c2hunter_pcap_indexed_export_coalesced_ranges_total 5.0" in text
    assert "c2hunter_pcap_indexed_export_selected_payload_bytes_total 140.0" in text
    assert "c2hunter_pcap_indexed_export_fetched_bytes_total 250.0" in text
    assert "c2hunter_pcap_indexed_export_source_saved_bytes_total 950.0" in text
    assert 'c2hunter_pcap_indexed_export_amplification_total{bucket="le_2"} 1.0' in text
    assert 'c2hunter_pcap_indexed_export_amplification_total{bucket="le_4"} 1.0' in text
    assert 'c2hunter_pcap_indexed_export_source_fraction_total{bucket="le_25pct"} 1.0' in text
    assert 'c2hunter_pcap_indexed_export_source_fraction_total{bucket="le_50pct"} 1.0' in text
    assert 'c2hunter_pcap_indexed_export_shadow_parity_total{result="mismatch"} 1.0' in text


def test_rollout_metric_labels_have_fixed_vocabulary_and_no_raw_values() -> None:
    registry = CollectorRegistry()
    metrics = PcapExportMetrics(registry)
    _observe(metrics)
    _observe(metrics, path="shadow", shadow_parity="match")
    _observe(metrics, path="sequential", shadow_parity="not_sampled")
    _observe(metrics, path="fallback", fallback_reason="version_drift")

    rollout_samples = [
        sample
        for family in registry.collect()
        for sample in family.samples
        if sample.name.startswith("c2hunter_pcap_indexed_export_")
    ]
    allowed_keys = {"path", "reason", "result", "bucket"}
    allowed_values = {
        "indexed",
        "shadow",
        "sequential",
        "fallback",
        "version_drift",
        "match",
        "not_sampled",
        "le_1",
        "le_2",
        "le_4",
        "le_8",
        "gt_8",
        "le_10pct",
        "le_25pct",
        "le_50pct",
        "le_75pct",
        "le_100pct",
    }
    assert rollout_samples
    assert all(set(sample.labels) <= allowed_keys for sample in rollout_samples)
    assert all(
        value in allowed_values for sample in rollout_samples for value in sample.labels.values()
    )
    text = generate_latest(registry).decode()
    assert "job-" not in text
    assert "sha256" not in text
    assert "digest" not in text


def test_rollout_metric_adapter_is_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    metrics = PcapExportMetrics(CollectorRegistry())

    class BrokenCounter:
        def labels(self, **_labels: str) -> BrokenCounter:
            return self

        def inc(self, _amount: int = 1) -> None:
            raise RuntimeError("metrics unavailable")

    monkeypatch.setattr(metrics, "indexed_executions_total", BrokenCounter())
    _observe(metrics)


def test_app_uses_one_registry_for_queue_and_rollout_metrics() -> None:
    app = create_app(Settings(environment="test"), MemoryRepository())
    metrics = app.state.pcap_export_metrics
    observer = app.state.pcap_export_executor.dependencies.rollout_observer

    assert observer is not None
    assert observer == metrics.rollout_observer
    names = {family.name for family in app.state.metrics_registry.collect()}
    assert "c2hunter_pcap_export_queue_depth" in names
    assert "c2hunter_pcap_indexed_export_executions" in names


def test_worker_wires_existing_metrics_observer_without_registering_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = CollectorRegistry()
    metrics = PcapExportMetrics(registry)
    captured: list[PcapExportDependencies] = []

    class Executor:
        def __init__(
            self,
            _repository: object,
            _settings: Settings,
            dependencies: PcapExportDependencies,
        ) -> None:
            captured.append(dependencies)

        def execute(self, *_args: object, **_kwargs: object) -> dict[str, Any]:
            return {}

    monkeypatch.setattr(worker_module, "PcapExportExecutor", Executor)
    worker_module.create_pcap_export_worker(
        MemoryRepository(), Settings(environment="test"), metrics=metrics
    )

    assert len(captured) == 1
    observer = captured[0].rollout_observer
    assert observer is not None
    assert observer == metrics.rollout_observer
    names = [family.name for family in registry.collect()]
    assert len(names) == len(set(names))
