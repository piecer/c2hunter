from __future__ import annotations

from itertools import product

from prometheus_client import CollectorRegistry, generate_latest

from c2hunter_controller.pcap_posting_index_metrics import (
    ADMISSION_OUTCOMES,
    BUILD_OUTCOMES,
    QUEUE_STATUSES,
    SOURCE_KINDS,
    TASK_OUTCOMES,
    TASK_REASONS,
    PcapPostingIndexMetrics,
)


def test_metrics_module_uses_an_isolated_registry_by_default() -> None:
    first = PcapPostingIndexMetrics()
    second = PcapPostingIndexMetrics()

    assert isinstance(first.registry, CollectorRegistry)
    assert first.registry is not second.registry


def test_metric_collectors_have_only_the_frozen_label_contracts() -> None:
    metrics = PcapPostingIndexMetrics()

    assert metrics._admissions._labelnames == ("source_kind", "outcome")
    assert metrics._tasks._labelnames == ("source_kind", "outcome", "reason")
    assert metrics._depth._labelnames == ("status",)
    assert metrics._build_seconds._labelnames == ("source_kind", "outcome")
    assert metrics._memberships._labelnames == ("source_kind",)
    assert metrics._encoded_bytes._labelnames == ("source_kind",)


def test_every_permitted_label_tuple_has_bounded_cardinality() -> None:
    registry = CollectorRegistry()
    metrics = PcapPostingIndexMetrics(registry)
    for source_kind, outcome in product(SOURCE_KINDS, ADMISSION_OUTCOMES):
        metrics.admission(source_kind, outcome)
    for source_kind, outcome, reason in product(SOURCE_KINDS, TASK_OUTCOMES, TASK_REASONS):
        metrics.task(source_kind, outcome, reason)
    for source_kind, outcome in product(SOURCE_KINDS, BUILD_OUTCOMES):
        metrics.build(source_kind, outcome, 0.01)
    for source_kind in SOURCE_KINDS:
        metrics.generation(source_kind, 1, 2)
    metrics.reconcile_depth(dict.fromkeys(QUEUE_STATUSES, 1))

    samples = [sample for metric in registry.collect() for sample in metric.samples]
    admission_tuples = {
        (sample.labels["source_kind"], sample.labels["outcome"])
        for sample in samples
        if sample.name == "c2hunter_pcap_posting_index_admissions_total"
    }
    task_tuples = {
        (sample.labels["source_kind"], sample.labels["outcome"], sample.labels["reason"])
        for sample in samples
        if sample.name == "c2hunter_pcap_posting_index_tasks_total"
    }
    assert admission_tuples == set(product(SOURCE_KINDS, ADMISSION_OUTCOMES))
    assert task_tuples == set(product(SOURCE_KINDS, TASK_OUTCOMES, TASK_REASONS))
    assert len(admission_tuples) == len(SOURCE_KINDS) * len(ADMISSION_OUTCOMES)
    assert len(task_tuples) == len(SOURCE_KINDS) * len(TASK_OUTCOMES) * len(TASK_REASONS)


def test_unknown_labels_normalize_to_other_without_leaking_values() -> None:
    registry = CollectorRegistry()
    metrics = PcapPostingIndexMetrics(registry)
    secret = "10.2.3.4:443/source-file.pcap/sha256/token/error-text"

    metrics.admission(secret, secret)
    metrics.task(secret, secret, secret)
    metrics.build(secret, secret, 1)
    metrics.generation(secret, 3, 4)
    metrics.reconcile_depth({secret: 7})

    text = generate_latest(registry).decode()
    assert secret not in text
    assert 'source_kind="other"' in text
    assert 'outcome="other"' in text
    assert 'reason="other"' in text
    assert 'status="other"} 7.0' in text
