"""Custom detector plugin framework tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from c2hunter_analysis.custom import (
    MAX_CUSTOM_EVIDENCE,
    CustomDetector,
    CustomDetectorError,
    DetectorExecutionError,
    DetectorLoaderError,
    DetectorRegistryCache,
    build_detector_registry,
    discover_custom_detectors,
    load_custom_detector_from_script,
)
from c2hunter_analysis.detectors import run_detectors
from c2hunter_analysis.domain import AnalysisContext, Evidence


def context() -> AnalysisContext:
    return AnalysisContext(
        dataset_id="custom-detector-test",
        start=datetime.fromisoformat("2026-01-01T00:00:00+00:00"),
        end=datetime.fromisoformat("2026-01-01T01:00:00+00:00"),
        flows=[],
    )


def evidence(
    *,
    detector: str = "placeholder",
    version: str = "0",
    kind: str = "COMMON_DESTINATION",
) -> Evidence:
    return Evidence(
        candidate_ip="203.0.113.9",
        type=kind,
        detector=detector,
        version=version,
        raw_score=5,
        contribution=5,
        description="custom detector finding",
    )


def test_create_detector_from_function_normalizes_provenance() -> None:
    def my_detector(_context: AnalysisContext) -> list[Evidence]:
        return [evidence()]

    detector = CustomDetector.from_function(
        my_detector,
        name="test-detector",
        version="2.1.0",
    )

    assert detector.name == "test-detector"
    assert detector.version == "2.1.0"
    assert detector.analyze(context())[0].detector == "test-detector"
    assert detector.analyze(context())[0].version == "2.1.0"


def test_detector_from_function_uses_function_name() -> None:
    def my_detector(_context: AnalysisContext) -> list[Evidence]:
        return []

    detector = CustomDetector.from_function(my_detector)

    assert detector.name == "my_detector"
    assert detector.version == "1.0.0"


def test_detector_from_object_uses_metadata() -> None:
    class ExampleDetector:
        name = "example"
        version = "3.0.0"

        def analyze(self, _context: AnalysisContext) -> list[Evidence]:
            return []

    detector = CustomDetector.from_object(ExampleDetector())

    assert detector.name == "example"
    assert detector.version == "3.0.0"


def test_detector_from_class_instantiates_zero_argument_detector() -> None:
    class DetectorClass:
        name = "class-detector"
        version = "3.0.0"

        def analyze(self, _context: AnalysisContext) -> list[Evidence]:
            return []

    detector = CustomDetector.from_class(DetectorClass)

    assert detector.name == "class-detector"
    assert detector.analyze(context()) == []


def test_detector_rejects_async_and_invalid_signatures() -> None:
    async def asynchronous(_context: AnalysisContext) -> list[Evidence]:
        return []

    def missing_context() -> list[Evidence]:
        return []

    def optional_keyword(_context: AnalysisContext, *, enabled: bool = True) -> list[Evidence]:
        return [] if enabled else []

    def variadic(_context: AnalysisContext, **_kwargs: object) -> list[Evidence]:
        return []

    with pytest.raises(DetectorLoaderError, match="must be synchronous"):
        CustomDetector.from_function(asynchronous, name="async")  # type: ignore[arg-type]
    with pytest.raises(DetectorLoaderError, match="must accept exactly one context"):
        CustomDetector.from_function(missing_context, name="missing")  # type: ignore[arg-type]
    with pytest.raises(DetectorLoaderError, match="must accept exactly one context"):
        CustomDetector.from_function(optional_keyword, name="optional")  # type: ignore[arg-type]
    with pytest.raises(DetectorLoaderError, match="must accept exactly one context"):
        CustomDetector.from_function(variadic, name="variadic")  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["", "   "])
def test_detector_rejects_empty_name(name: str) -> None:
    with pytest.raises(DetectorLoaderError, match="name must be a non-empty string"):
        CustomDetector.from_function(lambda _context: [], name=name)


def test_detector_rejects_invalid_result_container() -> None:
    detector = CustomDetector.from_function(
        lambda _context: (),  # type: ignore[arg-type]
        name="invalid-container",
    )

    with pytest.raises(CustomDetectorError, match=r"must return list\[Evidence\]"):
        detector.analyze(context())


def test_detector_rejects_non_evidence_result() -> None:
    detector = CustomDetector.from_function(
        lambda _context: [object()],  # type: ignore[list-item,return-value]
        name="invalid-item",
    )

    with pytest.raises(CustomDetectorError, match="item 0 is object, expected Evidence"):
        detector.analyze(context())


def test_detector_rejects_unscored_evidence_types_and_excessive_results() -> None:
    unknown_type = CustomDetector.from_function(
        lambda _context: [evidence(kind="CUSTOM_UNKNOWN")],
        name="unknown-type",
    )
    excessive = CustomDetector.from_function(
        lambda _context: [evidence()] * (MAX_CUSTOM_EVIDENCE + 1),
        name="excessive",
    )

    with pytest.raises(CustomDetectorError, match="unsupported evidence type CUSTOM_UNKNOWN"):
        unknown_type.analyze(context())
    with pytest.raises(CustomDetectorError, match="returned 10001 evidence items"):
        excessive.analyze(context())


@pytest.mark.parametrize(
    ("invalid", "message"),
    [
        (replace(evidence(), contribution="5"), "contribution must be a finite number"),
        (replace(evidence(), raw_score=True), "raw_score must be a finite number"),
        (replace(evidence(), raw_score=10**1000), "raw_score must be between 0 and 100"),
        (replace(evidence(), raw_score=-1), "raw_score must be between 0 and 100"),
        (replace(evidence(), contribution=101), "contribution must be between 0 and 100"),
        (replace(evidence(), contribution=-1), "contribution must be between 0 and 100"),
        (replace(evidence(), confidence=1.1), "confidence must be between 0 and 1"),
        (replace(evidence(), candidate_ip=123), "candidate_ip must be a string"),
        (replace(evidence(), type=123), "type must be a non-empty string"),
        (replace(evidence(), hosts=("10.0.0.1", 2)), "hosts must be a tuple of strings"),
        (replace(evidence(), metrics={"invalid": object()}), "metrics must be JSON-compatible"),
        (
            replace(evidence(), metrics={"when": datetime.now(UTC)}),
            "metrics must be JSON-compatible",
        ),
        (replace(evidence(), metrics={"huge": 10**10000}), "metrics must be JSON-compatible"),
        (replace(evidence(), metrics={"sample_count": {}}), "sample_count must be an integer"),
        (
            replace(evidence(), metrics={"public_dns_ntp": "yes"}),
            "public_dns_ntp must be a boolean",
        ),
        (replace(evidence(), metrics={"cdn_cloud": 1}), "cdn_cloud must be a boolean"),
        (replace(evidence(), metrics={"match_mode": {}}), "match_mode must be a string"),
        (
            replace(evidence(), first_seen=datetime(2026, 1, 1)),
            "first_seen must be timezone-aware",
        ),
        (
            replace(
                evidence(),
                first_seen=datetime(2026, 1, 2, tzinfo=UTC),
                last_seen=datetime(2026, 1, 1, tzinfo=UTC),
            ),
            "first_seen must not be after last_seen",
        ),
    ],
)
def test_detector_rejects_malformed_evidence_fields(invalid: Evidence, message: str) -> None:
    detector = CustomDetector.from_function(lambda _context: [invalid], name="malformed")

    with pytest.raises(CustomDetectorError, match=message):
        detector.analyze(context())


def test_detector_rejects_recursive_metrics() -> None:
    metrics: dict[str, object] = {}
    metrics["self"] = metrics
    invalid = replace(evidence(), metrics=metrics)
    detector = CustomDetector.from_function(lambda _context: [invalid], name="invalid")

    with pytest.raises(CustomDetectorError, match="metrics must be JSON-compatible"):
        detector.analyze(context())


@pytest.mark.parametrize("confidence", [0, 1])
def test_detector_accepts_confidence_boundaries(confidence: float) -> None:
    detector = CustomDetector.from_function(
        lambda _context: [replace(evidence(), confidence=confidence)],
        name="confidence-boundary",
    )

    assert detector.analyze(context())[0].confidence == confidence


def test_detector_wraps_execution_failure_with_identity() -> None:
    def fail(_context: AnalysisContext) -> list[Evidence]:
        raise RuntimeError("broken plugin")

    detector = CustomDetector.from_function(fail, name="failing")

    with pytest.raises(DetectorExecutionError, match="failing@1.0.0 failed") as captured:
        detector.analyze(context())
    assert isinstance(captured.value.__cause__, RuntimeError)


def test_load_script_analyze_function(tmp_path: Path) -> None:
    script = tmp_path / "function_detector.py"
    script.write_text(
        "from c2hunter_analysis.domain import Evidence\n"
        "DETECTOR_NAME = 'script-function'\n"
        "DETECTOR_VERSION = '4.2.0'\n"
        "def analyze(context):\n"
        "    return [Evidence('203.0.113.20', 'COMMON_DESTINATION', 'ignored', '0', "
        "5, 5, 'script finding')]\n"
    )

    detector = load_custom_detector_from_script(script)

    assert (detector.name, detector.version) == ("script-function", "4.2.0")
    assert detector.analyze(context())[0].detector == "script-function"


def test_load_script_detector_object(tmp_path: Path) -> None:
    script = tmp_path / "object_detector.py"
    script.write_text(
        "class ExampleDetector:\n"
        "    name = 'script-object'\n"
        "    version = '1.3.0'\n"
        "    def analyze(self, context):\n"
        "        return []\n"
        "DETECTOR = ExampleDetector()\n"
    )

    detector = load_custom_detector_from_script(script)

    assert (detector.name, detector.version) == ("script-object", "1.3.0")


def test_load_script_factory(tmp_path: Path) -> None:
    script = tmp_path / "factory_detector.py"
    script.write_text(
        "class ExampleDetector:\n"
        "    name = 'script-factory'\n"
        "    version = '1.1.0'\n"
        "    def analyze(self, context):\n"
        "        return []\n"
        "def create_detector():\n"
        "    return ExampleDetector()\n"
    )

    detector = load_custom_detector_from_script(script)

    assert detector.name == "script-factory"


def test_load_script_reports_import_and_contract_errors(tmp_path: Path) -> None:
    broken = tmp_path / "broken.py"
    broken.write_text("raise RuntimeError('import exploded')\n")
    empty = tmp_path / "empty.py"
    empty.write_text("VALUE = 1\n")

    with pytest.raises(DetectorLoaderError, match="failed to import") as captured:
        load_custom_detector_from_script(broken)
    assert isinstance(captured.value.__cause__, RuntimeError)

    with pytest.raises(
        DetectorLoaderError, match="must export DETECTOR, create_detector, or analyze"
    ):
        load_custom_detector_from_script(empty)


def test_load_script_rejects_non_python_and_symlink(tmp_path: Path) -> None:
    text_file = tmp_path / "detector.txt"
    text_file.write_text("not python")
    target = tmp_path / "target.py"
    target.write_text("def analyze(context):\n    return []\n")
    symlink = tmp_path / "linked.py"
    symlink.symlink_to(target)

    with pytest.raises(DetectorLoaderError, match="must use the .py suffix"):
        load_custom_detector_from_script(text_file)
    with pytest.raises(DetectorLoaderError, match="symbolic links are not allowed"):
        load_custom_detector_from_script(symlink)


def test_load_script_rejects_symlinked_allowed_root(tmp_path: Path) -> None:
    root = tmp_path / "real-root"
    root.mkdir()
    script = root / "detector.py"
    script.write_text("def analyze(context):\n    return []\n")
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(root, target_is_directory=True)

    with pytest.raises(DetectorLoaderError, match="symbolic links are not allowed"):
        load_custom_detector_from_script(linked_root / "detector.py", allowed_root=linked_root)


def test_discover_custom_detectors_is_sorted_and_rejects_duplicate_names(
    tmp_path: Path,
) -> None:
    (tmp_path / "b.py").write_text(
        "DETECTOR_NAME = 'second'\ndef analyze(context):\n    return []\n"
    )
    (tmp_path / "a.py").write_text(
        "DETECTOR_NAME = 'first'\ndef analyze(context):\n    return []\n"
    )
    (tmp_path / "_ignored.py").write_text("raise RuntimeError('must not load')\n")

    detectors = discover_custom_detectors(tmp_path)

    assert [detector.name for detector in detectors] == ["first", "second"]
    assert run_detectors(context(), detectors=detectors) == []

    (tmp_path / "duplicate.py").write_text(
        "DETECTOR_NAME = 'first'\ndef analyze(context):\n    return []\n"
    )
    with pytest.raises(DetectorLoaderError, match="duplicate detector name 'first'"):
        discover_custom_detectors(tmp_path)


def test_build_detector_registry_preserves_order_and_rejects_builtin_collision(
    tmp_path: Path,
) -> None:
    built_in = CustomDetector.from_function(lambda _context: [], name="built-in")
    (tmp_path / "custom.py").write_text(
        "DETECTOR_NAME = 'custom'\ndef analyze(context):\n    return []\n"
    )

    registry = build_detector_registry((built_in,), tmp_path)

    assert [detector.name for detector in registry] == ["built-in", "custom"]

    (tmp_path / "collision.py").write_text(
        "DETECTOR_NAME = 'built-in'\ndef analyze(context):\n    return []\n"
    )
    with pytest.raises(DetectorLoaderError, match="collide with registered detectors"):
        build_detector_registry((built_in,), tmp_path)


def test_detector_registry_cache_normalizes_paths_without_eviction(tmp_path: Path) -> None:
    built_in = CustomDetector.from_function(lambda _context: [], name="built-in")
    registry = DetectorRegistryCache((built_in,))
    first_directory = tmp_path / "detectors-0"
    first_directory.mkdir()
    (first_directory / "custom.py").write_text(
        "DETECTOR_NAME = 'custom-0'\ndef analyze(context):\n    return []\n"
    )

    first = registry.get(first_directory)
    equivalent = registry.get(first_directory / ".")

    assert first is equivalent
    for index in range(1, 6):
        directory = tmp_path / f"detectors-{index}"
        directory.mkdir()
        (directory / "custom.py").write_text(
            f"DETECTOR_NAME = 'custom-{index}'\ndef analyze(context):\n    return []\n"
        )
        registry.get(directory)
    assert registry.get(first_directory) is first
