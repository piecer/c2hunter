"""Operator-controlled custom detector plugin framework."""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import math
import os
import sys
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from threading import Lock
from types import ModuleType
from typing import Final, cast

from .domain import AnalysisContext, Detector, Evidence
from .scoring import CAPS

Analyzer = Callable[[AnalysisContext], list[Evidence]]
_DEFAULT_VERSION: Final = "1.0.0"
MAX_CUSTOM_EVIDENCE: Final = 10_000
MAX_CUSTOM_SCORE: Final = 100
MAX_SAFE_INTEGER: Final = 2**53 - 1


class CustomDetectorError(Exception):
    """Base error raised by the custom detector framework."""


class DetectorLoaderError(CustomDetectorError):
    """Raised when a custom detector cannot be loaded safely."""


class DetectorExecutionError(CustomDetectorError):
    """Raised when a custom detector fails while analyzing a dataset."""


def _require_metadata(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DetectorLoaderError(f"custom detector {field} must be a non-empty string")
    return value.strip()


def _validate_analyzer(analyze_func: Analyzer) -> None:
    if not callable(analyze_func):
        raise DetectorLoaderError("custom detector analyze must be callable")
    if inspect.iscoroutinefunction(analyze_func):
        raise DetectorLoaderError("custom detector analyze must be synchronous")
    try:
        parameters = tuple(inspect.signature(analyze_func).parameters.values())
    except ValueError as exc:
        raise DetectorLoaderError("custom detector analyze signature is unavailable") from exc
    positional_kinds = (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )
    if len(parameters) != 1 or parameters[0].kind not in positional_kinds:
        raise DetectorLoaderError("custom detector analyze must accept exactly one context")


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _is_json_compatible(value: object, seen: set[int] | None = None) -> bool:
    if value is None or isinstance(value, str | bool):
        return True
    if isinstance(value, int):
        return abs(value) <= MAX_SAFE_INTEGER
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list | tuple):
        active = seen if seen is not None else set()
        identity = id(value)
        if identity in active:
            return False
        active.add(identity)
        compatible = all(_is_json_compatible(item, active) for item in value)
        active.remove(identity)
        return compatible
    if isinstance(value, dict):
        active = seen if seen is not None else set()
        identity = id(value)
        if identity in active:
            return False
        active.add(identity)
        compatible = all(
            isinstance(key, str) and _is_json_compatible(item, active)
            for key, item in value.items()
        )
        active.remove(identity)
        return compatible
    return False


def _validate_reserved_metrics(metrics: dict[str, object], detector_name: str) -> None:
    if "sample_count" in metrics:
        sample_count = metrics["sample_count"]
        if (
            isinstance(sample_count, bool)
            or not isinstance(sample_count, int)
            or not 0 <= sample_count <= MAX_SAFE_INTEGER
        ):
            raise CustomDetectorError(
                f"custom detector {detector_name} metric sample_count must be an integer"
            )
    for field_name in ("public_dns_ntp", "cdn_cloud"):
        if field_name in metrics and not isinstance(metrics[field_name], bool):
            raise CustomDetectorError(
                f"custom detector {detector_name} metric {field_name} must be a boolean"
            )
    if "match_mode" in metrics and not isinstance(metrics["match_mode"], str):
        raise CustomDetectorError(
            f"custom detector {detector_name} metric match_mode must be a string"
        )


def _validate_evidence(item: Evidence, detector_name: str, index: int) -> None:
    if not isinstance(item.candidate_ip, str):
        raise CustomDetectorError(f"custom detector {detector_name} candidate_ip must be a string")
    try:
        ip_address(item.candidate_ip)
    except ValueError as exc:
        raise CustomDetectorError(
            f"custom detector {detector_name} returned invalid candidate IP "
            f"at index {index}: {item.candidate_ip!r}"
        ) from exc
    if not isinstance(item.type, str) or not item.type.strip():
        raise CustomDetectorError(
            f"custom detector {detector_name} type must be a non-empty string"
        )
    if item.type not in CAPS:
        raise CustomDetectorError(
            f"custom detector {detector_name} returned unsupported evidence type {item.type}"
        )
    if not isinstance(item.description, str):
        raise CustomDetectorError(f"custom detector {detector_name} description must be a string")
    for field_name, values in (
        ("hosts", item.hosts),
        ("sensors", item.sensors),
        ("warnings", item.warnings),
    ):
        if not isinstance(values, tuple) or not all(isinstance(value, str) for value in values):
            raise CustomDetectorError(
                f"custom detector {detector_name} {field_name} must be a tuple of strings"
            )
    for field_name, timestamp_value in (
        ("first_seen", item.first_seen),
        ("last_seen", item.last_seen),
    ):
        if timestamp_value is None:
            continue
        if not isinstance(timestamp_value, datetime):
            raise CustomDetectorError(
                f"custom detector {detector_name} {field_name} must be a datetime or None"
            )
        try:
            offset = timestamp_value.utcoffset()
        except (TypeError, ValueError) as exc:
            raise CustomDetectorError(
                f"custom detector {detector_name} {field_name} must be timezone-aware"
            ) from exc
        if offset is None:
            raise CustomDetectorError(
                f"custom detector {detector_name} {field_name} must be timezone-aware"
            )
    if (
        item.first_seen is not None
        and item.last_seen is not None
        and item.first_seen > item.last_seen
    ):
        raise CustomDetectorError(
            f"custom detector {detector_name} first_seen must not be after last_seen"
        )
    if not isinstance(item.metrics, dict) or not _is_json_compatible(item.metrics):
        raise CustomDetectorError(
            f"custom detector {detector_name} metrics must be JSON-compatible"
        )
    _validate_reserved_metrics(item.metrics, detector_name)
    for field_name, numeric_value in (
        ("raw_score", item.raw_score),
        ("contribution", item.contribution),
        ("confidence", item.confidence),
    ):
        if not _is_finite_number(numeric_value):
            raise CustomDetectorError(
                f"custom detector {detector_name} {field_name} must be a finite number"
            )
    for field_name, score_value in (
        ("raw_score", item.raw_score),
        ("contribution", item.contribution),
    ):
        if not 0 <= score_value <= MAX_CUSTOM_SCORE:
            raise CustomDetectorError(
                f"custom detector {detector_name} {field_name} must be between "
                f"0 and {MAX_CUSTOM_SCORE}"
            )
    if not 0 <= item.confidence <= 1:
        raise CustomDetectorError(
            f"custom detector {detector_name} confidence must be between 0 and 1"
        )


class CustomDetector:
    """Validated adapter implementing the C2Hunter ``Detector`` protocol."""

    def __init__(
        self, analyze_func: Analyzer, *, name: str, version: str = _DEFAULT_VERSION
    ) -> None:
        _validate_analyzer(analyze_func)
        self.name = _require_metadata(name, "name")
        self.version = _require_metadata(version, "version")
        self._analyze_func = analyze_func

    @classmethod
    def from_function(
        cls,
        analyze_func: Analyzer,
        name: str | None = None,
        version: str = _DEFAULT_VERSION,
    ) -> CustomDetector:
        """Create a detector from an ``analyze(context)`` function."""
        inferred_name = getattr(analyze_func, "__name__", "")
        resolved_name = str(inferred_name) if name is None else name
        return cls(analyze_func, name=resolved_name, version=version)

    @classmethod
    def from_object(
        cls,
        detector: object,
        *,
        name: str | None = None,
        version: str | None = None,
    ) -> CustomDetector:
        """Adapt an object exposing ``name``, ``version`` and ``analyze``."""
        analyze = getattr(detector, "analyze", None)
        if not callable(analyze):
            raise DetectorLoaderError(
                "custom detector object must expose a callable analyze method"
            )
        resolved_name = name if name is not None else getattr(detector, "name", None)
        resolved_version = version if version is not None else getattr(detector, "version", None)
        return cls(
            cast(Analyzer, analyze),
            name=_require_metadata(resolved_name, "name"),
            version=_require_metadata(resolved_version, "version"),
        )

    @classmethod
    def from_class(cls, detector_class: object) -> CustomDetector:
        """Instantiate a zero-argument detector class or adapt an existing instance."""
        instance = detector_class
        if inspect.isclass(detector_class):
            try:
                instance = detector_class()
            except Exception as exc:
                raise DetectorLoaderError(
                    f"custom detector class {detector_class.__name__} could not be "
                    f"instantiated: {exc}"
                ) from exc
        return cls.from_object(instance)

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        """Execute the plugin and validate all returned evidence."""
        try:
            produced = self._analyze_func(context)
        except Exception as exc:
            raise DetectorExecutionError(
                f"custom detector {self.name}@{self.version} failed: {exc}"
            ) from exc

        if not isinstance(produced, list):
            raise CustomDetectorError(
                f"custom detector {self.name} must return list[Evidence], "
                f"got {type(produced).__name__}"
            )
        if len(produced) > MAX_CUSTOM_EVIDENCE:
            raise CustomDetectorError(
                f"custom detector {self.name} returned {len(produced)} evidence items; "
                f"maximum is {MAX_CUSTOM_EVIDENCE}"
            )

        validated: list[Evidence] = []
        for index, item in enumerate(produced):
            if not isinstance(item, Evidence):
                raise CustomDetectorError(
                    f"custom detector {self.name} item {index} is {type(item).__name__}, "
                    "expected Evidence"
                )
            _validate_evidence(item, self.name, index)
            validated.append(replace(item, detector=self.name, version=self.version))
        return validated


def _absolute_path_without_symlinks(path: str | Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise DetectorLoaderError(
                f"custom detector {label} symbolic links are not allowed: {current}"
            )
    return absolute


def resolve_custom_detector_directory(directory: str | Path) -> Path:
    """Resolve an existing detector directory without following any symlink component."""
    root_path = _absolute_path_without_symlinks(directory, "directory")
    try:
        root = root_path.resolve(strict=True)
    except OSError as exc:
        raise DetectorLoaderError(f"custom detector directory does not exist: {directory}") from exc
    if not root.is_dir():
        raise DetectorLoaderError(f"custom detector path is not a directory: {root}")
    return root


def normalize_custom_detector_directory(value: str | None) -> str | None:
    """Treat an unset, empty, or whitespace-only directory setting as disabled."""
    if value is None:
        return None
    return value.strip() or None


def _resolve_script_path(script_path: str | Path, allowed_root: str | Path | None) -> Path:
    candidate = _absolute_path_without_symlinks(script_path, "script")
    if candidate.suffix != ".py":
        raise DetectorLoaderError(f"custom detector script must use the .py suffix: {candidate}")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise DetectorLoaderError(f"custom detector script does not exist: {candidate}") from exc
    if not resolved.is_file():
        raise DetectorLoaderError(f"custom detector script is not a regular file: {resolved}")

    if allowed_root is not None:
        root = resolve_custom_detector_directory(allowed_root)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise DetectorLoaderError(
                f"custom detector script escapes configured root: {resolved}"
            ) from exc
    return resolved


def _load_module(script_path: Path) -> ModuleType:
    digest = hashlib.sha256(str(script_path).encode()).hexdigest()[:16]
    module_name = f"c2hunter_custom_detector_{digest}"
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise DetectorLoaderError(f"unable to create module spec for {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(module_name, None)
        raise DetectorLoaderError(f"failed to import custom detector {script_path}: {exc}") from exc
    return module


def _detector_from_module(
    module: ModuleType, script_path: Path, detector_name: str | None
) -> CustomDetector:
    if hasattr(module, "DETECTOR"):
        return CustomDetector.from_object(module.DETECTOR, name=detector_name)

    factory = getattr(module, "create_detector", None)
    if factory is not None:
        if not callable(factory):
            raise DetectorLoaderError("custom detector create_detector must be callable")
        try:
            detector = factory()
        except Exception as exc:
            raise DetectorLoaderError(f"custom detector factory failed: {exc}") from exc
        return CustomDetector.from_object(detector, name=detector_name)

    analyze = getattr(module, "analyze", None)
    if callable(analyze):
        name = detector_name or getattr(module, "DETECTOR_NAME", script_path.stem)
        version = getattr(module, "DETECTOR_VERSION", _DEFAULT_VERSION)
        return CustomDetector.from_function(cast(Analyzer, analyze), name=name, version=version)

    raise DetectorLoaderError(
        "custom detector script must export DETECTOR, create_detector, or analyze"
    )


def load_custom_detector_from_script(
    script_path: str | Path,
    detector_name: str | None = None,
    *,
    allowed_root: str | Path | None = None,
) -> CustomDetector:
    """Load one trusted local Python plugin using the documented export contract."""
    resolved = _resolve_script_path(script_path, allowed_root)
    return _detector_from_module(_load_module(resolved), resolved, detector_name)


def discover_custom_detectors(directory: str | Path) -> tuple[CustomDetector, ...]:
    """Load visible ``.py`` plugins from an operator-controlled directory."""
    root = resolve_custom_detector_directory(directory)

    detectors: list[CustomDetector] = []
    names: set[str] = set()
    for script in sorted(root.iterdir(), key=lambda path: path.name):
        if script.name.startswith((".", "_")) or script.suffix != ".py":
            continue
        detector = load_custom_detector_from_script(script, allowed_root=root)
        if detector.name in names:
            raise DetectorLoaderError(f"duplicate detector name {detector.name!r}")
        names.add(detector.name)
        detectors.append(detector)
    return tuple(detectors)


def build_detector_registry(
    registered_detectors: Iterable[Detector], directory: str | Path | None = None
) -> tuple[Detector, ...]:
    """Append discovered plugins to an immutable registry with unique names."""
    registered = tuple(registered_detectors)
    registered_names = [detector.name for detector in registered]
    if len(registered_names) != len(set(registered_names)):
        raise DetectorLoaderError("registered detector names must be unique")
    if directory is None:
        return registered

    custom = discover_custom_detectors(directory)
    collisions = sorted({detector.name for detector in custom} & set(registered_names))
    if collisions:
        raise DetectorLoaderError(
            f"custom detector names collide with registered detectors: {collisions}"
        )
    return (*registered, *custom)


class DetectorRegistryCache:
    """Process-lifetime detector registry cache keyed by normalized directory path."""

    def __init__(self, registered_detectors: Iterable[Detector]) -> None:
        self._registered = build_detector_registry(registered_detectors)
        self._entries: dict[str | None, tuple[Detector, ...] | DetectorLoaderError] = {
            None: self._registered
        }
        self._lock = Lock()

    def get(self, directory: str | Path | None) -> tuple[Detector, ...]:
        key = None if directory is None else str(resolve_custom_detector_directory(directory))
        with self._lock:
            cached = self._entries.get(key)
            if isinstance(cached, DetectorLoaderError):
                raise DetectorLoaderError(str(cached)) from cached
            if cached is not None:
                return cached
            try:
                loaded = build_detector_registry(self._registered, key)
            except DetectorLoaderError as exc:
                self._entries[key] = exc
                raise
            self._entries[key] = loaded
            return loaded


__all__ = [
    "MAX_CUSTOM_EVIDENCE",
    "MAX_CUSTOM_SCORE",
    "CustomDetector",
    "CustomDetectorError",
    "DetectorExecutionError",
    "DetectorLoaderError",
    "DetectorRegistryCache",
    "build_detector_registry",
    "discover_custom_detectors",
    "load_custom_detector_from_script",
    "normalize_custom_detector_directory",
    "resolve_custom_detector_directory",
]
