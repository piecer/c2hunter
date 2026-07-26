"""Test for Custom Detector Framework"""

from c2hunter_analysis.custom import CustomDetector
from c2hunter_analysis.domain import AnalysisContext, Evidence


def test_create_detector_from_function() -> None:
    """Verify CustomDetector.from_function creates a detector instance."""

    def my_detector(context: AnalysisContext) -> list[Evidence]:
        return []

    detector = CustomDetector.from_function(my_detector, name="test-detector")
    assert detector.name == "test-detector"
    assert detector.version == "1.0.0"


def test_detector_from_function_uses_provided_name() -> None:
    """Verify detector uses provided name when given."""

    def my_detector(context: AnalysisContext) -> list[Evidence]:
        return []

    detector = CustomDetector.from_function(my_detector, name="custom-name")
    assert detector.name == "custom-name"
