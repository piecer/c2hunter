from pathlib import Path


def test_operations_require_abort_incomplete_multipart_lifecycle() -> None:
    operations = (Path(__file__).parents[2] / "docs" / "operations.md").read_text()

    assert "AbortIncompleteMultipartUpload" in operations
    assert "DaysAfterInitiation" in operations
    assert "get-bucket-lifecycle-configuration" in operations
    assert "put-bucket-lifecycle-configuration" in operations
    assert "mandatory" in operations.lower()
