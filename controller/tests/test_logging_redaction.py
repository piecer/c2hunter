import logging

from c2hunter_controller.logging import (
    SensitivePathFilter,
    install_access_log_redaction,
    redact_sensitive_path,
)


def test_redact_sensitive_path_masks_only_enrollment_claim_token() -> None:
    token = "one-time-super-secret"

    redacted = redact_sensitive_path(f"/api/v1/sensor-enrollments/{token}/claim?source=installer")

    assert token not in redacted
    assert redacted == "/api/v1/sensor-enrollments/{token}/claim?source=installer"
    assert redact_sensitive_path("/api/v1/sensor-enrollments") == ("/api/v1/sensor-enrollments")


def test_sensitive_path_filter_redacts_uvicorn_access_log_arguments() -> None:
    token = "one-time-super-secret"
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        (
            "127.0.0.1:1234",
            "POST",
            f"/api/v1/sensor-enrollments/{token}/claim",
            "1.1",
            201,
        ),
        None,
    )

    assert SensitivePathFilter().filter(record)
    assert token not in record.getMessage()
    assert "/api/v1/sensor-enrollments/{token}/claim" in record.getMessage()


def test_install_access_log_redaction_is_idempotent() -> None:
    logger = logging.getLogger("uvicorn.access")
    original_filters = list(logger.filters)
    logger.filters.clear()
    try:
        install_access_log_redaction()
        install_access_log_redaction()

        assert sum(isinstance(item, SensitivePathFilter) for item in logger.filters) == 1
    finally:
        logger.filters[:] = original_filters


def test_sensitive_path_filter_redacts_mapping_arguments() -> None:
    token = "mapping-super-secret"
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        "path=%(path)s status=%(status)d",
        {
            "path": f"/api/v1/sensor-enrollments/{token}/claim",
            "status": 201,
        },
        None,
    )

    assert SensitivePathFilter().filter(record)
    assert token not in record.getMessage()
