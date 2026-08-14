from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

_ENROLLMENT_CLAIM_PATH = re.compile(r"(/api/v1/sensor-enrollments/)[^/?\s]+(/claim)(?=[?\s\"']|$)")


def redact_sensitive_path(value: str) -> str:
    return _ENROLLMENT_CLAIM_PATH.sub(r"\1{token}\2", value)


class SensitivePathFilter(logging.Filter):
    """Redact one-time enrollment tokens before access records are rendered."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_sensitive_path(str(record.msg))
        if isinstance(record.args, tuple):
            record.args = tuple(
                redact_sensitive_path(value) if isinstance(value, str) else value
                for value in record.args
            )
        elif isinstance(record.args, dict):
            record.args = {
                key: redact_sensitive_path(value) if isinstance(value, str) else value
                for key, value in record.args.items()
            }
        return True


def install_access_log_redaction() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, SensitivePathFilter) for item in access_logger.filters):
        access_logger.addFilter(SensitivePathFilter())


def render_json_log(
    level: str,
    component: str,
    message: str,
    *,
    service: str = "c2hunter-controller",
    job_id: str | None = None,
    sensor_id: str | None = None,
    request_id: str | None = None,
    error: Any = None,
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "level": level,
        "service": service,
        "component": component,
        "job_id": job_id,
        "sensor_id": sensor_id,
        "request_id": request_id,
        "message": message,
        "error": error,
    }
