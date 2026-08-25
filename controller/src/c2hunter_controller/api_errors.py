from collections.abc import Mapping
from typing import Any


class ApiError(Exception):
    """Structured API failure handled by the application error boundary."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        self.headers = dict(headers or {})
