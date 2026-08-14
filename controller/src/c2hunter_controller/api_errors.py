from typing import Any


class ApiError(Exception):
    """Structured API failure handled by the application error boundary."""

    def __init__(self, status: int, code: str, message: str, details: Any = None) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.details = details
