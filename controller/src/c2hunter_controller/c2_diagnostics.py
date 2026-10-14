"""Failure-only C2 telemetry. Never persisted in the closed run/HTTP contract."""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from .network_ai import ProviderFinishReason

logger = logging.getLogger(__name__)
Stage = Literal[
    "GATEWAY",
    "RESPONSE_ENVELOPE",
    "JSON_PARSE",
    "SCHEMA",
    "EVIDENCE_VALIDATION",
    "ARTIFACT_PREPARATION",
    "TRANSPORT",
    "CANCELLED",
]


class C2FailureDiagnostic(BaseModel):
    """Counts cover this candidate invocation only, not previous deliveries.

    None means unobserved (e.g. a custom gateway); zero means observed no calls.
    Output length and finish reason describe only the last transport response.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    stage: Stage
    attempt_count: int | None = Field(default=None, ge=0, le=2)
    repair_count: int | None = Field(default=None, ge=0, le=1)
    transport_attempt_count: int | None = Field(default=None, ge=0, le=8)
    output_bytes: int | None = Field(default=None, ge=0, le=2**63 - 1)
    provider_finish_reason: ProviderFinishReason | None = None


@dataclass
class C2Diagnostics:
    """Invocation-local observations; no shared gateway state or raw values."""

    stage: Stage = "GATEWAY"
    attempt_count: int | None = None
    repair_count: int | None = None
    transport_attempt_count: int | None = None
    output_bytes: int | None = None
    provider_finish_reason: ProviderFinishReason | None = None

    @contextmanager
    def capture(self, run_id: str) -> Iterator[None]:
        """Wrap compute only, never caller persistence or storage-error mapping."""
        from ._baseline_storage import BaselineStorageError
        from .ai_gateway import AIAnalysisCancelled
        from .historical_ai_storage import HistoricalStorageError

        try:
            yield
        except (BaselineStorageError, HistoricalStorageError):
            raise
        except Exception as exc:
            if isinstance(exc, AIAnalysisCancelled):
                self.stage = "CANCELLED"
            elif isinstance(exc, TimeoutError) and self.stage == "GATEWAY":
                self.stage = "TRANSPORT"
            self.report(run_id)
            raise

    def observe_response(self, response: dict[str, Any], provider: str) -> None:
        value = response.get("done_reason") if provider == "ollama" else None
        if provider == "openai-compatible":
            choices = response.get("choices")
            if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                value = choices[0].get("finish_reason")
        self.provider_finish_reason = (
            cast(ProviderFinishReason, value)
            if isinstance(value, str)
            and value in {"stop", "length", "load", "unload", "tool_calls", "content_filter"}
            else None
        )

    def report(self, run_id: str) -> None:
        # Telemetry must not replace model, cancellation or persistence outcomes.
        # Only canonical service-owned UUIDs may be used for correlation.
        try:
            if str(uuid.UUID(run_id)) != run_id:
                return
            diagnostic = C2FailureDiagnostic(
                stage=self.stage,
                attempt_count=self.attempt_count,
                repair_count=self.repair_count,
                transport_attempt_count=self.transport_attempt_count,
                output_bytes=self.output_bytes,
                provider_finish_reason=self.provider_finish_reason,
            ).model_dump(mode="json")
            logger.warning(
                "C2 failure diagnostic %s",
                json.dumps({"ai_run_id": run_id, **diagnostic}, separators=(",", ":")),
                extra={"ai_run_id": run_id, "failure_diagnostic": diagnostic},
            )
        except Exception:  # noqa: S110 -- failed diagnostic sinks must not recurse or alter outcomes
            pass
