"""Loopback-only experiment adapters; production prompts and loops are unchanged."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from .ai_gateway import OllamaGateway
from .ai_investigation_gateway import (
    InvestigationCompletion,
    InvestigationGatewayError,
    InvestigationModelGateway,
)

ENDPOINT = "http://127.0.0.1:11434"
MODEL = "llama3.1:8b"
RESPONSE_LIMIT = 256 * 1024


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass
class AttemptBudget:
    attempts: int = 0
    deadline: float = field(default_factory=lambda: time.monotonic() + 900)

    limit: int = 12
    parent: AttemptBudget | None = None

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise TimeoutError("experiment deadline")
        if self.attempts >= self.limit:
            raise ValueError("experiment attempt budget")
        if self.parent is not None:
            self.parent.check()

    def admit(self) -> None:
        self.check()
        if self.parent is not None:
            self.parent.admit()
        self.attempts += 1


@dataclass
class Trace:
    calls: list[dict[str, Any]] = field(default_factory=list)
    # Private bounded model text for validation, not published raw or as hidden reasoning.
    outputs: list[str | None] = field(default_factory=list)
    inputs: list[list[dict[str, str]]] = field(default_factory=list)

    def begin(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> dict[str, Any]:
        if len(self.calls) >= 12:
            raise ValueError("trace limit")
        repair = any("Invalid output category:" in m["content"] for m in messages)
        try:
            repair = repair or bool(json.loads(messages[1]["content"]).get("repair_invalid_output"))
        except (ValueError, IndexError, AttributeError):
            pass
        entry = dict(
            input_sha256=_hash(messages),
            schema_sha256=_hash(schema),
            repair_requested=repair,
            http_attempts=0,
            completed_responses=0,
            input_tokens=None,
            output_tokens=None,
            cost_usd=None,
            finish_reason=None,
            error=None,
            elapsed_seconds=0.0,
        )
        self.calls.append(entry)
        self.inputs.append(messages)
        self.outputs.append(None)
        return entry

    def content(self, value: str) -> None:
        encoded = value.encode("utf-8", errors="replace")
        self.calls[-1]["output_bytes"] = len(encoded)
        self.calls[-1]["output_sha256"] = hashlib.sha256(encoded).hexdigest()
        if len(encoded) <= 65536:
            self.outputs[-1] = value


def _count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**31 - 1 else None


class LocalHTTP:
    """A single bounded HTTP request, no redirects, proxies, DNS, or retries.

    This explicit experiment transport replaces the legacy default transport,
    not its selection, prompt, parsing, or one-repair policy.
    """

    timeout_seconds = 60

    def __init__(self, budget: AttemptBudget, trace: Trace) -> None:
        self.budget = budget
        self.trace = trace

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.request_cancellable(
            method, url, headers=headers, body=body, should_cancel=lambda: False
        )

    def request_cancellable(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
        should_cancel: Callable[[], bool],
    ) -> dict[str, Any]:
        allowed = {
            (ENDPOINT + "/api/tags", "GET"),
            (ENDPOINT + "/api/ps", "GET"),
            (ENDPOINT + "/api/chat", "POST"),
        }
        if (url, method) not in allowed:
            raise ValueError("endpoint not allowed")
        if headers and any(k.lower() not in {"content-type"} for k in headers):
            raise ValueError("headers not allowed")
        if should_cancel():
            raise InterruptedError("cancelled")
        inference = method == "POST"
        entry = (
            self.trace.begin(body["messages"], {"format": body["format"]})
            if inference and body
            else None
        )
        start = time.monotonic()

        def check_live() -> None:
            if should_cancel():
                raise InterruptedError("cancelled")
            if time.monotonic() >= min(self.budget.deadline, start + self.timeout_seconds):
                raise TimeoutError("experiment deadline")

        async def perform() -> dict[str, Any]:
            transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0)
            async with httpx.AsyncClient(
                transport=transport,
                trust_env=False,
                follow_redirects=False,
                timeout=min(
                    self.timeout_seconds, max(0.001, self.budget.deadline - time.monotonic())
                ),
            ) as client:
                request = client.build_request(
                    method, url, json=body, headers={"Accept-Encoding": "identity"}
                )
                if len(request.content) > RESPONSE_LIMIT:
                    raise ValueError("REQUEST_LIMIT")
                check_live()
                if inference:
                    self.budget.admit()
                    if entry is not None:
                        entry["http_attempts"] = 1
                response = await client.send(request, stream=True)
                try:
                    if not 200 <= response.status_code < 300:
                        raise ValueError("HTTP_STATUS")
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise ValueError("CONTENT_ENCODING")
                    raw = bytearray()
                    async for chunk in response.aiter_raw():
                        check_live()
                        if len(chunk) > RESPONSE_LIMIT - len(raw):
                            raise ValueError("RESPONSE_LIMIT")
                        raw.extend(chunk)
                    check_live()
                    if entry is not None:
                        entry["completed_responses"] = 1
                    try:
                        parsed = json.loads(raw)
                    except (ValueError, UnicodeError, RecursionError):
                        raise ValueError("INVALID_PROVIDER_JSON") from None
                    if type(parsed) is not dict:
                        raise ValueError("INVALID_PROVIDER_JSON")
                    check_live()
                    return parsed
                finally:
                    await response.aclose()

        async def bounded() -> dict[str, Any]:
            remaining = min(self.timeout_seconds, self.budget.deadline - time.monotonic())
            if remaining <= 0:
                raise TimeoutError("experiment deadline")
            return await asyncio.wait_for(perform(), remaining)

        try:
            result = asyncio.run(bounded())
            check_live()
            if entry is not None:
                entry["input_tokens"] = _count(result.get("prompt_eval_count"))
                entry["output_tokens"] = _count(result.get("eval_count"))
                reason = result.get("done_reason")
                entry["finish_reason"] = reason if reason in {"stop", "length"} else None
                message = result.get("message")
                if isinstance(message, dict) and isinstance(message.get("content"), str):
                    self.trace.content(message["content"])
            return result
        except InterruptedError:
            if entry is not None:
                entry["error"] = "CANCELLED"
            raise
        except (httpx.TimeoutException, TimeoutError):
            if entry is not None:
                entry["error"] = "TIMEOUT"
            raise TimeoutError("model request timed out") from None
        except httpx.HTTPError:
            if entry is not None:
                entry["error"] = "TRANSPORT"
            raise OSError("model transport failed") from None
        except ValueError as exc:
            if entry is not None:
                entry["error"] = (
                    str(exc)
                    if str(exc)
                    in {
                        "HTTP_STATUS",
                        "CONTENT_ENCODING",
                        "RESPONSE_LIMIT",
                        "INVALID_PROVIDER_JSON",
                    }
                    else "ADMISSION"
                )
            raise
        finally:
            if entry is not None:
                entry["elapsed_seconds"] = time.monotonic() - start


@dataclass(frozen=True)
class ObservedInvestigationGateway(InvestigationModelGateway):
    budget: AttemptBudget = field(default_factory=AttemptBudget, compare=False, repr=False)
    trace: Trace = field(default_factory=Trace, compare=False, repr=False)

    def complete(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        *,
        should_cancel: Callable[[], bool],
        deadline_monotonic: float,
        before_attempt: Callable[[], None],
        allow_remote: bool = False,
    ) -> InvestigationCompletion:
        entry = self.trace.begin(messages, schema)
        start = time.monotonic()

        def admit() -> None:
            self.budget.admit()
            before_attempt()

        try:
            result = super().complete(
                messages,
                schema,
                should_cancel=should_cancel,
                deadline_monotonic=min(deadline_monotonic, self.budget.deadline),
                before_attempt=admit,
                allow_remote=allow_remote,
            )
            entry["http_attempts"] = result.accounting.transport_attempts
            entry["completed_responses"] = result.accounting.completed_responses
            entry["input_tokens"] = result.usage.input_tokens
            entry["output_tokens"] = result.usage.output_tokens
            entry["finish_reason"] = result.finish_reason
            self.trace.content(result.content)
            return result
        except InvestigationGatewayError as exc:
            entry["error"] = exc.code
            entry["http_attempts"] = exc.accounting.transport_attempts
            entry["completed_responses"] = exc.accounting.completed_responses
            raise
        finally:
            entry["elapsed_seconds"] = time.monotonic() - start


class LocalExperiment:
    def __init__(
        self,
        *,
        real_local_model: bool = False,
        endpoint: str = ENDPOINT,
        model: str = MODEL,
        matrix_budget: AttemptBudget | None = None,
    ) -> None:
        if real_local_model is not True:
            raise ValueError("real local model requires explicit opt-in")
        if endpoint != ENDPOINT:
            raise ValueError("endpoint must be the approved literal loopback endpoint")
        self.budget = AttemptBudget(parent=matrix_budget)
        if matrix_budget is not None:
            self.budget.deadline = min(self.budget.deadline, matrix_budget.deadline)
        self.legacy_trace = Trace()
        self.investigation_trace = Trace()
        self.http = LocalHTTP(self.budget, self.legacy_trace)
        self.legacy = OllamaGateway(
            base_url=endpoint,
            model=model,
            retries=0,
            temperature=0,
            context_tokens=16384,
            max_output_tokens=2048,
            timeout_seconds=60,
            http_client=self.http,
        )
        self.investigation = ObservedInvestigationGateway(
            provider="ollama",
            base_url=endpoint,
            model=model,
            api_key="",
            temperature=0,
            context_tokens=16384,
            max_output_tokens=2048,
            timeout_seconds=60,
            server_allow_remote=False,
            budget=self.budget,
            trace=self.investigation_trace,
        )

    def metadata(self) -> dict[str, Any]:
        tags = self.http.request("GET", ENDPOINT + "/api/tags")
        models = tags.get("models")
        if not isinstance(models, list) or len(models) > 100:
            raise ValueError("INVALID_TAGS")
        matching = [
            item
            for item in models
            if isinstance(item, dict) and item.get("name") == self.legacy.model
        ]
        if len(matching) != 1:
            raise ValueError("MODEL_NOT_INSTALLED")
        item = matching[0]
        identity = {key: item.get(key) for key in ("name", "digest", "size", "modified_at")}
        if (
            not isinstance(identity["digest"], str)
            or len(identity["digest"]) != 64
            or any(c not in "0123456789abcdef" for c in identity["digest"])
        ):
            raise ValueError("INVALID_TAG_DIGEST")
        size, modified = identity["size"], identity["modified_at"]
        if (
            type(identity["name"]) is not str
            or len(identity["name"].encode()) > 512
            or (size is not None and (type(size) is not int or not 0 <= size < 2**63))
            or (
                modified is not None and (type(modified) is not str or len(modified.encode()) > 512)
            )
        ):
            raise ValueError("INVALID_TAG_METADATA")
        loaded = self.http.request("GET", ENDPOINT + "/api/ps").get("models")
        if not isinstance(loaded, list) or len(loaded) > 100:
            raise ValueError("INVALID_LOADED_MODELS")
        loaded_names = []
        for item in loaded:
            if (
                not isinstance(item, dict)
                or type(item.get("name")) is not str
                or len(item["name"].encode()) > 512
            ):
                raise ValueError("INVALID_LOADED_MODELS")
            loaded_names.append(item["name"])
        return dict(
            observed_at=datetime_utc(),
            tag=identity,
            loaded_names=loaded_names,
            claim="Observed tag metadata, not cryptographic proof of executing weights",
        )


def datetime_utc() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
