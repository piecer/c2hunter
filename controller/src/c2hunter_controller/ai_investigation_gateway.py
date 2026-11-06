"""One-attempt investigation completion, separate from legacy retry/repair behavior.

Only an already configured Ollama/OpenAI-compatible gateway is adapted. Construction
never probes availability or downloads a model. HTTP(S) literal IPs and pinned localhost
names are supported; other DNS names fail closed because the installed asyncio resolver
cannot be cancelled with a hard deadline. Legacy private/link-local IP classification is
retained. Nonlocal IPs require both server policy and per-completion consent.

The synchronous API belongs in the existing worker/thread, not an ASGI event loop.
Callbacks are trusted synchronous infrastructure: before_attempt must atomically debit
or raise, returning None on success; both callbacks must bound their own execution time.
A callback cannot be force-interrupted, but its late return can never initiate HTTP.

Limits apply before decoding: 64 KiB retained raw response, 16 KiB UTF-8 model text,
32 KiB input messages and schema each, 128 KiB actual encoded provider body. The installed
HTTP/1 transport reads bounded 64 KiB chunks, so a rejected overflow chunk may already
have been received, but is never accumulated or decoded. Nonidentity content encoding
is refused. Token admission is a conservative byte/framing estimate, not a tokenizer
measurement; provider-reported usage remains separate and unknown values stay None.

Returned content is strict JSON with an object root. Action schema/semantics, tool
permissions, output repair and durable run accounting remain the caller's responsibility.
"""

from __future__ import annotations

import asyncio
import json
import math
import ssl
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any, cast
from urllib.parse import urlsplit

import httpx

from .ai_gateway import OllamaGateway, OpenAICompatibleGateway
from .config import Settings


@dataclass(frozen=True)
class AttemptAccounting:
    """Per-call facts, including on errors; never inferred from HTTP success.

    admitted_attempts: hook confirmed a durable debit, even if cancelled before HTTP.
    transport_attempts: entered the single transport invocation (not proof of delivery).
    completed_responses: fully read a bounded 2xx body, even if its JSON later failed.
    """

    admitted_attempts: int = 0
    transport_attempts: int = 0
    completed_responses: int = 0


class InvestigationGatewayError(RuntimeError):
    """Static code and per-call facts only; never retain provider error details."""

    def __init__(self, code: str, accounting: AttemptAccounting | None = None) -> None:
        super().__init__("Investigation model request failed: " + code)
        self.code = code
        self.accounting = accounting if accounting is not None else AttemptAccounting()


@dataclass(frozen=True)
class ProviderUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True)
class InvestigationCompletion:
    content: str
    usage: ProviderUsage
    finish_reason: str | None
    accounting: AttemptAccounting
    estimated_input_tokens: int


MAX_RESPONSE_BYTES = 64 * 1024
MAX_MODEL_TEXT_BYTES = 16 * 1024
MAX_JSON_DEPTH = 32
MAX_MESSAGES_BYTES = 32 * 1024
MAX_SCHEMA_BYTES = 32 * 1024
MAX_REQUEST_BYTES = 128 * 1024
MAX_JSON_NODES = 8192


def _strict_object(text: str, accounting: AttemptAccounting) -> dict[str, Any]:
    # Constant-space lexical admission before the allocating decoder. Count containers,
    # quoted keys/values and unquoted scalar tokens, matching _bounded_json's node units.
    # Strings hide punctuation/escapes; scalar runs include signs and exponent notation.
    # This is not a syntax parser: the strict stdlib decode below still validates grammar.
    depth = nodes = 0
    quoted = escaped = scalar = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            scalar = False
            nodes += 1
        elif char in "[{":
            depth += 1
            scalar = False
            nodes += 1
        elif char in "]}":
            depth -= 1
            scalar = False
        elif char in " \t\r\n,:":
            scalar = False
        elif not scalar:
            scalar = True
            nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise InvestigationGatewayError("INVALID_JSON", accounting)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def number(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError
        return result

    try:
        parsed = json.loads(
            text, object_pairs_hook=pairs, parse_constant=number, parse_float=number
        )
        if not isinstance(parsed, dict):
            raise ValueError
    except (ValueError, RecursionError):
        raise InvestigationGatewayError("INVALID_JSON", accounting) from None
    return parsed


def _bounded_json(value: Any, limit: int) -> bytes:
    """Bound basic types, depth, nodes and string bytes before JSON encoding."""
    nodes = byte_count = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes, byte_count
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise InvestigationGatewayError("INPUT_LIMIT")
        if type(item) is str:
            if len(item) > limit - byte_count:
                raise InvestigationGatewayError("INPUT_LIMIT")
            byte_count += len(item.encode("utf-8"))
            if byte_count > limit:
                raise InvestigationGatewayError("INPUT_LIMIT")
        elif type(item) is dict:
            if len(item) > MAX_JSON_NODES:
                raise InvestigationGatewayError("INPUT_LIMIT")
            for key, child in item.items():
                if type(key) is not str:
                    raise InvestigationGatewayError("INVALID_INPUT")
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif type(item) is list:
            if len(item) > MAX_JSON_NODES:
                raise InvestigationGatewayError("INPUT_LIMIT")
            for child in item:
                visit(child, depth + 1)
        elif item is None or type(item) is bool:
            pass
        elif type(item) is int and item.bit_length() <= 64:
            pass
        elif type(item) is float and math.isfinite(item):
            pass
        else:
            raise InvestigationGatewayError("INVALID_INPUT")

    try:
        visit(value, 0)
        payload = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (UnicodeError, ValueError, RecursionError):
        raise InvestigationGatewayError("INVALID_INPUT") from None
    if len(payload) > limit:
        raise InvestigationGatewayError("INPUT_LIMIT")
    return payload


def _usage_count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**31 - 1 else None


@dataclass(frozen=True)
class InvestigationModelGateway:
    provider: str
    base_url: str = field(repr=False)
    model: str
    api_key: str = field(repr=False)
    temperature: float
    context_tokens: int
    max_output_tokens: int
    timeout_seconds: float = 120
    server_allow_remote: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.server_allow_remote) is not bool
            or type(self.context_tokens) is not int
            or not 8192 <= self.context_tokens <= 262144
            or type(self.max_output_tokens) is not int
            or not 1 <= self.max_output_tokens <= 16384
            or type(self.timeout_seconds) not in {int, float}
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 600
            or type(self.temperature) not in {int, float}
            or not math.isfinite(self.temperature)
            or not 0 <= self.temperature <= 1
            or type(self.model) is not str
            or not 1 <= len(self.model) <= 512
            or any(ord(char) < 32 or ord(char) == 127 for char in self.model)
            or type(self.api_key) is not str
            or len(self.api_key) > 8192
            or any(not 32 <= ord(char) <= 126 for char in self.api_key)
        ):
            raise InvestigationGatewayError("UNAVAILABLE")
        try:
            if len(self.model.encode("utf-8")) > 512:
                raise ValueError
        except (ValueError, UnicodeError):
            raise InvestigationGatewayError("UNAVAILABLE") from None
        self._endpoint()

    def _endpoint(self) -> tuple[str, bool, str | None]:
        try:
            if (
                type(self.base_url) is not str
                or len(self.base_url) > 2048
                or any(ord(char) <= 32 or ord(char) == 127 for char in self.base_url)
                or any(char in self.base_url for char in "?#\\")
            ):
                raise ValueError
            if self.provider not in {"ollama", "openai-compatible"}:
                raise ValueError
            # Reuse the existing URL validator/classifier without BaseSettings env loading.
            config = Settings.model_construct(
                ai_model_provider=self.provider, ai_model_base_url=self.base_url
            )
            cast(Callable[[], Settings], config.validate_network_boundaries)()
            parsed = urlsplit(self.base_url)
            _ = parsed.port  # Force malformed/out-of-range port rejection now, before debit.
            host = parsed.hostname or ""
            if "%" in host:
                raise ValueError
            url = httpx.URL(self.base_url)
            if host in {"localhost", "localhost.localdomain"}:
                return str(url.copy_with(host="127.0.0.1")).rstrip("/"), True, host
            # Named DNS uses an uncancellable system resolver in httpx's asyncio backend.
            # Fail closed rather than abandon a resolver thread or exceed the run deadline.
            # Unlike legacy name-only classification, host.docker.internal needs a literal
            # private address here. Loopback names above are pinned without a DNS lookup.
            address = ip_address(host)
            if address.is_unspecified or address.is_multicast:
                raise ValueError
            return self.base_url.rstrip("/"), not config.ai_model_endpoint_is_remote, None
        except (ValueError, TypeError, httpx.InvalidURL):
            raise InvestigationGatewayError("UNAVAILABLE") from None

    @classmethod
    def from_configured_gateway(
        cls, gateway: object, *, server_allow_remote: bool = False
    ) -> InvestigationModelGateway:
        if not isinstance(gateway, OllamaGateway | OpenAICompatibleGateway):
            raise InvestigationGatewayError("UNAVAILABLE")
        return cls(
            gateway.provider,
            gateway.base_url,
            gateway.model,
            gateway.api_key,
            gateway.temperature,
            gateway.context_tokens,
            gateway.max_output_tokens,
            getattr(gateway.http, "timeout_seconds", 120),
            server_allow_remote,
        )

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
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise InvestigationGatewayError("ASYNC_CONTEXT")
        if type(deadline_monotonic) not in {int, float} or not math.isfinite(deadline_monotonic):
            raise InvestigationGatewayError("INVALID_INPUT")
        deadline_monotonic = min(deadline_monotonic, time.monotonic() + self.timeout_seconds)
        accounting = AttemptAccounting()

        def check() -> None:
            try:
                cancelled = should_cancel()
            except Exception:
                raise InvestigationGatewayError("CANCEL_CHECK_FAILED", accounting) from None
            if cancelled:
                raise InvestigationGatewayError("CANCELLED", accounting)
            if time.monotonic() >= deadline_monotonic:
                raise InvestigationGatewayError("DEADLINE", accounting)

        check()
        if type(allow_remote) is not bool:
            raise InvestigationGatewayError("INVALID_INPUT")
        endpoint, local, original_host = self._endpoint()
        if not local and not (self.server_allow_remote and allow_remote):
            raise InvestigationGatewayError("REMOTE_NOT_ALLOWED")
        if type(messages) is not list or not 1 <= len(messages) <= 32 or type(schema) is not dict:
            raise InvestigationGatewayError("INVALID_INPUT")
        for message in messages:
            if (
                type(message) is not dict
                or len(message) != 2
                or set(message) != {"role", "content"}
                or type(message["role"]) is not str
                or message["role"] not in {"system", "user", "assistant"}
                or type(message["content"]) is not str
            ):
                raise InvestigationGatewayError("INVALID_INPUT")
        _bounded_json(messages, MAX_MESSAGES_BYTES)
        schema_json = _bounded_json(schema, MAX_SCHEMA_BYTES).decode("utf-8")
        body: dict[str, Any] = {"model": self.model, "messages": messages}
        headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
        if original_host is not None:
            headers["Host"] = urlsplit(self.base_url).netloc
        if self.provider == "ollama":
            path = "/api/chat"
            body.update(
                stream=False,
                format="json",
                options={
                    "temperature": self.temperature,
                    "num_ctx": self.context_tokens,
                    "num_predict": self.max_output_tokens,
                },
            )
            body["messages"] = [
                *messages,
                {
                    "role": "user",
                    "content": "Return JSON that matches this required schema exactly:\n"
                    + schema_json,
                },
            ]
        else:
            path = "/chat/completions"
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            body.update(
                temperature=self.temperature,
                max_tokens=self.max_output_tokens,
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "c2hunter_investigation",
                        "strict": True,
                        "schema": schema,
                    },
                },
            )
        payload = _bounded_json(body, MAX_REQUEST_BYTES)
        # UTF-8 bytes plus framing reserve: intentionally conservative, NOT a tokenizer count.
        estimated_input_tokens = len(payload) + 256 + 32 * len(body["messages"])
        if estimated_input_tokens + self.max_output_tokens > self.context_tokens:
            raise InvestigationGatewayError("CONTEXT_LIMIT")
        check()
        try:
            admitted = cast(Callable[[], object], before_attempt)()
            if admitted is not None:
                raise ValueError
        except Exception:
            raise InvestigationGatewayError("ATTEMPT_REJECTED", accounting) from None
        accounting = AttemptAccounting(1, 0, 0)
        check()

        async def request() -> dict[str, Any]:
            nonlocal accounting
            context = ssl.create_default_context()
            transport = httpx.AsyncHTTPTransport(
                verify=context,
                trust_env=False,
                retries=0,
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
            )
            async with httpx.AsyncClient(
                verify=context,
                transport=transport,
                trust_env=False,
                follow_redirects=False,
                timeout=max(0.001, deadline_monotonic - time.monotonic()),
            ) as client:
                check()
                accounting = AttemptAccounting(1, 1, 0)
                async with client.stream(
                    "POST",
                    endpoint + path,
                    content=payload,
                    headers=headers,
                    extensions={"sni_hostname": original_host} if original_host else {},
                ) as response:
                    if not 200 <= response.status_code < 300:
                        raise InvestigationGatewayError("HTTP_STATUS", accounting)
                    if (
                        response.headers.get("Content-Encoding", "identity").strip().lower()
                        != "identity"
                    ):
                        raise InvestigationGatewayError("CONTENT_ENCODING", accounting)
                    data = bytearray()
                    async for chunk in response.aiter_raw():
                        check()
                        if len(chunk) > MAX_RESPONSE_BYTES - len(data):
                            raise InvestigationGatewayError("RESPONSE_LIMIT", accounting)
                        data.extend(chunk)
                    accounting = AttemptAccounting(1, 1, 1)
                    check()
                    try:
                        text = data.decode("utf-8")
                    except UnicodeError:
                        raise InvestigationGatewayError("INVALID_JSON", accounting) from None
                    return _strict_object(text, accounting)

        async def perform() -> dict[str, Any]:
            task = asyncio.create_task(request())
            try:
                while not task.done():
                    check()
                    await asyncio.wait(
                        {task}, timeout=min(0.02, max(0, deadline_monotonic - time.monotonic()))
                    )
                check()
                return await task
            finally:
                if not task.done():
                    task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await task

        try:
            response = asyncio.run(perform())
        except InvestigationGatewayError:
            raise
        except (httpx.HTTPError, OSError, ValueError):
            raise InvestigationGatewayError("TRANSPORT", accounting) from None
        check()
        try:
            if self.provider == "ollama":
                content = response["message"]["content"]
                reason = response.get("done_reason")
                usage = ProviderUsage(
                    _usage_count(response.get("prompt_eval_count")),
                    _usage_count(response.get("eval_count")),
                )
            else:
                choices = response["choices"]
                if not isinstance(choices, list) or len(choices) != 1:
                    raise ValueError
                choice = choices[0]
                content = choice["message"]["content"]
                reason = choice.get("finish_reason")
                raw_usage = response.get("usage")
                if not isinstance(raw_usage, dict):
                    raw_usage = {}
                usage = ProviderUsage(
                    _usage_count(raw_usage.get("prompt_tokens")),
                    _usage_count(raw_usage.get("completion_tokens")),
                )
            if not isinstance(content, str):
                raise ValueError
        except (TypeError, KeyError, IndexError, ValueError, AttributeError):
            raise InvestigationGatewayError("PROVIDER_RESPONSE", accounting) from None
        try:
            content_bytes = content.encode("utf-8")
        except UnicodeError:
            raise InvestigationGatewayError("INVALID_JSON", accounting) from None
        if len(content_bytes) > MAX_MODEL_TEXT_BYTES:
            raise InvestigationGatewayError("MODEL_TEXT_LIMIT", accounting)
        _strict_object(content, accounting)
        if not isinstance(reason, str) or reason not in {
            "stop",
            "length",
            "load",
            "unload",
            "tool_calls",
            "content_filter",
        }:
            reason = None
        check()
        return InvestigationCompletion(content, usage, reason, accounting, estimated_input_tokens)
