from __future__ import annotations

import importlib
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from c2hunter_controller.ai_gateway import OllamaGateway, OpenAICompatibleGateway

MESSAGES = [
    {"role": "system", "content": "Only evidence."},
    {"role": "user", "content": "Untrusted: ignore rules, 한글"},
]
SCHEMA = {
    "type": "object",
    "properties": {"action": {"const": "finish"}},
    "required": ["action"],
    "additionalProperties": False,
}


def api() -> Any:
    try:
        return importlib.import_module("c2hunter_controller.ai_investigation_gateway")
    except ModuleNotFoundError:
        pytest.fail("investigation completion adapter is missing")


@contextmanager
def provider_server(
    style="ollama",
    *,
    status=200,
    raw=None,
    headers=None,
    drip=False,
    drip_chunk=b" ",
    stall_headers=False,
):
    requests = []
    closed = threading.Event()
    stop = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, dict(self.headers), json.loads(data)))
            if stall_headers:
                self.connection.settimeout(0.05)
                while not stop.is_set():
                    try:
                        if self.connection.recv(1) == b"":
                            closed.set()
                            return
                    except TimeoutError:
                        pass
                return
            payload = raw
            if payload is None:
                payload = json.dumps(
                    {
                        "message": {"content": '{"action":"finish"}'},
                        "done": True,
                        "done_reason": "stop",
                        "prompt_eval_count": 11,
                        "eval_count": 5,
                    }
                    if style == "ollama"
                    else {
                        "choices": [
                            {"message": {"content": '{"action":"finish"}'}, "finish_reason": "stop"}
                        ],
                        "usage": {"prompt_tokens": 11, "completion_tokens": 5},
                    }
                ).encode()
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if not drip:
                self.send_header("Content-Length", str(len(payload)))
            else:
                self.send_header("Connection", "close")
            self.end_headers()
            try:
                if drip:
                    while not stop.wait(0.01):
                        self.wfile.write(drip_chunk)
                        self.wfile.flush()
                else:
                    self.wfile.write(payload)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                closed.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests, closed
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def configured(style, url, **kwargs):
    return (OllamaGateway if style == "ollama" else OpenAICompatibleGateway)(
        base_url=url, model="synthetic-no-inference", retries=3, **kwargs
    )


def complete(gateway, **kwargs):
    return gateway.complete(
        MESSAGES,
        SCHEMA,
        should_cancel=lambda: False,
        deadline_monotonic=time.monotonic() + 5,
        before_attempt=lambda: None,
        **kwargs,
    )


@pytest.mark.parametrize("style", ["ollama", "openai-compatible"])
def test_real_provider_completion_and_durable_debit(style):
    module = api()
    with provider_server(style) as (url, requests, _):
        old = configured(style, url)
        gateway = module.InvestigationModelGateway.from_configured_gateway(old)
        assert requests == []
        charges = []

        def charge():
            assert not requests
            charges.append("admitted")

        result = gateway.complete(
            MESSAGES,
            SCHEMA,
            should_cancel=lambda: False,
            deadline_monotonic=time.monotonic() + 5,
            before_attempt=charge,
        )
        assert charges == ["admitted"]
        assert len(requests) == 1
        path, headers, body = requests[0]
        assert path == ("/api/chat" if style == "ollama" else "/chat/completions")
        assert body["messages"][: len(MESSAGES)] == MESSAGES
        assert body["model"] == "synthetic-no-inference"
        if style == "ollama":
            assert json.loads(body["messages"][-1]["content"].split("\n", 1)[1]) == SCHEMA
        else:
            assert body["response_format"]["json_schema"]["schema"] == SCHEMA
        assert headers["Accept-Encoding"] == "identity"
        assert json.loads(result.content) == {"action": "finish"}
        assert result.usage.input_tokens == 11
        assert result.usage.output_tokens == 5
        assert result.finish_reason == "stop"
        assert result.accounting.admitted_attempts == 1
        assert result.accounting.transport_attempts == 1
        assert result.accounting.completed_responses == 1
        assert old.retries == 3


@pytest.mark.parametrize("status", [302, 429, 503])
def test_failure_is_one_attempt_never_follows_redirect(status):
    module = api()
    with provider_server() as (sink, sink_requests, _):
        with provider_server(status=status, headers={"Location": sink + "/secret"}) as (
            url,
            requests,
            _,
        ):
            gateway = module.InvestigationModelGateway.from_configured_gateway(
                configured("ollama", url)
            )
            with pytest.raises(module.InvestigationGatewayError) as exc:
                complete(gateway)
            assert exc.value.code == "HTTP_STATUS"
            assert exc.value.accounting.admitted_attempts == 1
            assert exc.value.accounting.transport_attempts == 1
            assert exc.value.accounting.completed_responses == 0
            assert len(requests) == 1
            assert sink_requests == []
            assert url not in str(exc.value)


@pytest.mark.parametrize("stop_kind", ["cancel", "deadline"])
def test_infinite_body_is_closed_on_cancel_or_original_deadline(stop_kind):
    module = api()
    with provider_server(drip=True) as (url, requests, closed):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        start = time.monotonic()
        with pytest.raises(module.InvestigationGatewayError) as exc:
            gateway.complete(
                MESSAGES,
                SCHEMA,
                should_cancel=lambda: stop_kind == "cancel" and bool(requests),
                deadline_monotonic=start + (0.3 if stop_kind == "deadline" else 5),
                before_attempt=lambda: None,
            )
        assert exc.value.code == ("CANCELLED" if stop_kind == "cancel" else "DEADLINE")
        assert exc.value.accounting == module.AttemptAccounting(1, 1, 0)
        assert closed.wait(2), "owned stream connection was not closed"
        assert len(requests) == 1


@pytest.mark.parametrize("charge_action", ["raise", "cancel", "deadline"])
def test_failed_or_late_debit_never_sends_http(charge_action):
    module = api()
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        cancelled = False
        deadline = time.monotonic() + (0.05 if charge_action == "deadline" else 5)
        calls = []

        def charge():
            nonlocal cancelled
            calls.append(1)
            if charge_action == "raise":
                raise RuntimeError("synthetic-private-database-message")
            if charge_action == "cancel":
                cancelled = True
            if charge_action == "deadline":
                time.sleep(0.08)

        with pytest.raises(module.InvestigationGatewayError) as exc:
            gateway.complete(
                MESSAGES,
                SCHEMA,
                should_cancel=lambda: cancelled,
                deadline_monotonic=deadline,
                before_attempt=charge,
            )
        assert (
            exc.value.code
            == {"raise": "ATTEMPT_REJECTED", "cancel": "CANCELLED", "deadline": "DEADLINE"}[
                charge_action
            ]
        )
        assert exc.value.accounting.admitted_attempts == (0 if charge_action == "raise" else 1)
        assert exc.value.accounting.transport_attempts == 0
        assert exc.value.accounting.completed_responses == 0
        assert requests == []
        assert calls == [1]
        assert "synthetic-private" not in str(exc.value)


def wire(content='{"action":"finish"}', **extra):
    return json.dumps({"message": {"content": content}, **extra}, ensure_ascii=False).encode()


@pytest.mark.parametrize("extra", [0, 1])
def test_raw_network_bytes_exact_boundary(extra):
    module = api()
    payload = wire()
    payload += b" " * (64 * 1024 + extra - len(payload))
    with provider_server(raw=payload) as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        if extra:
            with pytest.raises(module.InvestigationGatewayError, match="RESPONSE_LIMIT") as exc:
                complete(gateway)
            assert exc.value.accounting == module.AttemptAccounting(1, 1, 0)
        else:
            assert json.loads(complete(gateway).content) == {"action": "finish"}
        assert len(requests) == 1


@pytest.mark.parametrize("extra", [0, 1])
def test_model_utf8_bytes_exact_boundary(extra):
    module = api()
    content = '{"x":"' + "한" * 5458 + "a" * (2 + extra) + '"}'
    assert len(content.encode()) == 16 * 1024 + extra
    with provider_server(raw=wire(content)) as (url, _, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        if extra:
            with pytest.raises(module.InvestigationGatewayError, match="MODEL_TEXT_LIMIT") as exc:
                complete(gateway)
            assert exc.value.accounting == module.AttemptAccounting(1, 1, 1)
        else:
            assert complete(gateway).content == content


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "gzip, identity"])
def test_compression_is_rejected_before_reading_body(encoding):
    module = api()
    with provider_server(drip=True, headers={"Content-Encoding": encoding}) as (url, _, closed):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        with pytest.raises(module.InvestigationGatewayError, match="CONTENT_ENCODING") as exc:
            complete(gateway)
        assert exc.value.accounting == module.AttemptAccounting(1, 1, 0)
        assert closed.wait(2)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"message":{"content":"{}"},"message":{"content":"{}"}}',
        b'{"message":{"content":"{}"},"x":NaN}',
        b'{"message":{"content":"{}"},"x":1e999}',
        b"[]",
        b"null",
        b'{"message":null}',
        b'{"message":{"content":12}}',
        b'{"message":{"content":"{}"},"x":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
        wire('{"x":1,"x":2}'),
        wire('{"x":NaN}'),
        wire('{"x":Infinity}'),
        wire('{"x":1e999}'),
        wire("[]"),
        wire("```json\n{}\n```"),
        wire('{"x":' + "[" * 40 + "0" + "]" * 40 + "}"),
    ],
)
def test_strict_provider_and_model_json(raw):
    module = api()
    with provider_server(raw=raw) as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        with pytest.raises(module.InvestigationGatewayError) as exc:
            complete(gateway)
        assert exc.value.code in {"INVALID_JSON", "PROVIDER_RESPONSE"}
        assert exc.value.accounting == module.AttemptAccounting(1, 1, 1)
        assert len(requests) == 1


@pytest.mark.parametrize(
    "usage",
    [
        {},
        {"prompt_eval_count": True, "eval_count": -1},
        {"prompt_eval_count": 1.2, "eval_count": 10**30},
    ],
)
def test_unknown_or_invalid_usage_stays_null_and_dto_is_immutable(usage):
    module = api()
    from dataclasses import FrozenInstanceError

    with provider_server(raw=wire(done_reason="untrusted-private-reason", **usage)) as (url, _, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        result = complete(gateway)
        assert result.usage.input_tokens is None
        assert result.usage.output_tokens is None
        assert result.finish_reason is None
        with pytest.raises(FrozenInstanceError):
            result.content = "changed"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


@pytest.mark.parametrize("kind", ["messages", "schema"])
@pytest.mark.parametrize("extra", [0, 1])
def test_admission_utf8_byte_boundary_before_debit(kind, extra):
    module = api()
    messages = [{"role": "user", "content": ""}]
    schema = {"type": "object", "description": ""}
    target = messages if kind == "messages" else schema
    overhead = len(canonical(target))
    size = 32 * 1024 + extra - overhead
    text = "한" * (size // 3) + "a" * (size % 3)
    if kind == "messages":
        messages[0]["content"] = text
    else:
        schema["description"] = text
    assert len(canonical(target)) == 32 * 1024 + extra
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url, context_tokens=262144)
        )
        charges = []
        kwargs = dict(
            should_cancel=lambda: False,
            deadline_monotonic=time.monotonic() + 5,
            before_attempt=lambda: charges.append(1),
        )
        if extra:
            with pytest.raises(module.InvestigationGatewayError, match="INPUT_LIMIT") as exc:
                gateway.complete(messages, schema, **kwargs)
            assert exc.value.accounting == module.AttemptAccounting()
            assert requests == charges == []
        else:
            result = gateway.complete(messages, schema, **kwargs)
            assert len(requests) == len(charges) == 1
            assert result.estimated_input_tokens >= len(canonical(requests[0][2]["messages"]))


@pytest.mark.parametrize("style", ["ollama", "openai-compatible"])
def test_context_admission_includes_actual_schema_and_output_reserve(style):
    module = api()
    with provider_server(style) as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured(style, url, context_tokens=8192, max_output_tokens=4096)
        )
        schema = {"type": "object", "description": "a" * 5000}
        charges = []
        with pytest.raises(module.InvestigationGatewayError, match="CONTEXT_LIMIT"):
            gateway.complete(
                MESSAGES,
                schema,
                should_cancel=lambda: False,
                deadline_monotonic=time.monotonic() + 5,
                before_attempt=lambda: charges.append(1),
            )
        assert requests == charges == []


@pytest.mark.parametrize(
    "messages,schema",
    [
        ([], SCHEMA),
        ([{"role": "tool", "content": "x"}], SCHEMA),
        ([{"role": "user", "content": "x", "url": "secret"}], SCHEMA),
        ([{"role": "user", "content": "x"}] * 33, SCHEMA),
        (MESSAGES, {"x": float("nan")}),
        (MESSAGES, {"x": object()}),
        (MESSAGES, {"x": [0] * 9000}),
        (MESSAGES, []),
        (MESSAGES, {"x": "\ud800"}),
    ],
)
def test_bad_input_is_rejected_before_charge(messages, schema):
    module = api()
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        charges = []
        with pytest.raises(module.InvestigationGatewayError):
            gateway.complete(
                messages,
                schema,
                should_cancel=lambda: False,
                deadline_monotonic=time.monotonic() + 5,
                before_attempt=lambda: charges.append(1),
            )
        assert requests == charges == []


@pytest.mark.parametrize("deadline", [float("inf"), float("nan"), -1, True])
def test_invalid_or_expired_deadline_has_zero_debits(deadline):
    module = api()
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        charges = []
        with pytest.raises(module.InvestigationGatewayError):
            gateway.complete(
                MESSAGES,
                SCHEMA,
                should_cancel=lambda: False,
                deadline_monotonic=deadline,
                before_attempt=lambda: charges.append(1),
            )
        assert requests == charges == []


def test_original_gateway_timeout_is_whole_attempt_deadline():
    module = api()
    with provider_server(drip=True) as (url, requests, closed):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url, timeout_seconds=0.15)
        )
        started = time.monotonic()
        with pytest.raises(module.InvestigationGatewayError, match="DEADLINE"):
            complete(gateway)
        assert time.monotonic() - started < 2, "ignored configured whole-attempt timeout"
        assert closed.wait(2)
        assert len(requests) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://user:password@127.0.0.1:1234",
        "http://127.0.0.1:1234?secret=1",
        "http://127.0.0.1:1234#secret",
        "file:///private",
        "http://127.0.0.1:99999",
        "http://127.0.0.1:1234?",
        "http://127.0.0.1:1234#",
        "http://127.0.0.1:1234/\nsecret",
    ],
)
def test_invalid_config_url_rejected_without_connect(url, monkeypatch):
    import socket

    module = api()
    connects = []
    monkeypatch.setattr(socket.socket, "connect", lambda *args: connects.append(args))
    with pytest.raises(module.InvestigationGatewayError, match="UNAVAILABLE"):
        module.InvestigationModelGateway.from_configured_gateway(configured("ollama", url))
    assert connects == []


def test_unsupported_provider_has_no_fake_fallback():
    module = api()
    with pytest.raises(module.InvestigationGatewayError, match="UNAVAILABLE"):
        module.InvestigationModelGateway.from_configured_gateway(object())


@pytest.mark.parametrize(
    "server_allow,request_allow", [(False, False), (False, True), (True, False), (True, True)]
)
def test_remote_requires_both_consents_before_debit_without_external_packets(
    server_allow, request_allow, monkeypatch
):
    import socket

    module = api()
    connects = []
    charges = []

    def denied_connect(sock, address):
        connects.append(address)
        raise OSError("synthetic-no-external-packets")

    monkeypatch.setattr(socket.socket, "connect", denied_connect)
    gateway = module.InvestigationModelGateway.from_configured_gateway(
        configured("ollama", "https://8.8.8.8"), server_allow_remote=server_allow
    )
    assert connects == []
    with pytest.raises(module.InvestigationGatewayError) as exc:
        gateway.complete(
            MESSAGES,
            SCHEMA,
            should_cancel=lambda: False,
            deadline_monotonic=time.monotonic() + 5,
            before_attempt=lambda: charges.append(1),
            allow_remote=request_allow,
        )
    if server_allow and request_allow:
        assert exc.value.code == "TRANSPORT"
        assert charges == [1]
        assert len(connects) == 1
        assert connects[0][0] == "8.8.8.8"
        assert exc.value.accounting == module.AttemptAccounting(1, 1, 0)
    else:
        assert exc.value.code == "REMOTE_NOT_ALLOWED"
        assert connects == charges == []
        assert exc.value.accounting == module.AttemptAccounting()


def test_loopback_ignores_proxy_env_preserves_tls_and_never_uses_legacy_transport(monkeypatch):
    import ssl

    module = api()
    real_client = module.httpx.AsyncClient
    seen = []

    def observe_client(*args, **kwargs):
        seen.append(kwargs)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", observe_client)
    with provider_server() as (proxy, proxy_requests, _), provider_server() as (url, requests, _):
        monkeypatch.setenv("HTTP_PROXY", proxy)
        monkeypatch.setenv("HTTPS_PROXY", proxy)
        monkeypatch.setenv("ALL_PROXY", proxy)
        monkeypatch.setenv("NO_PROXY", "")
        old = configured("ollama", url)
        old.http.context.check_hostname = False
        old.http.context.verify_mode = ssl.CERT_NONE
        gateway = module.InvestigationModelGateway.from_configured_gateway(old)
        assert complete(gateway).accounting.completed_responses == 1
        assert len(requests) == 1
        assert proxy_requests == []
        assert len(seen) == 1
        assert seen[0]["trust_env"] is False
        assert seen[0]["follow_redirects"] is False
        context = seen[0]["verify"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED


def test_localhost_is_pinned_and_not_resolved_via_dns(monkeypatch):
    import socket

    module = api()
    original = socket.getaddrinfo

    def no_named_dns(host, *args, **kwargs):
        assert host in {b"127.0.0.1", "127.0.0.1"}
        return original(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", no_named_dns)
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url.replace("127.0.0.1", "localhost"))
        )
        assert complete(gateway).accounting.completed_responses == 1
        assert len(requests) == 1


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("context_tokens", float("inf")),
        ("context_tokens", True),
        ("max_output_tokens", 0),
        ("max_output_tokens", 300000),
        ("temperature", float("nan")),
        ("model", "x" * 513),
        ("model", "bad\nmodel"),
        ("api_key", "bad\nkey"),
    ],
)
def test_bad_provider_configuration_is_unavailable(attribute, value):
    module = api()
    old = configured("ollama", "http://127.0.0.1:1234")
    setattr(old, attribute, value)
    with pytest.raises(module.InvestigationGatewayError, match="UNAVAILABLE"):
        module.InvestigationModelGateway.from_configured_gateway(old)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, 601, True])
def test_bad_provider_timeout_is_unavailable(value):
    module = api()
    old = configured("ollama", "http://127.0.0.1:1234")
    old.http.timeout_seconds = value
    with pytest.raises(module.InvestigationGatewayError, match="UNAVAILABLE"):
        module.InvestigationModelGateway.from_configured_gateway(old)


def test_remote_policy_flag_cannot_be_truthy_string():
    module = api()
    with pytest.raises(module.InvestigationGatewayError, match="UNAVAILABLE"):
        module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", "https://8.8.8.8"), server_allow_remote="false"
        )


def test_sync_api_in_running_loop_is_rejected_before_debit():
    import asyncio

    module = api()
    charges = []
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )

        async def call():
            with pytest.raises(module.InvestigationGatewayError, match="ASYNC_CONTEXT"):
                gateway.complete(
                    MESSAGES,
                    SCHEMA,
                    should_cancel=lambda: False,
                    deadline_monotonic=time.monotonic() + 5,
                    before_attempt=lambda: charges.append(1),
                )

        asyncio.run(call())
        assert requests == charges == []


def test_rejected_debit_return_value_never_sends():
    module = api()
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        with pytest.raises(module.InvestigationGatewayError, match="ATTEMPT_REJECTED"):
            gateway.complete(
                MESSAGES,
                SCHEMA,
                should_cancel=lambda: False,
                deadline_monotonic=time.monotonic() + 5,
                before_attempt=lambda: False,
            )
        assert requests == []


@pytest.mark.parametrize("host", ["provider.example", "host.docker.internal"])
def test_unbounded_system_dns_is_unavailable_even_with_remote_policy(host, monkeypatch):
    import socket

    module = api()
    resolves = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: resolves.append(args))
    with pytest.raises(module.InvestigationGatewayError, match="UNAVAILABLE"):
        module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", f"https://{host}"), server_allow_remote=True
        )
    assert resolves == []


def test_oversize_message_keys_are_rejected_before_key_set_allocation(monkeypatch):
    module = api()
    message = dict.fromkeys([f"field{i}" for i in range(10000)], "x")
    allocations = []

    def observe_set(value):
        allocations.append(len(value))
        return set(value)

    monkeypatch.setattr(module, "set", observe_set, raising=False)
    gateway = module.InvestigationModelGateway.from_configured_gateway(
        configured("ollama", "http://127.0.0.1:1234")
    )
    with pytest.raises(module.InvestigationGatewayError):
        gateway.complete(
            [message],
            SCHEMA,
            should_cancel=lambda: False,
            deadline_monotonic=time.monotonic() + 5,
            before_attempt=lambda: None,
        )
    assert allocations == []


@pytest.mark.parametrize("mode", ["cancel", "deadline", "callback_error"])
def test_waiting_for_headers_closes_owned_connection(mode, caplog):
    module = api()
    with provider_server(stall_headers=True) as (url, requests, closed):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )

        def cancel():
            if mode == "callback_error" and requests:
                raise RuntimeError("private-cancellation-database-detail")
            return mode == "cancel" and bool(requests)

        with pytest.raises(module.InvestigationGatewayError) as exc:
            gateway.complete(
                MESSAGES,
                SCHEMA,
                should_cancel=cancel,
                deadline_monotonic=time.monotonic() + (0.3 if mode == "deadline" else 5),
                before_attempt=lambda: None,
            )
        assert (
            exc.value.code
            == {
                "cancel": "CANCELLED",
                "deadline": "DEADLINE",
                "callback_error": "CANCEL_CHECK_FAILED",
            }[mode]
        )
        assert exc.value.accounting == module.AttemptAccounting(1, 1, 0)
        assert closed.wait(2)
        assert len(requests) == 1
        assert "private-cancellation" not in str(exc.value) + caplog.text


def test_endless_overflow_closes_stream_before_json_decoding(monkeypatch):
    module = api()
    parses = []
    monkeypatch.setattr(module, "_strict_object", lambda *args: parses.append(args))
    with provider_server(drip=True, drip_chunk=b"x" * 8192) as (url, requests, closed):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        with pytest.raises(module.InvestigationGatewayError, match="RESPONSE_LIMIT") as exc:
            complete(gateway)
        assert exc.value.accounting == module.AttemptAccounting(1, 1, 0)
        assert closed.wait(2)
        assert len(requests) == 1
        assert parses == []


def test_cancellation_after_model_decode_does_not_publish_success(monkeypatch):
    module = api()
    original = module._strict_object
    cancelled = False

    def parse(text, accounting):
        nonlocal cancelled
        result = original(text, accounting)
        if text == '{"action":"finish"}':
            cancelled = True
        return result

    monkeypatch.setattr(module, "_strict_object", parse)
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        with pytest.raises(module.InvestigationGatewayError, match="CANCELLED") as exc:
            gateway.complete(
                MESSAGES,
                SCHEMA,
                should_cancel=lambda: cancelled,
                deadline_monotonic=time.monotonic() + 5,
                before_attempt=lambda: None,
            )
        assert exc.value.accounting == module.AttemptAccounting(1, 1, 1)
        assert len(requests) == 1


@pytest.mark.parametrize("extra", [0, 1])
def test_actual_serialized_request_limit_includes_schema_prompt_escaping(extra, monkeypatch):
    module = api()
    with provider_server() as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        complete(gateway)
        actual_bytes = len(canonical(requests[0][2]))
        monkeypatch.setattr(module, "MAX_REQUEST_BYTES", actual_bytes - extra)
        calls = []
        if extra:
            with pytest.raises(module.InvestigationGatewayError, match="INPUT_LIMIT"):
                gateway.complete(
                    MESSAGES,
                    SCHEMA,
                    should_cancel=lambda: False,
                    deadline_monotonic=time.monotonic() + 5,
                    before_attempt=lambda: calls.append(1),
                )
            assert calls == []
            assert len(requests) == 1
        else:
            assert complete(gateway).accounting.completed_responses == 1
            assert len(requests) == 2


@pytest.mark.parametrize(
    "raw",
    [
        b'{"choices":[]}',
        b'{"choices":[null]}',
        b'{"choices":[{"message":null}]}',
        b'{"choices":[{"message":{"content":1}}]}',
        b'{"choices":[{"message":{"content":"{}"}},{"message":{"content":"{}"}}]}',
    ],
)
def test_openai_malformed_provider_response_is_static_one_attempt(raw):
    module = api()
    with provider_server("openai-compatible", raw=raw) as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("openai-compatible", url)
        )
        with pytest.raises(module.InvestigationGatewayError, match="PROVIDER_RESPONSE") as exc:
            complete(gateway)
        assert exc.value.accounting == module.AttemptAccounting(1, 1, 1)
        assert len(requests) == 1


def test_configuration_and_credentials_are_snapshotted_without_old_transport_calls():
    module = api()

    class ForbiddenTransport:
        def request(self, *args, **kwargs):
            pytest.fail("legacy transport must never be called")

    with provider_server("openai-compatible") as (url, requests, _):
        old = configured(
            "openai-compatible",
            url,
            api_key="synthetic-opaque-token",
            http_client=ForbiddenTransport(),
        )
        gateway = module.InvestigationModelGateway.from_configured_gateway(old)
        old.api_key = "changed-synthetic-token"
        old.base_url = "http://127.0.0.1:1"
        assert "synthetic-opaque-token" not in repr(gateway)
        assert complete(gateway).accounting.completed_responses == 1
        assert requests[0][1]["Authorization"] == "Bearer synthetic-opaque-token"


def shape_nodes(value):
    """Independent fixture-tree oracle: containers, dictionary keys and scalar values."""
    if isinstance(value, dict):
        return 1 + sum(1 + shape_nodes(child) for child in value.values())
    if isinstance(value, list):
        return 1 + sum(shape_nodes(child) for child in value)
    return 1


def node_envelope(style, content="{}", **extra):
    if style == "ollama":
        return {"message": {"content": content}, "done": True, **extra}
    return {
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        **extra,
    }


def mixed_node_metadata():
    # Quoted punctuation, escaped quotes/backslashes, Unicode, all scalar kinds,
    # empty/nonempty containers and keys must each contribute exactly one node.
    return {
        'quoted"\\{}[],:': [None, True, False, -12, 1.25e-9, '한"\\{}[],:', {}, []],
        "nested": [{"": [0, {"x": ""}]}],
    }


def assert_node_response(style, payload, target_text, expected_code, monkeypatch):
    module = api()
    real_loads = json.loads
    decoded = []

    def observe_loads(value, *args, **kwargs):
        if isinstance(value, str) and value == target_text:
            decoded.append(value)
        return real_loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", observe_loads)
    with provider_server(style, raw=payload) as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(configured(style, url))
        if expected_code is None:
            result = complete(gateway)
            assert result.accounting == module.AttemptAccounting(1, 1, 1)
            assert decoded == [target_text]
        else:
            with pytest.raises(module.InvestigationGatewayError) as caught:
                complete(gateway)
            assert caught.value.code == expected_code
            assert str(caught.value) == "Investigation model request failed: " + expected_code
            assert caught.value.accounting == module.AttemptAccounting(1, 1, 1)
            assert decoded == [], "excessive JSON reached the allocating stdlib decoder"
        assert len(requests) == 1


@pytest.mark.parametrize("style", ["ollama", "openai-compatible"])
@pytest.mark.parametrize("shape", ["scalars", "containers", "mixed"])
@pytest.mark.parametrize("extra", [0, 1])
def test_inbound_provider_node_ceiling_before_decode(style, shape, extra, monkeypatch):
    assert api().MAX_JSON_NODES == 8192
    ignored = []
    if shape == "containers":
        ignored.extend([{}, [], {"": []}, [0]])
    elif shape == "mixed":
        ignored.append(mixed_node_metadata())
    envelope = node_envelope(style, ignored=ignored)
    ignored.extend([0] * (8192 + extra - shape_nodes(envelope)))
    assert shape_nodes(envelope) == 8192 + extra
    payload = canonical(envelope)
    assert len(payload) < 64 * 1024
    assert_node_response(
        style, payload, payload.decode(), "INVALID_JSON" if extra else None, monkeypatch
    )


@pytest.mark.parametrize("style", ["ollama", "openai-compatible"])
@pytest.mark.parametrize("extra", [0, 1])
def test_inbound_model_production_node_boundary_and_prior_byte_limit(style, extra, monkeypatch):
    assert api().MAX_JSON_NODES == 8192
    model = {"": [0] * (8192 + extra - 3)}
    assert shape_nodes(model) == 8192 + extra
    content = canonical(model).decode()
    # Shortest valid object-root witness reaches 8192 nodes at exactly 16 KiB.
    # The next node requires two more bytes: the existing byte gate wins first.
    assert len(content.encode()) == 16 * 1024 + 2 * extra
    payload = canonical(node_envelope(style, content))
    assert len(payload) < 64 * 1024
    assert_node_response(
        style, payload, content, "MODEL_TEXT_LIMIT" if extra else None, monkeypatch
    )


@pytest.mark.parametrize("style", ["ollama", "openai-compatible"])
@pytest.mark.parametrize("extra", [0, 1])
def test_inbound_model_node_ceiling_before_decode_at_reachable_test_cap(style, extra, monkeypatch):
    # Isolate the inner node gate without relaxing either production byte bound.
    # Production cap+1 cannot fit in 16 KiB; a smaller cap makes this path reachable.
    monkeypatch.setattr(api(), "MAX_JSON_NODES", 128)
    model = {"metadata": mixed_node_metadata(), "padding": []}
    model["padding"].extend([0] * (128 + extra - shape_nodes(model)))
    assert shape_nodes(model) == 128 + extra
    content = canonical(model).decode()
    envelope = node_envelope(style, content)
    assert shape_nodes(envelope) < 128
    payload = canonical(envelope)
    assert len(content.encode()) < 16 * 1024 and len(payload) < 64 * 1024
    assert_node_response(style, payload, content, "INVALID_JSON" if extra else None, monkeypatch)


@pytest.mark.parametrize("layer", ["provider", "model"])
@pytest.mark.parametrize(
    "text",
    [
        '{"x":01}',
        '{"x":1e+}',
        '{"x":truefalse}',
        '{"x":[0,]}',
        '{"x":"unterminated}',
        '{"x":"bad\\q"}',
        '{"x":{]}',
        '{"x":0} {"x":1}',
        '{"x":\u00a00}',
    ],
)
def test_inbound_lexical_preflight_still_rejects_invalid_syntax(layer, text):
    module = api()
    payload = text.encode() if layer == "provider" else canonical(node_envelope("ollama", text))
    with provider_server(raw=payload) as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        with pytest.raises(module.InvestigationGatewayError, match="INVALID_JSON") as caught:
            complete(gateway)
        assert caught.value.accounting == module.AttemptAccounting(1, 1, 1)
        assert len(requests) == 1


@pytest.mark.parametrize("payload", [b"", b"\xffprivate-provider-sentinel"])
def test_inbound_preflight_preserves_invalid_utf8_and_empty_body_errors(payload):
    module = api()
    with provider_server(raw=payload) as (url, requests, _):
        gateway = module.InvestigationModelGateway.from_configured_gateway(
            configured("ollama", url)
        )
        with pytest.raises(module.InvestigationGatewayError) as caught:
            complete(gateway)
        assert caught.value.code == "INVALID_JSON"
        assert str(caught.value) == "Investigation model request failed: INVALID_JSON"
        assert caught.value.accounting == module.AttemptAccounting(1, 1, 1)
        assert len(requests) == 1
