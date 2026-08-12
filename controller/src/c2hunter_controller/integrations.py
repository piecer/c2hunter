"""Outbound threat-intelligence and MISP integrations.

The controller performs bounded automatic or operator-triggered lookups and only
operator-triggered exports. API keys are never returned in provider data or errors.
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Protocol, cast

import httpx


class IntegrationError(Exception):
    """A sanitized external integration failure."""

    def __init__(
        self,
        provider: str,
        message: str,
        *,
        http_status: int | None = None,
        retry_after: str | None = None,
    ) -> None:
        super().__init__(message)
        self.provider = provider
        self.message = message
        self.http_status = http_status
        self.retry_after = retry_after


def _transport_failure_message(exc: BaseException) -> str:
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "external service TLS certificate verification failed"
    if isinstance(reason, socket.gaierror):
        return "external service DNS resolution failed"
    if isinstance(reason, ConnectionRefusedError):
        return "external service connection refused"
    if isinstance(reason, TimeoutError):
        return "external service request timed out"
    return "external service request failed"


class ThreatIntelLookup(Protocol):
    def lookup_ip(self, ip_address: str) -> dict[str, Any]: ...


class MispPublisher(Protocol):
    def lookup_ip(self, ip_address: str) -> dict[str, Any]: ...

    def add_ip_attribute(self, event_id: str, ip_address: str, comment: str) -> dict[str, Any]: ...


class JsonHttpClient:
    """Small JSON HTTP client with bounded timeout and optional TLS verification."""

    def __init__(self, timeout_seconds: float = 10.0, *, verify_tls: bool = True) -> None:
        self.timeout_seconds = timeout_seconds
        self.context = ssl.create_default_context()
        if not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
                context=self.context,
            ) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
                if len(payload) > 2 * 1024 * 1024:
                    raise IntegrationError("http", "external service response exceeded 2 MiB")
        except urllib.error.HTTPError as exc:
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            raise IntegrationError(
                "http",
                f"external service returned HTTP {exc.code}",
                http_status=exc.code,
                retry_after=retry_after,
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise IntegrationError("http", _transport_failure_message(exc)) from exc
        try:
            parsed = json.loads(payload or b"{}")
        except json.JSONDecodeError as exc:
            raise IntegrationError("http", "external service returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise IntegrationError("http", "external service returned an invalid response")
        return cast(dict[str, Any], parsed)


class CancellableJsonHttpClient(JsonHttpClient):
    """AI transport that closes an in-flight request when cancellation is observed."""

    def request_cancellable(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
        should_cancel: Callable[[], bool],
    ) -> dict[str, Any]:
        async def perform() -> httpx.Response:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                verify=self.context,
            ) as client:
                task = asyncio.create_task(client.request(method, url, headers=headers, json=body))
                while not task.done():
                    if should_cancel():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                        raise InterruptedError("external service request cancelled")
                    await asyncio.sleep(0.05)
                return await task

        try:
            response = asyncio.run(perform())
            response.raise_for_status()
        except InterruptedError:
            raise
        except httpx.HTTPStatusError as exc:
            retry_after = exc.response.headers.get("Retry-After")
            raise IntegrationError(
                "http",
                f"external service returned HTTP {exc.response.status_code}",
                http_status=exc.response.status_code,
                retry_after=retry_after,
            ) from exc
        except (httpx.HTTPError, TimeoutError, OSError) as exc:
            raise IntegrationError("http", "external service request failed") from exc
        if len(response.content) > 2 * 1024 * 1024:
            raise IntegrationError("http", "external service response exceeded 2 MiB")
        try:
            parsed = response.json()
        except ValueError as exc:
            raise IntegrationError("http", "external service returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise IntegrationError("http", "external service returned an invalid response")
        return cast(dict[str, Any], parsed)


class ThreatIntelService:
    """Query configured IP reputation providers and normalize their responses."""

    def __init__(
        self,
        *,
        virustotal_api_key: str = "",
        abuseipdb_api_key: str = "",
        abuseipdb_max_age_days: int = 90,
        http_client: JsonHttpClient | None = None,
    ) -> None:
        self.virustotal_api_key = virustotal_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.abuseipdb_max_age_days = abuseipdb_max_age_days
        self.http = http_client or JsonHttpClient()

    def lookup_ip(self, ip_address: str) -> dict[str, Any]:
        normalized_ip = str(ip_address_value(ip_address))
        providers: dict[str, dict[str, Any]] = {}
        if self.virustotal_api_key:
            providers["virustotal"] = self._safe_lookup(
                "virustotal", lambda: self._lookup_virustotal(normalized_ip)
            )
        else:
            providers["virustotal"] = {"status": "NOT_CONFIGURED"}
        if self.abuseipdb_api_key:
            providers["abuseipdb"] = self._safe_lookup(
                "abuseipdb", lambda: self._lookup_abuseipdb(normalized_ip)
            )
        else:
            providers["abuseipdb"] = {"status": "NOT_CONFIGURED"}
        vt = providers["virustotal"]
        abuse = providers["abuseipdb"]
        return {
            "ip_address": normalized_ip,
            "fetched_at": datetime.now(UTC).isoformat(),
            "summary": {
                "malicious": int(vt.get("malicious", 0) or 0),
                "suspicious": int(vt.get("suspicious", 0) or 0),
                "harmless": int(vt.get("harmless", 0) or 0),
                "abuse_confidence_score": int(abuse.get("abuse_confidence_score", 0) or 0),
                "country_code": abuse.get("country_code") or vt.get("country_code"),
                "network_owner": abuse.get("isp") or vt.get("network_owner"),
            },
            "providers": providers,
        }

    @staticmethod
    def _safe_lookup(provider: str, callback: Any) -> dict[str, Any]:
        try:
            return cast(dict[str, Any], callback())
        except IntegrationError as exc:
            if exc.http_status in {401, 403}:
                status = "AUTH_ERROR"
            elif exc.http_status == 429:
                status = "RATE_LIMITED"
            else:
                status = "ERROR"
            result = {"status": status, "error": exc.message, "provider": provider}
            if exc.retry_after:
                result["retry_after"] = exc.retry_after
            return result

    def _lookup_virustotal(self, ip_address: str) -> dict[str, Any]:
        payload = self.http.request(
            "GET",
            f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip_address)}",
            headers={"x-apikey": self.virustotal_api_key, "Accept": "application/json"},
        )
        attributes = _mapping(_mapping(payload.get("data")).get("attributes"))
        stats = _mapping(attributes.get("last_analysis_stats"))
        return {
            "status": "OK",
            "malicious": _integer(stats.get("malicious")),
            "suspicious": _integer(stats.get("suspicious")),
            "harmless": _integer(stats.get("harmless")),
            "undetected": _integer(stats.get("undetected")),
            "reputation": _integer(attributes.get("reputation")),
            "country_code": attributes.get("country"),
            "network_owner": attributes.get("as_owner"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }

    def _lookup_abuseipdb(self, ip_address: str) -> dict[str, Any]:
        query = urllib.parse.urlencode(
            {"ipAddress": ip_address, "maxAgeInDays": self.abuseipdb_max_age_days}
        )
        payload = self.http.request(
            "GET",
            f"https://api.abuseipdb.com/api/v2/check?{query}",
            headers={"Key": self.abuseipdb_api_key, "Accept": "application/json"},
        )
        data = _mapping(payload.get("data"))
        return {
            "status": "OK",
            "abuse_confidence_score": _integer(data.get("abuseConfidenceScore")),
            "total_reports": _integer(data.get("totalReports")),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": bool(data.get("isTor", False)),
            "is_whitelisted": data.get("isWhitelisted"),
        }


class MispClient:
    """Search candidate IPs and publish confirmed IPs as MISP attributes."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        http_client: JsonHttpClient | None = None,
    ) -> None:
        parsed_url = urllib.parse.urlsplit(base_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise ValueError("MISP URL must be an absolute HTTP or HTTPS URL")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.http = http_client or JsonHttpClient()

    def lookup_ip(self, ip_address: str) -> dict[str, Any]:
        normalized_ip = str(ip_address_value(ip_address))
        payload = self.http.request(
            "POST",
            f"{self.base_url}/attributes/restSearch",
            headers={
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body={
                "returnFormat": "json",
                "type": ["ip-src", "ip-dst"],
                "value": normalized_ip,
                "limit": 100,
            },
        )
        response = payload.get("response")
        container = _mapping(response) if isinstance(response, dict) else payload
        raw_attributes = container.get("Attribute")
        if any(key in payload for key in ("error", "errors", "message")) or not isinstance(
            raw_attributes, list
        ):
            raise IntegrationError("misp", "MISP search response was invalid")
        attributes = raw_attributes
        matches = []
        for item in attributes[:100]:
            attribute = _mapping(item)
            if str(attribute.get("value", "")) != normalized_ip:
                continue
            matches.append(
                {
                    "attribute_id": str(attribute.get("id", "")),
                    "event_id": str(attribute.get("event_id", "")),
                    "type": str(attribute.get("type", "")),
                    "category": str(attribute.get("category", "")),
                    "to_ids": bool(attribute.get("to_ids", False)),
                    "timestamp": attribute.get("timestamp"),
                    "comment": str(attribute.get("comment", "")),
                }
            )
        return {
            "status": "OK",
            "attribute_count": len(matches),
            "event_count": len({item["event_id"] for item in matches if item["event_id"]}),
            "matches": matches,
        }

    def add_ip_attribute(self, event_id: str, ip_address: str, comment: str) -> dict[str, Any]:
        normalized_ip = str(ip_address_value(ip_address))
        payload = self.http.request(
            "POST",
            f"{self.base_url}/attributes/add/{urllib.parse.quote(event_id, safe='')}",
            headers={
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body={
                "type": "ip-src",
                "category": "Network activity",
                "value": normalized_ip,
                "to_ids": True,
                "distribution": 5,
                "comment": comment,
            },
        )
        attribute = _mapping(payload.get("Attribute")) or _mapping(payload.get("attribute"))
        if not attribute and payload.get("id"):
            attribute = payload
        attribute_id = str(attribute.get("id", ""))
        returned_event_id = str(attribute.get("event_id", event_id))
        returned_value = str(attribute.get("value", normalized_ip))
        if not attribute_id:
            raise IntegrationError("misp", "MISP response did not contain a created attribute")
        if returned_event_id != event_id or returned_value != normalized_ip:
            raise IntegrationError("misp", "MISP response attribute did not match the request")
        return {
            "attribute_id": attribute_id,
            "event_id": returned_event_id,
            "value": returned_value,
        }


def ip_address_value(value: str) -> Any:
    try:
        return ip_address(value)
    except ValueError as exc:
        raise IntegrationError("validation", "candidate IP address is invalid") from exc


def _mapping(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _integer(value: object) -> int:
    return int(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0
