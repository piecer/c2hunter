"""External TI and MISP client contract tests."""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from typing import Any

import pytest

from c2hunter_controller.integrations import (
    IntegrationError,
    JsonHttpClient,
    MispClient,
    ThreatIntelService,
)


class StubHttpClient(JsonHttpClient):
    def __init__(
        self,
        *,
        fail_virustotal: bool = False,
        rate_limit_virustotal: bool = False,
        invalid_misp: bool = False,
    ) -> None:
        self.fail_virustotal = fail_virustotal
        self.rate_limit_virustotal = rate_limit_virustotal
        self.invalid_misp = invalid_misp
        self.requests: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.requests.append({"method": method, "url": url, "headers": headers, "body": body})
        if "virustotal" in url:
            if self.rate_limit_virustotal:
                raise IntegrationError(
                    "virustotal",
                    "external service returned HTTP 429",
                    http_status=429,
                    retry_after="60",
                )
            if self.fail_virustotal:
                raise IntegrationError("virustotal", "provider unavailable")
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 8,
                            "suspicious": 2,
                            "harmless": 20,
                            "undetected": 10,
                        },
                        "reputation": -12,
                        "country": "KR",
                        "as_owner": "Example Network",
                        "last_analysis_date": 1_700_000_000,
                    }
                }
            }
        if "abuseipdb" in url:
            return {
                "data": {
                    "abuseConfidenceScore": 75,
                    "totalReports": 12,
                    "lastReportedAt": "2026-08-01T00:00:00+00:00",
                    "countryCode": "KR",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example ISP",
                    "domain": "example.test",
                    "isTor": False,
                    "isWhitelisted": False,
                }
            }
        if url.endswith("/attributes/restSearch"):
            if self.invalid_misp:
                return {"message": "validation failed"}
            return {
                "response": {
                    "Attribute": [
                        {
                            "id": "77",
                            "event_id": "42",
                            "type": "ip-src",
                            "value": "203.0.113.44",
                            "category": "Network activity",
                            "to_ids": True,
                            "timestamp": "1700000000",
                            "comment": "known C2",
                        }
                    ]
                }
            }
        if self.invalid_misp:
            return {"message": "validation failed"}
        return {"Attribute": {"id": "9001", "event_id": "42", "value": "203.0.113.44"}}


@pytest.mark.parametrize(
    ("reason", "expected_message"),
    [
        (
            ssl.SSLCertVerificationError(1, "certificate verify failed"),
            "external service TLS certificate verification failed",
        ),
        (
            socket.gaierror(-2, "name or service not known"),
            "external service DNS resolution failed",
        ),
        (ConnectionRefusedError(), "external service connection refused"),
        (TimeoutError(), "external service request timed out"),
        (OSError(), "external service request failed"),
    ],
)
def test_json_http_client_sanitizes_transport_failure_messages(
    monkeypatch: pytest.MonkeyPatch,
    reason: OSError,
    expected_message: str,
) -> None:
    def fail_request(*args: object, **kwargs: object) -> None:
        raise urllib.error.URLError(reason)

    monkeypatch.setattr(urllib.request, "urlopen", fail_request)

    with pytest.raises(IntegrationError, match=f"^{expected_message}$"):
        JsonHttpClient().request("GET", "https://example.test/data")


def test_threat_intel_service_normalizes_both_providers_without_exposing_keys() -> None:
    http = StubHttpClient()
    service = ThreatIntelService(
        virustotal_api_key="vt-secret",
        abuseipdb_api_key="abuse-secret",
        http_client=http,
    )

    result = service.lookup_ip("203.0.113.44")

    assert result["summary"] == {
        "malicious": 8,
        "suspicious": 2,
        "harmless": 20,
        "abuse_confidence_score": 75,
        "country_code": "KR",
        "network_owner": "Example ISP",
    }
    assert result["providers"]["virustotal"]["status"] == "OK"
    assert result["providers"]["abuseipdb"]["status"] == "OK"
    assert "vt-secret" not in str(result)
    assert "abuse-secret" not in str(result)


def test_threat_intel_service_keeps_partial_results_when_one_provider_fails() -> None:
    service = ThreatIntelService(
        virustotal_api_key="vt-secret",
        abuseipdb_api_key="abuse-secret",
        http_client=StubHttpClient(fail_virustotal=True),
    )

    result = service.lookup_ip("203.0.113.44")

    assert result["providers"]["virustotal"]["status"] == "ERROR"
    assert result["providers"]["abuseipdb"]["status"] == "OK"
    assert result["summary"]["abuse_confidence_score"] == 75


def test_threat_intel_rate_limit_preserves_retry_metadata() -> None:
    service = ThreatIntelService(
        virustotal_api_key="vt-secret",
        http_client=StubHttpClient(rate_limit_virustotal=True),
    )

    result = service.lookup_ip("203.0.113.44")

    assert result["providers"]["virustotal"] == {
        "status": "RATE_LIMITED",
        "error": "external service returned HTTP 429",
        "provider": "virustotal",
        "retry_after": "60",
    }


def test_misp_client_posts_ip_src_attribute_to_selected_event() -> None:
    http = StubHttpClient()
    client = MispClient("https://misp.example/api", "misp-secret", http_client=http)

    result = client.add_ip_attribute("42", "203.0.113.44", "confirmed by analyst")

    request = http.requests[0]
    assert request["method"] == "POST"
    assert request["url"] == "https://misp.example/api/attributes/add/42"
    assert request["body"] == {
        "type": "ip-src",
        "category": "Network activity",
        "value": "203.0.113.44",
        "to_ids": True,
        "distribution": 5,
        "comment": "confirmed by analyst",
    }
    assert result == {"attribute_id": "9001", "event_id": "42", "value": "203.0.113.44"}


def test_misp_client_searches_existing_ip_attributes_without_exposing_key() -> None:
    http = StubHttpClient()
    client = MispClient("https://misp.example/api", "misp-secret", http_client=http)

    result = client.lookup_ip("203.0.113.44")

    request = http.requests[0]
    assert request["method"] == "POST"
    assert request["url"] == "https://misp.example/api/attributes/restSearch"
    assert request["body"] == {
        "returnFormat": "json",
        "type": ["ip-src", "ip-dst"],
        "value": "203.0.113.44",
        "limit": 100,
    }
    assert result["status"] == "OK"
    assert result["attribute_count"] == 1
    assert result["event_count"] == 1
    assert result["matches"][0]["event_id"] == "42"
    assert "misp-secret" not in str(result)


def test_misp_client_rejects_http_200_error_payload_for_lookup() -> None:
    http = StubHttpClient(invalid_misp=True)
    client = MispClient("https://misp.example", "misp-secret", http_client=http)

    with pytest.raises(IntegrationError, match="MISP search response was invalid"):
        client.lookup_ip("203.0.113.44")


def test_misp_client_rejects_non_http_base_url() -> None:
    with pytest.raises(ValueError, match="HTTP or HTTPS"):
        MispClient("file:///tmp/misp", "misp-secret", http_client=StubHttpClient())


def test_misp_client_rejects_success_response_without_created_attribute() -> None:
    http = StubHttpClient(invalid_misp=True)
    client = MispClient("https://misp.example", "misp-secret", http_client=http)

    with pytest.raises(IntegrationError, match="created attribute"):
        client.add_ip_attribute("42", "203.0.113.44", "confirmed")
