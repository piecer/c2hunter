from __future__ import annotations

from c2hunter_analysis.pcap import (
    _application_domain,
    _dns_query_name,
    _safe_application_text,
)


def _dns_query(qname: bytes) -> bytes:
    return (
        b"\x12\x34"
        b"\x01\x00"
        b"\x00\x01"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        + qname
        + b"\x00\x01"
        + b"\x00\x01"
    )


def test_dns_query_name_accepts_normal_ascii_name() -> None:
    payload = _dns_query(b"\x06pektbo\x05libre\x00")
    assert _dns_query_name(payload) == "pektbo.libre"


def test_dns_query_name_rejects_nul_and_control_bytes() -> None:
    payload = _dns_query(
        b"\x06pektbo"
        b"\x06libre\x19"
        b"\x01\x00"
        b"\x00"
    )
    assert _dns_query_name(payload) is None


def test_safe_application_text_rejects_control_and_non_ascii_bytes() -> None:
    assert _safe_application_text(b"example.org") == "example.org"
    assert _safe_application_text(b"example\x00.org") is None
    assert _safe_application_text(b"example\x19.org") is None
    assert _safe_application_text(b"example\xff.org") is None


def test_http_host_with_nul_is_not_returned_as_domain() -> None:
    payload = b"GET / HTTP/1.1\r\nHost: example\x00.org\r\n\r\n"
    assert _application_domain("TCP", 12345, 80, payload) is None


def test_sni_marker_with_nul_is_not_returned_as_domain() -> None:
    assert _application_domain("TCP", 12345, 443, b"sni-example\x00.org") is None