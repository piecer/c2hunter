from c2hunter_controller.security import trusted_client_ip


def test_direct_client_cannot_spoof_forwarded_for() -> None:
    assert trusted_client_ip("198.51.100.9", "203.0.113.7", ()) == "198.51.100.9"


def test_trusted_proxy_uses_forwarded_client_chain() -> None:
    assert (
        trusted_client_ip(
            "172.20.0.5",
            "203.0.113.7, 10.0.0.4",
            ("172.20.0.0/16", "10.0.0.0/8"),
        )
        == "203.0.113.7"
    )


def test_invalid_forwarded_chain_falls_back_to_peer() -> None:
    assert (
        trusted_client_ip("172.20.0.5", "invalid, 203.0.113.7", ("172.20.0.0/16",)) == "172.20.0.5"
    )
