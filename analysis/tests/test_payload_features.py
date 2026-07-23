from c2hunter_analysis.payload_features import (
    extract_payload_features,
    simhash_hamming_distance,
)


def test_payload_features_match_cross_language_contract() -> None:
    features = extract_payload_features(b"beacon")

    assert features is not None
    assert features.as_dict() == {
        "payload_hash": "8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887",
        "payload_prefix_hash": ("8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887"),
        "payload_length": 6,
        "payload_entropy": 2.585,
        "payload_printable_ratio": 1.0,
        "payload_simhash": "e627bf19152d67b3",
        "payload_feature_version": "1",
    }


def test_payload_features_handle_empty_short_and_binary_values() -> None:
    assert extract_payload_features(b"") is None
    short = extract_payload_features(b"xy")
    binary = extract_payload_features(bytes(range(16)))

    assert short is not None and short.payload_simhash == "08f14f07b58deb1a"
    assert binary is not None
    assert binary.payload_entropy == 4.0
    assert binary.payload_printable_ratio == 0.1875
    assert simhash_hamming_distance(binary.payload_simhash, binary.payload_simhash) == 0


def test_simhash_distance_rejects_invalid_values() -> None:
    try:
        simhash_hamming_distance("not-hex", "also-not-hex")
    except ValueError as exc:
        assert "16 hex" in str(exc)
    else:
        raise AssertionError("invalid SimHash was accepted")
