from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import asdict, dataclass

_FNV_OFFSET = 14695981039346656037
_FNV_PRIME = 1099511628211
_MASK_64 = (1 << 64) - 1
_PREFIX_BYTES = 32
_SHINGLE_BYTES = 3
_PRINTABLE_CONTROL_BYTES = {9, 10, 13}


@dataclass(frozen=True)
class PayloadFeatures:
    payload_hash: str
    payload_prefix_hash: str
    payload_length: int
    payload_entropy: float
    payload_printable_ratio: float
    payload_simhash: str
    payload_feature_version: str = "1"

    def as_dict(self) -> dict[str, str | int | float]:
        return asdict(self)


def extract_payload_features(payload: bytes) -> PayloadFeatures | None:
    """Return deterministic, non-reversible features for one non-empty L4 payload."""
    if not payload:
        return None
    counts = Counter(payload)
    length = len(payload)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    printable = sum(
        1 for value in payload if 0x20 <= value <= 0x7E or value in _PRINTABLE_CONTROL_BYTES
    )
    prefix = payload[:_PREFIX_BYTES]
    return PayloadFeatures(
        payload_hash=hashlib.sha256(payload).hexdigest(),
        payload_prefix_hash=hashlib.sha256(prefix).hexdigest(),
        payload_length=length,
        payload_entropy=round(entropy, 4),
        payload_printable_ratio=round(printable / length, 4),
        payload_simhash=_simhash(payload),
    )


def simhash_hamming_distance(left: str, right: str) -> int:
    if len(left) != 16 or len(right) != 16:
        raise ValueError("payload SimHash values must contain exactly 16 hex characters")
    try:
        return (int(left, 16) ^ int(right, 16)).bit_count()
    except ValueError as exc:
        raise ValueError("payload SimHash values must be hexadecimal") from exc


def _simhash(payload: bytes) -> str:
    shingles = (
        [payload]
        if len(payload) < _SHINGLE_BYTES
        else [
            payload[index : index + _SHINGLE_BYTES]
            for index in range(len(payload) - _SHINGLE_BYTES + 1)
        ]
    )
    votes = [0] * 64
    for shingle in shingles:
        hashed = _fnv1a64(shingle)
        for bit in range(64):
            votes[bit] += 1 if hashed & (1 << bit) else -1
    result = 0
    for bit, vote in enumerate(votes):
        if vote >= 0:
            result |= 1 << bit
    return f"{result:016x}"


def _fnv1a64(value: bytes) -> int:
    result = _FNV_OFFSET
    for byte in value:
        result ^= byte
        result = (result * _FNV_PRIME) & _MASK_64
    return result
