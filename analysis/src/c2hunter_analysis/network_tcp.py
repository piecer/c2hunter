"""Bounded TCP serial-number coordinates shared by the two report APIs."""

from dataclasses import dataclass, field

_MODULUS = 2**32
_HALF_SPACE = _MODULUS // 2


def _extend(value: int, reference: int) -> int | None:
    distance = (value - reference) % _MODULUS
    if distance == _HALF_SPACE:
        return None  # Serial ordering is undefined at exactly half the space.
    return reference + (distance if distance < _HALF_SPACE else distance - _MODULUS)


@dataclass(slots=True)
class TCPSequenceSpace:
    """Keep an unambiguous (< half-space) observed range, without per-packet state.

    Rejected coordinates cannot retire outstanding data or establish duplicate
    ACK evidence. Exact payload repeats remain the caller's independent evidence.
    ACKs never move the send frontier and stale ACKs never move the ACK frontier.
    """

    lower: int | None = None
    upper: int | None = None
    highest_ack: int | None = None

    def observe(self, sequence: int, length: int) -> int | None:
        start = sequence if self.upper is None else _extend(sequence, self.upper)
        if start is None:
            return None
        lower = start if self.lower is None else min(self.lower, start)
        upper = start + length if self.upper is None else max(self.upper, start + length)
        if upper - lower >= _HALF_SPACE:
            return None
        self.lower, self.upper = lower, upper
        return start

    def acknowledge(self, acknowledgment: int) -> int | None:
        if self.upper is None:
            return None
        ack = _extend(acknowledgment, self.upper)
        if ack is None or ack > self.upper:
            return None
        if self.highest_ack is not None and ack < self.highest_ack:
            return None
        self.highest_ack = ack
        return ack


@dataclass(slots=True)
class TCPClosure:
    """A FIN closes one sender; retire only after both FINs are acknowledged."""

    ends: list[int | None] = field(default_factory=lambda: [None, None])
    acknowledged: list[bool] = field(default_factory=lambda: [False, False])

    def observe(
        self,
        direction: int,
        sequence: int,
        acknowledgment: int,
        length: int,
        *,
        fin: bool,
        ack: bool,
    ) -> bool:
        peer = 1 - direction
        if ack and self.ends[peer] == acknowledgment:
            self.acknowledged[peer] = True
        if fin and self.ends[direction] is None:
            # FIN consumes a sequence number after any accompanying payload.
            self.ends[direction] = (sequence + length + 1) % _MODULUS
        return all(self.acknowledged)
