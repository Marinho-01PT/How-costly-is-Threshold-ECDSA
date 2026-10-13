"""Additive secret sharing mod N.

With two devices both always take part, so d = d1 + d2 is enough.
(Shamir only pays off if fewer than all parties should be able to sign.)
"""
from .curve import N, rand_scalar


def share(secret: int) -> tuple[int, int]:
    """Split a secret into two random-looking parts that add up to it."""
    d1 = rand_scalar()
    d2 = (secret - d1) % N
    return d1, d2


def combine(*shares: int) -> int:
    """Add the parts back together."""
    return sum(shares) % N
