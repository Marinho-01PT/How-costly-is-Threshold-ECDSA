"""Additive secret sharing mod n (secp256k1's N unless another n is given).

With two devices both always take part, so d = d1 + d2 is enough.
(Shamir only pays off if fewer than all parties should be able to sign.)
"""
import secrets

from .curve import N


def share(secret: int, n: int = N, d1: int | None = None) -> tuple[int, int]:
    """Split a secret into two random-looking parts that add up to it.

    d1 is drawn uniformly from [1, n-1] unless given (for demos and traces).
    """
    if d1 is None:
        d1 = secrets.randbelow(n - 1) + 1
    d2 = (secret - d1) % n
    return d1, d2


def combine(*shares: int, n: int = N) -> int:
    """Add the parts back together."""
    return sum(shares) % n
