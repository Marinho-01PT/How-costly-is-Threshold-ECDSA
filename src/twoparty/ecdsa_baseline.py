"""Plain single-device ECDSA, written out with the formulas from our slides.

    s = k^-1 * (e + r*d)    with    r = x(k*G)

This is the baseline for the benchmark and the reference that a jointly
produced signature must match: it has to verify like any other ECDSA signature.
"""
from hashlib import sha256

from coincurve import PublicKey

from .curve import HALF_N, N, base_mult, der_encode, inv, rand_scalar, x_coord


def message_hash(msg: bytes) -> int:
    """e: SHA-256 of the message, as an int mod N."""
    return int.from_bytes(sha256(msg).digest(), "big") % N


def keygen() -> tuple[int, PublicKey]:
    """Private key d and public key Q = d*G."""
    d = rand_scalar()
    return d, base_mult(d)


def sign(d: int, msg: bytes) -> tuple[int, int]:
    """Sign msg with private key d. Returns (r, s) with low s."""
    e = message_hash(msg)
    while True:
        k = rand_scalar()
        r = x_coord(base_mult(k)) % N
        if r == 0:
            continue
        s = inv(k) * (e + r * d) % N
        if s == 0:
            continue
        if s > HALF_N:  # low-s form, as Bitcoin and libsecp256k1 require
            s = N - s
        return r, s


def verify(q: PublicKey, msg: bytes, sig: tuple[int, int]) -> bool:
    """Check (r, s) with the libsecp256k1 verifier (independent of our code)."""
    r, s = sig
    return q.verify(der_encode(r, s), sha256(msg).digest(), hasher=None)
