"""ECDSA in pure Python on any curve from ec.py, with every intermediate value.

Same formulas as ecdsa_baseline.py (and our slides):

    sign:    R = k*G,  r = x(R) mod n,  s = k^-1 * (e + r*d) mod n,  low s
    verify:  w = s^-1,  u1 = e*w,  u2 = r*w,  P = u1*G + u2*Q,  valid iff x(P) mod n == r

The message hash is e = SHA-256(m) mod n. (FIPS 186 instead keeps the leftmost
bits of the hash; for secp256k1 both give the same e, for the toy curve not.)

sign_steps / verify_steps return all intermediate values, so the trace and
the protocol visualizer show exactly what this code computed. Educational code,
not constant-time.
"""
import random
import secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

from .ec import Curve, Point


def message_hash(curve: Curve, msg: bytes) -> int:
    """e = SHA-256(msg) mod n."""
    return int.from_bytes(sha256(msg).digest(), "big") % curve.n


def rand_scalar(curve: Curve, rng: Optional[random.Random] = None) -> int:
    """Uniform scalar in [1, n-1]. Pass rng only for reproducible demos."""
    if rng is None:
        return secrets.randbelow(curve.n - 1) + 1
    return rng.randrange(1, curve.n)


def keygen(curve: Curve, d: Optional[int] = None,
           rng: Optional[random.Random] = None) -> tuple[int, Point]:
    """Private key d (random unless given) and public key Q = d*G."""
    if d is None:
        d = rand_scalar(curve, rng)
    if not 1 <= d < curve.n:
        raise ValueError("d must be in [1, n-1]")
    return d, curve.base_mul(d)


@dataclass(frozen=True)
class SignSteps:
    e: int
    k: int
    R: tuple[int, int]
    r: int
    k_inv: int
    s_raw: int       # k^-1 * (e + r*d) mod n, before the low-s rule
    s: int           # final s, s <= n/2
    flipped: bool    # True if s_raw was replaced by n - s_raw


def sign_steps(curve: Curve, d: int, e: int, k: int) -> SignSteps:
    """Sign hash e with key d and nonce k. Raises ValueError if this k fails."""
    n = curve.n
    if not 1 <= k < n:
        raise ValueError("k must be in [1, n-1]")
    R = curve.base_mul(k)
    r = R[0] % n
    if r == 0:
        raise ValueError("r = 0 for this k, pick another k")
    k_inv = pow(k, -1, n)
    s_raw = k_inv * (e + r * d) % n
    if s_raw == 0:
        raise ValueError("s = 0 for this k, pick another k")
    flipped = s_raw > n // 2
    return SignSteps(e, k, R, r, k_inv, s_raw, n - s_raw if flipped else s_raw, flipped)


def sign(curve: Curve, d: int, msg: bytes, k: Optional[int] = None,
         rng: Optional[random.Random] = None) -> tuple[int, int]:
    """Sign msg. Picks a fresh random k unless one is given. Returns (r, s)."""
    e = message_hash(curve, msg)
    while True:
        try:
            st = sign_steps(curve, d, e, k if k is not None else rand_scalar(curve, rng))
            return st.r, st.s
        except ValueError:
            if k is not None:
                raise


@dataclass(frozen=True)
class VerifySteps:
    e: int
    w: int
    u1: int
    u2: int
    P: Point
    valid: bool


def verify_steps(curve: Curve, Q: Point, e: int, sig: tuple[int, int]) -> VerifySteps:
    n = curve.n
    r, s = sig
    if not (1 <= r < n and 1 <= s < n):
        return VerifySteps(e, 0, 0, 0, None, False)
    w = pow(s, -1, n)
    u1 = e * w % n
    u2 = r * w % n
    P = curve.add(curve.base_mul(u1), curve.mul(u2, Q))
    return VerifySteps(e, w, u1, u2, P, P is not None and P[0] % n == r)


def verify(curve: Curve, Q: Point, msg: bytes, sig: tuple[int, int]) -> bool:
    return verify_steps(curve, Q, message_hash(curve, msg), sig).valid
