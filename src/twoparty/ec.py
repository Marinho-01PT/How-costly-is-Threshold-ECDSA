"""Elliptic curves in pure Python, with the curve as a parameter.

Curves have the short Weierstrass form  y^2 = x^3 + a*x + b  over the field
of integers mod p. Points are affine (x, y) tuples; the point at infinity
(the neutral element) is None.

Educational code: plain double-and-add, not constant-time. The benchmark
keeps using libsecp256k1 (see curve.py).
"""
from dataclasses import dataclass
from typing import Optional

Point = Optional[tuple[int, int]]
INFINITY: Point = None


@dataclass(frozen=True)
class Curve:
    name: str
    p: int          # field prime
    a: int
    b: int
    G: tuple[int, int]  # generator
    n: int          # order of G (prime)

    def on_curve(self, P: Point) -> bool:
        if P is None:
            return True
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def neg(self, P: Point) -> Point:
        if P is None:
            return None
        x, y = P
        return (x, (-y) % self.p)

    def add(self, P: Point, Q: Point) -> Point:
        """P + Q with the chord-and-tangent rule."""
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None  # P + (-P), also covers doubling a point with y = 0
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    def mul(self, k: int, P: Point) -> Point:
        """k * P by double-and-add (left to right)."""
        k %= self.n
        R: Point = None
        for bit in bin(k)[2:] if k else "":
            R = self.add(R, R)
            if bit == "1":
                R = self.add(R, P)
        return R

    def base_mul(self, k: int) -> Point:
        """k * G."""
        return self.mul(k, self.G)


SECP256K1 = Curve(
    name="secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)

# Same equation as secp256k1 (y^2 = x^3 + 7) over a field small enough to
# check by hand. Found with scripts/find_toy_curve.py: the group has 313
# points, a prime, so every point except infinity generates the whole group.
# G is the point with the smallest x.
TOY = Curve(name="toy", p=349, a=0, b=7, G=(2, 109), n=313)

CURVES = {c.name: c for c in (TOY, SECP256K1)}
