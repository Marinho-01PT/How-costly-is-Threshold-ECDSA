"""secp256k1 point arithmetic from libsecp256k1, with the interface of ec.Curve.

The protocol only calls base_mul, mul and add, and reads n. This adapter
gives it the same (x, y) tuples as the pure-Python curve, so both variants of
the building block "curve arithmetic in the protocol" run the same protocol
code. The conversion to and from coincurve objects is part of the measured
cost, as it would be in any program that keeps points as numbers.
"""
from coincurve import PublicKey

from .ec import SECP256K1, Point


def _pk(P: Point) -> PublicKey:
    return PublicKey.from_point(*P)


def _xy(pk: PublicKey) -> Point:
    return pk.point()


def _b32(k: int) -> bytes:
    return (k % SECP256K1.n).to_bytes(32, "big")


class LibsecpCurve:
    name = "secp256k1"
    p, a, b, G, n = SECP256K1.p, SECP256K1.a, SECP256K1.b, SECP256K1.G, SECP256K1.n

    def base_mul(self, k: int) -> Point:
        k %= self.n
        return None if k == 0 else _xy(PublicKey.from_secret(_b32(k)))

    def mul(self, k: int, P: Point) -> Point:
        k %= self.n
        if k == 0 or P is None:
            return None
        return _xy(_pk(P).multiply(_b32(k)))

    def add(self, P: Point, Q: Point) -> Point:
        if P is None:
            return Q
        if Q is None:
            return P
        try:
            return _xy(PublicKey.combine_keys([_pk(P), _pk(Q)]))
        except ValueError:  # P + (-P): the point at infinity
            return None

    def on_curve(self, P: Point) -> bool:
        return SECP256K1.on_curve(P)


LIBSECP = LibsecpCurve()


def resolve(curve, variant: str):
    """The curve object the protocol should use for this variant."""
    if variant == "libsecp256k1":
        if curve.name != "secp256k1":
            raise ValueError("curve=libsecp256k1 only works on secp256k1")
        return LIBSECP
    return curve
