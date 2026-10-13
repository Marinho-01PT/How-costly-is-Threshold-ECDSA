"""secp256k1 helpers on top of libsecp256k1 (via coincurve).

Scalars are plain Python ints modulo N. Points are coincurve PublicKey objects.
"""
import secrets

from coincurve import PublicKey

# Order of the group (number of points on secp256k1).
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = N // 2


def rand_scalar() -> int:
    """Uniform random scalar in [1, N-1]."""
    return secrets.randbelow(N - 1) + 1


def inv(x: int) -> int:
    """Modular inverse mod N."""
    return pow(x, -1, N)


def _b32(x: int) -> bytes:
    return (x % N).to_bytes(32, "big")


def base_mult(k: int) -> PublicKey:
    """k * G."""
    return PublicKey.from_secret(_b32(k))


def point_mult(point: PublicKey, k: int) -> PublicKey:
    """k * P."""
    return point.multiply(_b32(k))


def point_add(*points: PublicKey) -> PublicKey:
    """P1 + P2 + ..."""
    return PublicKey.combine_keys(list(points))


def x_coord(point: PublicKey) -> int:
    """x coordinate of a point, as an int."""
    return int.from_bytes(point.format(compressed=False)[1:33], "big")


def der_encode(r: int, s: int) -> bytes:
    """Encode an ECDSA signature (r, s) as DER."""
    def enc(i: int) -> bytes:
        b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body
