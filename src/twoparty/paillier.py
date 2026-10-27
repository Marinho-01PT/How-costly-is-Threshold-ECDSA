"""Paillier encryption: compute on encrypted numbers (the tool behind MtA).

    key:      N = p*q,  lam = (p-1)*(q-1),  mu = lam^-1 mod N
    encrypt:  Enc(m) = (1 + m*N) * r^N  mod N^2     r random, gcd(r, N) = 1
    decrypt:  Dec(c) = L(c^lam mod N^2) * mu  mod N   with L(x) = (x - 1) / N

Two rules make it useful:

    add(Enc(a), Enc(b))  = Enc(a) * Enc(b) = Enc(a + b)   (mod N)
    mul_const(Enc(a), k) = Enc(a)^k        = Enc(a * k)   (mod N)

So whoever has only N can compute with Alice's encrypted values, but only
Alice (who knows lam) can decrypt. Educational code, not constant-time.
"""
import math
import secrets
from dataclasses import dataclass

# Trial division by these first makes most candidates fail fast.
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


def is_probable_prime(x: int, rounds: int = 40) -> bool:
    """Miller-Rabin. A composite x passes with probability below 4^-rounds."""
    if x < 2:
        return False
    for sp in _SMALL_PRIMES:
        if x % sp == 0:
            return x == sp
    # Write x - 1 = 2^s * t with t odd.
    t, s = x - 1, 0
    while t % 2 == 0:
        t //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(x - 3) + 2  # witness in [2, x-2]
        y = pow(a, t, x)
        if y in (1, x - 1):
            continue
        for _ in range(s - 1):
            y = y * y % x
            if y == x - 1:
                break
        else:
            return False  # a proves that x is composite
    return True


def random_prime(bits: int) -> int:
    """Random prime with exactly `bits` bits.

    The top two bits are set, so the product of two such primes has exactly
    2*bits bits.
    """
    if bits < 3:
        raise ValueError("bits must be at least 3")
    while True:
        x = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
        if is_probable_prime(x):
            return x


@dataclass(frozen=True)
class Key:
    """Alice's key. Only N is public, Bob never sees the rest."""
    N: int
    p: int
    q: int
    lam: int
    mu: int


def key_from_primes(p: int, q: int) -> Key:
    """Build the key from two primes (keygen picks them, tests pass small ones)."""
    if p == q:
        raise ValueError("p and q must differ")
    N = p * q
    lam = (p - 1) * (q - 1)
    if math.gcd(N, lam) != 1:
        raise ValueError("gcd(N, lam) must be 1")
    return Key(N, p, q, lam, pow(lam, -1, N))


def keygen(bits: int = 2048) -> Key:
    """Fresh key with an N of exactly `bits` bits."""
    while True:
        p = random_prime(bits // 2)
        q = random_prime(bits - bits // 2)
        if p != q:
            return key_from_primes(p, q)


def encrypt(N: int, m: int, r: int | None = None) -> int:
    """Enc(m) for 0 <= m < N. r is random unless given (for demos and tests)."""
    if not 0 <= m < N:
        raise ValueError("m must be in [0, N-1]")
    if r is None:
        while True:
            r = secrets.randbelow(N - 1) + 1
            if math.gcd(r, N) == 1:
                break
    elif not (0 < r < N and math.gcd(r, N) == 1):
        raise ValueError("r must be in [1, N-1] with gcd(r, N) = 1")
    N2 = N * N
    # (1 + N)^m = 1 + m*N mod N^2, so the generator needs no exponentiation.
    return (1 + m * N) * pow(r, N, N2) % N2


def decrypt(key: Key, c: int) -> int:
    """Dec(c), a number in [0, N-1]."""
    N = key.N
    N2 = N * N
    if not 0 < c < N2:
        raise ValueError("c must be in [1, N^2 - 1]")
    x = pow(c, key.lam, N2)
    return (x - 1) // N * key.mu % N


def add(N: int, c1: int, c2: int) -> int:
    """Enc(a), Enc(b) -> Enc(a + b)."""
    return c1 * c2 % (N * N)


def mul_const(N: int, c: int, k: int) -> int:
    """Enc(a), k -> Enc(a * k). k is a plain number, not encrypted."""
    return pow(c, k, N * N)
