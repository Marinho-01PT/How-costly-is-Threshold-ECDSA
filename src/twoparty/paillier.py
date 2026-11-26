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


# --- Variants of the Paillier building blocks ---------------------------------
#
# The functions above are the "naive" variant and stay as they are (the demo,
# the trace and the visualizer show exactly them). Ops bundles one party's
# choice of variants, so MtA does not need to know which one is in use:
#
#   bignum  "int"   Python's own big integers
#           "gmpy2" the GMP library, same numbers, faster pow
#   dec     "naive" Dec(c) = L(c^lam mod N^2) * mu mod N
#           "crt"   decrypt mod p^2 and mod q^2 with exponents p-1 and q-1,
#                   then combine (Chinese remainder theorem). Alice only.
#   enc     "naive" Enc(m) = (1 + m*N) * r^N mod N^2
#           "crt"   r^N computed mod p^2 and mod q^2, then combined. Alice only,
#                   Bob does not know p and q and falls back to naive.
#           "precomputed" r^N mod N^2 does not depend on m, so it is computed
#                   beforehand (offline). Online only one multiplication is left.

def _powmod_int(b: int, e: int, m: int) -> int:
    return pow(b, e, m)


def _powmod_gmp(b: int, e: int, m: int) -> int:
    import gmpy2
    return int(gmpy2.powmod(b, e, m))


@dataclass(frozen=True)
class _Crt:
    p2: int
    q2: int
    p2_inv: int       # (p^2)^-1 mod q^2, to combine r^N
    ep: int           # N mod p(p-1), exponent for r^N mod p^2
    eq: int
    hp: int           # L_p((N+1)^(p-1) mod p^2)^-1 mod p
    hq: int
    p_inv: int        # p^-1 mod q, to combine the plaintext


def _crt_params(key: Key) -> _Crt:
    p, q, N = key.p, key.q, key.N
    p2, q2 = p * p, q * q
    hp = pow((pow(N + 1, p - 1, p2) - 1) // p, -1, p)
    hq = pow((pow(N + 1, q - 1, q2) - 1) // q, -1, q)
    return _Crt(p2, q2, pow(p2, -1, q2), N % (p * (p - 1)), N % (q * (q - 1)),
                hp, hq, pow(p, -1, q))


class Ops:
    """One party's Paillier operations. key for Alice, only N for Bob."""

    def __init__(self, N: int, key: Key | None = None, bignum: str = "int",
                 dec: str = "naive", enc: str = "naive"):
        self.N, self.N2, self.key = N, N * N, key
        self.powmod = _powmod_gmp if bignum == "gmpy2" else _powmod_int
        self.dec, self.enc = dec, enc
        if (dec == "crt" or enc == "crt") and key is not None:
            self.crt = _crt_params(key)
        self.pool: list[int] = []
        self.pool_misses = 0   # encryptions that found the pool empty

    @property
    def enc_used(self) -> str:
        """The variant that really runs: Bob cannot use crt."""
        return "naive" if self.enc == "crt" and self.key is None else self.enc

    def _random_r(self) -> int:
        N = self.N
        while True:
            r = secrets.randbelow(N - 1) + 1
            if math.gcd(r, N) == 1:
                return r

    def _r_to_N(self) -> int:
        r = self._random_r()
        if self.enc_used == "crt":
            c = self.crt
            xp = self.powmod(r, c.ep, c.p2)
            xq = self.powmod(r, c.eq, c.q2)
            return xp + c.p2 * ((xq - xp) * c.p2_inv % c.q2)
        return self.powmod(r, self.N, self.N2)

    def precompute(self, count: int) -> None:
        """Offline phase: fill the pool with count values of r^N mod N^2."""
        self.pool.extend(self.powmod(self._random_r(), self.N, self.N2) for _ in range(count))

    def encrypt(self, m: int) -> int:
        if not 0 <= m < self.N:
            raise ValueError("m must be in [0, N-1]")
        if self.enc_used == "precomputed":
            if self.pool:
                rn = self.pool.pop()
            else:
                self.pool_misses += 1
                rn = self.powmod(self._random_r(), self.N, self.N2)
        else:
            rn = self._r_to_N()
        return (1 + m * self.N) * rn % self.N2

    def decrypt(self, c: int) -> int:
        key = self.key
        if key is None:
            raise ValueError("only Alice can decrypt")
        if not 0 < c < self.N2:
            raise ValueError("c must be in [1, N^2 - 1]")
        if self.dec == "crt":
            k, p, q = self.crt, key.p, key.q
            mp = (self.powmod(c, p - 1, k.p2) - 1) // p * k.hp % p
            mq = (self.powmod(c, q - 1, k.q2) - 1) // q * k.hq % q
            return mp + p * ((mq - mp) * k.p_inv % q)
        x = self.powmod(c, key.lam, self.N2)
        return (x - 1) // self.N * key.mu % self.N

    def add(self, c1: int, c2: int) -> int:
        return c1 * c2 % self.N2

    def mul_const(self, c: int, k: int) -> int:
        return self.powmod(c, k, self.N2)


def ops_for(cfg, N: int, key: Key | None = None) -> Ops:
    """Ops for one party from a Config (see config.py)."""
    return Ops(N, key, cfg.bignum, cfg.paillier_dec, cfg.paillier_enc)
