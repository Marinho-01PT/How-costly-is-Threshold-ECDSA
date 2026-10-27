import secrets

import pytest

from twoparty import paillier
from twoparty.curve import N as SECP_N
from twoparty.ec import SECP256K1
from twoparty.paillier import add, decrypt, encrypt, key_from_primes, keygen, mul_const

# The worked example from our notes: p = 3, q = 5.
TINY = key_from_primes(3, 5)


def test_tiny_key():
    assert (TINY.N, TINY.lam, TINY.mu) == (15, 8, 2)


def test_tiny_example_by_hand():
    c = encrypt(15, 4, r=2)
    assert c == 173
    assert decrypt(TINY, c) == 4


def test_tiny_example_homomorphic():
    c4 = encrypt(15, 4, r=2)
    c3 = encrypt(15, 3, r=7)
    assert c3 == 28
    c = add(15, mul_const(15, c4, 2), c3)  # Enc(4)^2 * Enc(3)
    assert c == 112
    assert decrypt(TINY, c) == 2 * 4 + 3


@pytest.mark.parametrize("x", [2, 3, 5, 47, 53, 7919, 2**61 - 1, 2**127 - 1,
                               SECP256K1.p, SECP_N])
def test_primes(x):
    assert paillier.is_probable_prime(x)


# 561, 1105, 41041 are Carmichael numbers: they fool the simpler Fermat test.
@pytest.mark.parametrize("x", [-7, 0, 1, 4, 9, 49, 561, 1105, 41041,
                               (2**61 - 1) * (2**31 - 1), 2**127 + 1])
def test_composites(x):
    assert not paillier.is_probable_prime(x)


@pytest.mark.parametrize("bits", [3, 16, 30, 512])
def test_random_prime_has_exact_size(bits):
    p = paillier.random_prime(bits)
    assert p.bit_length() == bits and paillier.is_probable_prime(p)


@pytest.fixture(scope="module")
def key60():
    return keygen(60)


@pytest.fixture(scope="module")
def key2048(secp_key):
    return secp_key  # from conftest.py, generated once for all test files


def test_key_sizes(key60, key2048):
    assert key60.N.bit_length() == 60
    assert key2048.N.bit_length() == 2048
    assert key60.p != key60.q


# 2048-bit operations take ~0.2 s each in pure Python, so fewer rounds there.
@pytest.mark.parametrize("key, rounds", [("key60", 20), ("key2048", 2)])
def test_roundtrip(key, rounds, request):
    k = request.getfixturevalue(key)
    for m in [0, 1, k.N - 1] + [secrets.randbelow(k.N) for _ in range(rounds)]:
        assert decrypt(k, encrypt(k.N, m)) == m


def test_same_message_encrypts_differently(key60):
    assert encrypt(key60.N, 42) != encrypt(key60.N, 42)


@pytest.mark.parametrize("key, rounds", [("key60", 20), ("key2048", 1)])
def test_add_and_mul_const(key, rounds, request):
    k = request.getfixturevalue(key)
    for _ in range(rounds):
        a, b, x = (secrets.randbelow(k.N) for _ in range(3))
        ca, cb = encrypt(k.N, a), encrypt(k.N, b)
        assert decrypt(k, add(k.N, ca, cb)) == (a + b) % k.N
        assert decrypt(k, mul_const(k.N, ca, x)) == a * x % k.N


def test_rejects_bad_inputs(key60):
    N = key60.N
    for m in (-1, N):
        with pytest.raises(ValueError):
            encrypt(N, m)
    with pytest.raises(ValueError):
        encrypt(N, 1, r=key60.p)  # gcd(r, N) != 1
    with pytest.raises(ValueError):
        decrypt(key60, 0)
    with pytest.raises(ValueError):
        key_from_primes(7, 7)


def test_matches_phe(key60):
    """Same ciphertext as the independent python-paillier library, if installed."""
    phe = pytest.importorskip("phe")
    pub = phe.PaillierPublicKey(key60.N)
    priv = phe.PaillierPrivateKey(pub, key60.p, key60.q)
    m, r = 123456789, 987654321
    c = encrypt(key60.N, m, r=r)
    assert c == pub.raw_encrypt(m, r_value=r)
    assert priv.raw_decrypt(c) == m
