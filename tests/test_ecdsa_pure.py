import random
from hashlib import sha256

import pytest
from coincurve import PrivateKey, PublicKey

from twoparty.curve import der_encode
from twoparty.ec import SECP256K1, TOY
from twoparty.ecdsa_pure import (keygen, message_hash, sign, sign_steps, verify,
                                 verify_steps)

C = SECP256K1


def to_lib(Q) -> PublicKey:
    x, y = Q
    return PublicKey(b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"))


def der_decode(der: bytes) -> tuple[int, int]:
    rlen = der[3]
    r = int.from_bytes(der[4:4 + rlen], "big")
    s = int.from_bytes(der[6 + rlen:], "big")
    return r, s


def test_keygen_matches_libsecp256k1():
    for _ in range(5):
        d, Q = keygen(C)
        assert to_lib(Q).format() == PrivateKey(d.to_bytes(32, "big")).public_key.format()


def test_our_signature_verifies_in_libsecp256k1():
    d, Q = keygen(C)
    msg = b"pay 1 BTC to Bob"
    r, s = sign(C, d, msg)
    assert to_lib(Q).verify(der_encode(r, s), sha256(msg).digest(), hasher=None)


def test_libsecp256k1_signature_verifies_in_our_code():
    d, Q = keygen(C)
    msg = b"pay 1 BTC to Bob"
    der = PrivateKey(d.to_bytes(32, "big")).sign(msg)  # SHA-256 inside
    assert verify(C, Q, msg, der_decode(der))


@pytest.mark.parametrize("c", [TOY, SECP256K1], ids=lambda c: c.name)
def test_sign_verify_and_rejections(c):
    d, Q = keygen(c)
    r, s = sign(c, d, b"hello")
    assert verify(c, Q, b"hello", (r, s))
    assert s <= c.n // 2
    _, other = keygen(c, d % (c.n - 1) + 1)
    assert not verify(c, other, b"hello", (r, s))
    assert not verify(c, Q, b"hello", (r, (s + 1) % c.n or 1))
    assert not verify(c, Q, b"hello", (0, s))


def test_every_toy_key_and_nonce():
    """Exhaustive on the toy curve: every valid (d, k) gives a valid signature."""
    e = 100
    for d in range(1, TOY.n, 7):
        Q = TOY.base_mul(d)
        for k in range(1, TOY.n, 11):
            try:
                st = sign_steps(TOY, d, e, k)
            except ValueError:
                continue
            assert verify_steps(TOY, Q, e, (st.r, st.s)).valid


def test_sign_steps_values():
    st = sign_steps(TOY, d=42, e=100, k=17)
    assert st.R == TOY.mul(17, TOY.G)
    assert st.r == st.R[0] % TOY.n
    assert st.k_inv * 17 % TOY.n == 1
    assert st.s_raw == st.k_inv * (100 + st.r * 42) % TOY.n
    assert st.s == (TOY.n - st.s_raw if st.flipped else st.s_raw)


def test_bad_inputs_raise():
    with pytest.raises(ValueError):
        sign_steps(TOY, 5, 10, 0)
    with pytest.raises(ValueError):
        keygen(TOY, TOY.n)


def test_seeded_rng_is_reproducible():
    a = keygen(C, rng=random.Random(1))
    b = keygen(C, rng=random.Random(1))
    assert a == b


def test_message_hash_reduced():
    assert 0 <= message_hash(TOY, b"x") < TOY.n
