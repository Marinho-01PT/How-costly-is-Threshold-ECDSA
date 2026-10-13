from coincurve import PrivateKey

from twoparty.curve import N, base_mult, der_encode
from twoparty.ecdsa_baseline import keygen, sign, verify


def test_sign_then_verify():
    d, q = keygen()
    sig = sign(d, b"pay 1 BTC to Bob")
    assert verify(q, b"pay 1 BTC to Bob", sig)


def test_wrong_message_fails():
    d, q = keygen()
    sig = sign(d, b"pay 1 BTC to Bob")
    assert not verify(q, b"pay 2 BTC to Bob", sig)


def test_wrong_key_fails():
    d, _ = keygen()
    _, other = keygen()
    assert not verify(other, b"hello", sign(d, b"hello"))


def test_tampered_signature_fails():
    d, q = keygen()
    r, s = sign(d, b"hello")
    assert not verify(q, b"hello", (r, (s + 1) % N))


def test_public_key_matches_library():
    d, q = keygen()
    lib = PrivateKey(d.to_bytes(32, "big")).public_key
    assert q.format() == lib.format()


def test_library_accepts_our_signature_format():
    d, q = keygen()
    r, s = sign(d, b"x")
    # DER must be well formed: 0x30 <len> 0x02 ...
    der = der_encode(r, s)
    assert der[0] == 0x30 and der[2] == 0x02
    assert base_mult(d).format() == q.format()


def test_low_s():
    d, _ = keygen()
    for i in range(50):
        _, s = sign(d, f"m{i}".encode())
        assert s <= N // 2
