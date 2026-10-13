import importlib.util
from pathlib import Path

import pytest
from coincurve import PublicKey

from twoparty.ec import SECP256K1, TOY

ROOT = Path(__file__).resolve().parents[1]


def test_generators_on_curve():
    assert TOY.on_curve(TOY.G)
    assert SECP256K1.on_curve(SECP256K1.G)


@pytest.mark.parametrize("c", [TOY, SECP256K1], ids=lambda c: c.name)
def test_order_of_generator(c):
    assert c.mul(c.n, c.G) is None
    assert c.mul(c.n - 1, c.G) == c.neg(c.G)


def test_toy_group_has_prime_order():
    spec = importlib.util.spec_from_file_location("ftc", ROOT / "scripts" / "find_toy_curve.py")
    ftc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ftc)
    assert ftc.count_points(TOY.p) == TOY.n
    assert ftc.is_prime(TOY.n) and TOY.n > 200 and TOY.n != TOY.p
    assert ftc.smallest_point(TOY.p) == TOY.G


def test_toy_every_multiple_is_on_curve_and_distinct():
    pts = [TOY.base_mul(k) for k in range(1, TOY.n)]
    assert all(TOY.on_curve(P) for P in pts)
    assert len(set(pts)) == TOY.n - 1


def test_add_rules():
    G = TOY.G
    assert TOY.add(G, None) == G
    assert TOY.add(None, G) == G
    assert TOY.add(G, TOY.neg(G)) is None
    assert TOY.add(G, G) == TOY.mul(2, G)
    assert TOY.add(TOY.mul(5, G), TOY.mul(7, G)) == TOY.mul(12, G)
    assert TOY.mul(0, G) is None


@pytest.mark.parametrize("k", [1, 2, 3, 0xDEADBEEF, SECP256K1.n - 1, 2**255 + 99])
def test_secp256k1_matches_libsecp256k1(k):
    x, y = SECP256K1.base_mul(k)
    lib = PublicKey.from_secret((k % SECP256K1.n).to_bytes(32, "big")).format(compressed=False)
    assert lib == b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
