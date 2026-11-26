"""The building-block variants (config.py): every one still gives a valid
ECDSA signature, and the pieces behind them compute the right numbers."""
import csv
import secrets

import pytest

from twoparty import __main__ as cli
from twoparty import config, ec_libsecp, ecdsa_baseline, mta, net, paillier, protocol
from twoparty.config import Config
from twoparty.curve import base_mult
from twoparty.ec import SECP256K1, TOY

gmpy2 = pytest.importorskip("gmpy2")


@pytest.fixture(scope="module")
def small_key():
    return paillier.keygen(512)


@pytest.mark.parametrize("bignum", ["int", "gmpy2"])
@pytest.mark.parametrize("dec", ["naive", "crt"])
@pytest.mark.parametrize("enc", ["naive", "crt", "precomputed"])
def test_paillier_ops(small_key, bignum, dec, enc):
    key = small_key
    alice = paillier.Ops(key.N, key, bignum, dec, enc)
    bob = paillier.Ops(key.N, None, bignum, dec, enc)
    alice.precompute(2)
    bob.precompute(2)
    for m in (0, 1, 123456789, key.N - 1):
        assert alice.decrypt(alice.encrypt(m)) == m
        assert paillier.decrypt(key, alice.encrypt(m)) == m   # same ciphertexts as naive
        assert alice.decrypt(bob.encrypt(m)) == m
    c = bob.add(bob.mul_const(alice.encrypt(7), 6), bob.encrypt(5))
    assert alice.decrypt(c) == 47
    assert bob.enc_used == ("naive" if enc == "crt" else enc)  # Bob has no p, q


def test_precomputed_pool_falls_back(small_key):
    ops = paillier.Ops(small_key.N, small_key, enc="precomputed")
    ops.precompute(1)
    ops.encrypt(5)
    assert ops.decrypt(ops.encrypt(6)) == 6
    assert ops.pool_misses == 1


@pytest.mark.parametrize("msg", [
    {"c_A": 2**3000 - 17, "Q": [5, 7], "neg": -3, "zero": 0, "s": "tx-1", "b": True,
     "none": None, "empty": [], "ms": 1.25, "nested": {"x": [1, [2]]}},
    {},
])
def test_binary_roundtrip(msg):
    assert net.decode(net.encode(msg)) == msg


def test_binary_is_smaller():
    msg = {"c_B": secrets.randbits(4096)}
    import json
    assert len(net.encode(msg)) < 0.5 * len(json.dumps(msg))


def test_libsecp_curve_matches_pure():
    for k in (1, 2, secrets.randbelow(SECP256K1.n)):
        P = SECP256K1.base_mul(k)
        assert ec_libsecp.LIBSECP.base_mul(k) == P
        assert ec_libsecp.LIBSECP.mul(3, P) == SECP256K1.mul(3, P)
        assert ec_libsecp.LIBSECP.add(P, P) == SECP256K1.add(P, P)
    assert ec_libsecp.LIBSECP.add(P, SECP256K1.neg(P)) is None
    with pytest.raises(ValueError):
        ec_libsecp.resolve(TOY, "libsecp256k1")


def test_config_rows():
    assert Config().label() == "original"
    with pytest.raises(ValueError):
        Config(paillier_enc="magic")
    labels = [c.label() for c in config.variants_one_at_a_time()]
    assert labels[0] == "original" and len(labels) == len(set(labels)) == 8
    assert Config.from_dict(config.fastest().to_dict()) == config.fastest()


def _sign(run_pair, key, cfg, msg=b"Alice and Bob send 0.1 BTC to Carol"):
    curve = ec_libsecp.resolve(SECP256K1, cfg.curve)
    n = curve.n
    d1, d2 = secrets.randbelow(n - 1) + 1, secrets.randbelow(n - 1) + 1
    a_ops = paillier.ops_for(cfg, key.N, key)
    b_ops = paillier.ops_for(cfg, key.N)
    a_ops.precompute(4) if cfg.paillier_enc == "precomputed" else None
    b_ops.precompute(4) if cfg.paillier_enc == "precomputed" else None
    view = {}

    def bob(ch):
        ch.set_format(cfg.wire)
        return protocol.sign_bob(ch, curve, key.N, d2, msg, mask=cfg.mask, ops=b_ops)

    def alice(ch):
        ch.set_format(cfg.wire)
        return protocol.sign_alice(ch, curve, key, d1, msg, ops=a_ops,
                                   show=lambda step, v: view.update(v))
    sig_a, sig_b, stats = run_pair(alice, bob)
    Q = base_mult((d1 + d2) % n)
    return sig_a, sig_b, stats, view, d1, d2, Q


CONFIGS = [c for c in config.variants_one_at_a_time() + [config.fastest()]
           if c.paillier_bits == 2048]


@pytest.mark.parametrize("cfg", CONFIGS, ids=lambda c: c.label())
def test_every_variant_signs(run_pair, secp_key, cfg):
    msg = b"Alice and Bob send 0.1 BTC to Carol"
    sig_a, sig_b, stats, *_, Q = _sign(run_pair, secp_key, cfg, msg)
    assert sig_a == sig_b
    assert ecdsa_baseline.verify(Q, msg, sig_a)   # libsecp256k1 accepts it
    assert stats["sent_msgs"] + stats["recv_msgs"] >= 14


def test_experiment_still_works_with_fast_variants(run_pair, secp_key):
    cfg = config.fastest()
    cfg = Config(**{**cfg.to_dict(), "mask": False})
    *_, view, d1, d2, Q = _sign(run_pair, secp_key, cfg)
    assert mta.recover_b(view["alpha[k1*d2]"], view["k1"], SECP256K1.n) == d2


def test_3072_bit_key_size():
    from twoparty import bench
    assert bench.paillier_bits(SECP256K1, Config(paillier_bits=3072)) == 3072
    assert bench.paillier_bits(TOY, Config(paillier_bits=3072)) == mta.key_bits(TOY.n)


def test_matrix_cli_on_toy_curve(tmp_path):
    out = tmp_path / "m.csv"
    assert cli.main(["--task", "matrix", "--curve", "toy", "--rounds", "2",
                     "--out", str(out)]) == 0
    rows = list(csv.DictReader(out.open()))
    assert rows[0]["config"] == "original"
    assert all(float(r["sig_per_s"]) > 0 and float(r["msgs_per_sig"]) >= 14 for r in rows)
    assert any(r["wire"] == "binary" for r in rows)
