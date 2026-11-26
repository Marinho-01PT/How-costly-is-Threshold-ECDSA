"""The message-shaping building blocks: MtA reuse and the batched flow.

They change which messages travel, never the result: every combination must
give a normal ECDSA signature that libsecp256k1 accepts, both parties must
end with the same (r, s), and the experiment without beta' must still leak d2.
"""
import itertools
import secrets

import pytest

from twoparty import config, ec_libsecp, ecdsa_baseline, ecdsa_pure, mta, paillier, protocol
from twoparty.config import Config
from twoparty.ec import SECP256K1, TOY

MSG = b"Alice and Bob send 0.1 BTC to Carol"

# messages per signature: (mta, flow) -> count
EXPECTED_MSGS = {
    ("separate", "sequential"): 14,
    ("reuse", "sequential"): 12,
    ("separate", "batched"): 4,
    ("reuse", "batched"): 4,
}


def run_session(run_pair, curve, key, cfg, msg=MSG, rounds=1):
    """Setup plus rounds signatures with cfg. Returns (sigs_a, sigs_b, views, stats, d1, d2, Q)."""
    reuse, batched = cfg.mta == "reuse", cfg.flow == "batched"
    pcurve = ec_libsecp.resolve(curve, cfg.curve)
    views = []

    def alice(ch):
        ch.set_format(cfg.wire)
        _, d1, Q = protocol.setup_alice(ch, pcurve, key=key, reuse=reuse)
        ops = paillier.ops_for(cfg, key.N, key)
        if cfg.paillier_enc == "precomputed":
            ops.precompute(4 * rounds)
        setup_stats = ch.stats()
        sigs = []
        for _ in range(rounds):
            view = {}
            views.append(view)
            sigs.append(protocol.sign_alice(ch, pcurve, key, d1, msg, ops=ops, reuse=reuse,
                                            batched=batched,
                                            show=lambda step, v, view=view: view.update(v)))
        end = ch.stats()
        msgs = (end["sent_msgs"] + end["recv_msgs"]
                - setup_stats["sent_msgs"] - setup_stats["recv_msgs"])
        return sigs, d1, Q, msgs

    def bob(ch):
        ch.set_format(cfg.wire)
        if reuse:
            N, d2, Q, c_d1 = protocol.setup_bob(ch, pcurve, reuse=True)
        else:
            (N, d2, Q), c_d1 = protocol.setup_bob(ch, pcurve), None
        ops = paillier.ops_for(cfg, N)
        if cfg.paillier_enc == "precomputed":
            ops.precompute(4 * rounds)
        return [protocol.sign_bob(ch, pcurve, N, d2, msg, mask=cfg.mask, ops=ops,
                                  reuse=reuse, batched=batched, c_d1=c_d1)
                for _ in range(rounds)], d2, Q

    (sigs_a, d1, Q, msgs), (sigs_b, d2, Q_b), _ = run_pair(alice, bob)
    assert Q == Q_b
    return sigs_a, sigs_b, views, msgs, d1, d2, Q


SHAPES = list(itertools.product(["separate", "reuse"], ["sequential", "batched"]))
OTHERS = [Config(), config.fastest(),
          Config(paillier_dec="crt", paillier_enc="crt"),
          Config(wire="binary", bignum="gmpy2"),
          Config(curve="libsecp256k1", paillier_enc="precomputed")]


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: f"{s[0]}-{s[1]}")
@pytest.mark.parametrize("base", OTHERS, ids=lambda c: c.label())
def test_every_shape_signs(run_pair, secp_key, shape, base):
    if base.bignum == "gmpy2":
        pytest.importorskip("gmpy2")
    cfg = Config(**{**base.to_dict(), "mta": shape[0], "flow": shape[1]})
    sigs_a, sigs_b, _, msgs, *_, Q = run_session(run_pair, SECP256K1, secp_key, cfg)
    assert sigs_a == sigs_b
    assert ecdsa_baseline.verify(_pub(Q), MSG, sigs_a[0])
    assert msgs == EXPECTED_MSGS[shape]


def _pub(Q):
    from coincurve import PublicKey
    return PublicKey.from_point(*Q)


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: f"{s[0]}-{s[1]}")
def test_toy_curve_many_signatures(run_pair, toy_key, shape):
    """The toy curve (n = 313) hits the restarts (delta = 0, r = 0, s = 0) now and then."""
    cfg = Config(mta=shape[0], flow=shape[1])
    sigs_a, sigs_b, _, msgs, d1, d2, Q = run_session(run_pair, TOY, toy_key, cfg, rounds=40)
    assert sigs_a == sigs_b
    assert all(ecdsa_pure.verify(TOY, Q, MSG, sig) for sig in sigs_a)
    assert msgs >= 40 * EXPECTED_MSGS[shape]


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: f"{s[0]}-{s[1]}")
def test_experiment_still_leaks_d2(run_pair, secp_key, shape):
    cfg = Config(mask=False, mta=shape[0], flow=shape[1])
    _, _, views, _, d1, d2, Q = run_session(run_pair, SECP256K1, secp_key, cfg)
    v = views[0]
    assert mta.recover_b(v["alpha[k1*d2]"], v["k1"], SECP256K1.n) == d2


def test_reuse_needs_c_d1():
    with pytest.raises(ValueError):
        protocol.sign_bob(None, SECP256K1, 0, 1, MSG, reuse=True)


def test_default_is_unchanged(run_pair, secp_key):
    """Config() still sends 14 messages per signature, with 4 ciphertexts from Alice."""
    _, _, _, msgs, *_ = run_session(run_pair, SECP256K1, secp_key, Config())
    assert msgs == 14
