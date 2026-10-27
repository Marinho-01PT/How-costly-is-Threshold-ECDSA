import random
import secrets

import pytest

from twoparty import __main__ as cli
from twoparty import ecdsa_baseline, ecdsa_pure, mta, net, protocol
from twoparty.curve import base_mult
from twoparty.ec import SECP256K1, TOY


class Scripted:
    """Stand-in for random.Random: hands out the given values first, then random ones."""
    def __init__(self, *values):
        self.values = list(values)
        self.rest = random.Random()

    def randrange(self, lo, hi):
        return self.values.pop(0) if self.values else self.rest.randrange(lo, hi)


def recorder(view):
    """show hook for the tests: keeps the latest value of everything."""
    return lambda step, values: view.update(values)


def sign_once(run_pair, curve, key, msg, mask=True, rng_a=None, rng_b=None):
    """Fresh key shares, one two-party signature.

    Returns (sig_alice, sig_bob, view_alice, view_bob, stats_alice, d1, d2).
    """
    n = curve.n
    d1, d2 = secrets.randbelow(n - 1) + 1, secrets.randbelow(n - 1) + 1
    va, vb = {}, {}
    sig_a, sig_b, stats = run_pair(
        lambda ch: protocol.sign_alice(ch, curve, key, d1, msg, show=recorder(va), rng=rng_a),
        lambda ch: protocol.sign_bob(ch, curve, key.N, d2, msg, show=recorder(vb),
                                    rng=rng_b, mask=mask),
    )
    return sig_a, sig_b, va, vb, stats, d1, d2


def check_views(curve, va, vb, d1, d2):
    """The shares add up to what the protocol promises."""
    n = curve.n
    k = (va["k1"] + vb["k2"]) % n
    gamma = (va["gamma1"] + vb["gamma2"]) % n
    d = (d1 + d2) % n
    for name, a_side, b_side in [("k1*gamma2", va["k1"], vb["gamma2"]),
                                 ("gamma1*k2", va["gamma1"], vb["k2"]),
                                 ("k1*d2", va["k1"], d2),
                                 ("d1*k2", d1, vb["k2"])]:
        assert (va[f"alpha[{name}]"] + vb[f"beta[{name}]"]) % n == a_side * b_side % n, name
    assert (va["delta1"] + vb["delta2"]) % n == k * gamma % n
    assert (va["sigma1"] + vb["sigma2"]) % n == k * d % n
    assert va["R"] == vb["R"] == curve.base_mul(pow(k, -1, n))
    return k, d


@pytest.fixture
def key_for(toy_key, secp_key):
    return lambda curve: toy_key if curve is TOY else secp_key


@pytest.mark.parametrize("curve", [TOY, SECP256K1], ids=lambda c: c.name)
def test_signature_verifies(run_pair, key_for, curve):
    msg = b"pay 1 BTC to Bob"
    sig, sig_b, va, vb, stats, d1, d2 = sign_once(run_pair, curve, key_for(curve), msg)
    assert sig == sig_b  # both devices end up with the same signature
    k, d = check_views(curve, va, vb, d1, d2)
    Q = curve.base_mul(d)
    assert ecdsa_pure.verify(curve, Q, msg, sig)
    assert not ecdsa_pure.verify(curve, Q, b"pay 2 BTC to Bob", sig)
    assert not ecdsa_pure.verify(curve, curve.base_mul(d + 1), msg, sig)
    # Exactly the signature single-device ECDSA gives with key d and nonce k^-1.
    st = ecdsa_pure.sign_steps(curve, d, va["e"], pow(k, -1, curve.n))
    assert (st.r, st.s) == sig
    if va["attempt"] == 1:
        assert stats["sent_msgs"] == stats["recv_msgs"] == 7  # 14 messages in total
    if curve is SECP256K1:
        # The most important check: the independent libsecp256k1 accepts it.
        assert ecdsa_baseline.verify(base_mult(d), msg, sig)


def test_many_signatures_toy(run_pair, toy_key):
    """300 signatures over one connection, with setup. On the toy curve
    restarts (k = 0, gamma = 0, r = 0, s = 0) really happen now and then."""
    msgs = [f"tx-{i}".encode() for i in range(300)]

    def alice(ch):
        key, d1, Q = protocol.setup_alice(ch, TOY, toy_key)
        return Q, [protocol.sign_alice(ch, TOY, key, d1, m) for m in msgs]

    def bob(ch):
        N, d2, Q = protocol.setup_bob(ch, TOY)
        return Q, [protocol.sign_bob(ch, TOY, N, d2, m) for m in msgs]

    (Q, sigs), (Q_b, sigs_b), _ = run_pair(alice, bob)
    assert Q == Q_b and sigs == sigs_b
    assert all(ecdsa_pure.verify(TOY, Q, m, sig) for m, sig in zip(msgs, sigs))
    assert all(sig[1] <= TOY.n // 2 for sig in sigs)  # low s


def test_setup_gives_both_the_same_public_key(run_pair, toy_key):
    (key, d1, Q), (N, d2, Q_b), stats = run_pair(
        lambda ch: protocol.setup_alice(ch, TOY, toy_key),
        lambda ch: protocol.setup_bob(ch, TOY),
    )
    assert Q == Q_b == TOY.base_mul(d1 + d2)
    assert N == key.N
    assert stats["sent_msgs"] == stats["recv_msgs"] == 1


def test_restart_when_k_is_zero(run_pair, toy_key):
    """k1 = 1, k2 = n - 1: k = 0, so delta = 0. Both must start again."""
    n = TOY.n
    msg = b"restart"
    sig, sig_b, va, vb, _, d1, d2 = sign_once(
        run_pair, TOY, toy_key, msg, rng_a=Scripted(1, 5), rng_b=Scripted(n - 1, 7))
    assert va["attempt"] == vb["attempt"] == 2
    assert sig == sig_b
    assert ecdsa_pure.verify(TOY, TOY.base_mul(d1 + d2), msg, sig)


@pytest.mark.parametrize("curve", [TOY, SECP256K1], ids=lambda c: c.name)
def test_experiment_without_mask_alice_steals_the_key(run_pair, key_for, curve):
    """Bob leaves out beta'. The signature is still valid, but Alice reads d2
    out of her MtA share for k1*d2 and can then sign anything alone."""
    n = curve.n
    sig, _, va, _, _, d1, d2 = sign_once(run_pair, curve, key_for(curve), b"hi", mask=False)
    stolen_d2 = mta.recover_b(va["alpha[k1*d2]"], va["k1"], n)
    assert stolen_d2 == d2
    d = (d1 + stolen_d2) % n
    Q = curve.base_mul((d1 + d2) % n)
    forged = ecdsa_pure.sign(curve, d, b"pay everything to Alice")
    assert ecdsa_pure.verify(curve, Q, b"pay everything to Alice", forged)


def test_cli_sign_task(toy_key, capsys):
    """python -m twoparty --task sign end to end, both roles, toy curve."""
    import threading
    srv = net.listen("127.0.0.1", 0)
    port = srv.getsockname()[1]
    srv.close()
    t = threading.Thread(target=cli.main, args=(
        ["--role", "bob", "--listen", f"127.0.0.1:{port}", "--once"],), daemon=True)
    t.start()
    assert cli.main(["--role", "alice", "--peer", f"127.0.0.1:{port}",
                     "--task", "sign", "--curve", "toy", "--rounds", "5"]) == 0
    t.join(timeout=10)
    out = capsys.readouterr().out
    assert '"task": "sign"' in out and '"curve": "toy"' in out and '"n": 5' in out
