"""Two-party ECDSA signing (Gennaro & Goldfeder 2018, simplified for two parties).

Semi-honest model, as our supervisors specified: both devices follow the
protocol, so the paper's commitments and zero-knowledge proofs are left out.
Everything is shared additively, nobody ever holds d, k or gamma:

    d = d1 + d2,   k = k1 + k2,   gamma = gamma1 + gamma2

    1. Gamma_i = gamma_i * G, exchanged
    2. MtA(k1, gamma2), MtA(gamma1, k2)  ->  delta1 + delta2 = k * gamma
    3. MtA(k1, d2),     MtA(d1, k2)      ->  sigma1 + sigma2 = k * d
    4. delta_i exchanged:  R = delta^-1 * (Gamma1 + Gamma2) = k^-1 * G,  r = x(R) mod n
    5. s_i = e*k_i + r*sigma_i exchanged:  s = s1 + s2, low s

The nonce is k^-1, so s = k * (e + r*d) = (k^-1)^-1 * (e + r*d): a normal ECDSA
signature that any verifier accepts. Only Alice has a Paillier key, so she
takes the a side of every MtA (a*b = b*a).

Messages per signature: 2 (Gamma) + 4*2 (MtA) + 2 (delta) + 2 (s) = 14.
Setup, once per pair of devices: 2. Works on any curve from ec.py.

show: every function takes an optional hook show(step, values). It is called
with each step's name and the values computed in it, before that step's
message is sent: the live demo (demo.py) prints and pauses there, the tests
record the values. Values from an MtA carry its name, e.g. alpha[k1*d2].

ops: sign_alice and sign_bob take an optional paillier.Ops with the chosen
variants of the Paillier building blocks (see config.py). Without it they use
the naive functions, as before. The curve variant is chosen by passing
ec_libsecp.LIBSECP instead of ec.SECP256K1.

Two more building blocks change the messages, not the math (keyword args,
off by default, so the original protocol is unchanged):

    reuse=True    Enc(d1) travels once, in the setup message, and Bob keeps it.
                  Per signature Alice sends Enc(k1) once and Bob uses it for
                  both MtAs with k1. Alice sends 2 ciphertexts instead of 4,
                  and the sequential flow shrinks to 12 messages. Safe in the
                  semi-honest model: every MtA still adds its own fresh beta'.
    batched=True  4 messages per signature instead of 14:
                    A -> B  Gamma1, all of Alice's c_A
                    B -> A  Gamma2, all four c_B, delta2
                    A -> B  delta1, s1
                    B -> A  s2
                  Bob can compute delta2 and sigma2 as soon as he has made his
                  c_B, because his beta shares are his own random numbers.
"""
from typing import Callable, Optional

from . import mta, paillier
from .ec import Curve, Point
from .ecdsa_pure import message_hash, rand_scalar
from .paillier import Key

Show = Optional[Callable[[str, dict], None]]


def _show(show: Show, step: str, **values) -> None:
    if show is not None:
        show(step, values)


def _mta_show(show: Show, name: str) -> Show:
    """Hook for one MtA: names the step and tags every value, e.g. alpha[k1*d2]."""
    if show is None:
        return None
    return lambda step, values: show(f"MtA {name}: {step}",
                                     {f"{k}[{name}]": v for k, v in values.items()})


def _swap(channel, msg: dict, first: bool) -> dict:
    """Send msg and get the other party's. Alice sends first, Bob answers."""
    if first:
        channel.send(msg)
        return channel.recv()
    other = channel.recv()
    channel.send(msg)
    return other


def _point(xy) -> Point:
    """Points travel as JSON lists; back to the (x, y) tuple of ec.py."""
    return tuple(xy)


# Setup: each party picks its own key share d_i and publishes Q_i = d_i * G.
# The full key d = d1 + d2 never exists anywhere; the public key is Q = Q1 + Q2.

def setup_alice(channel, curve: Curve, key: Optional[Key] = None, show: Show = None,
                mask_bits: int = mta.MASK_BITS, reuse: bool = False) -> tuple[Key, int, Point]:
    """Returns (Paillier key, d1, Q). Pass key to reuse one (its keygen is timed apart).

    reuse=True: the setup message also carries Enc(d1), for every later signature.
    """
    if key is None:
        key = paillier.keygen(mta.key_bits(curve.n, mask_bits))
    mta.check_key(key.N, curve.n, mask_bits)
    while True:
        d1 = rand_scalar(curve)
        Q1 = curve.base_mul(d1)
        _show(show, "setup: Paillier key and key share d1, send N and Q1 = d1*G",
              p=key.p, q=key.q, N=key.N, lam=key.lam, mu=key.mu, d1=d1, Q1=Q1)
        msg = {"N": key.N, "Q": Q1}
        if reuse:
            msg["c_d1"] = paillier.encrypt(key.N, d1)
        Q2 = _point(_swap(channel, msg, first=True)["Q"])
        Q = curve.add(Q1, Q2)
        _show(show, "setup: public key Q = Q1 + Q2", Q2=Q2, Q=Q)
        if Q is not None:  # d1 + d2 = 0 mod n, both see it and start again
            return key, d1, Q


def setup_bob(channel, curve: Curve, show: Show = None,
              mask_bits: int = mta.MASK_BITS, reuse: bool = False):
    """Returns (Alice's Paillier N, d2, Q).

    reuse=True: returns (N, d2, Q, c_d1), Enc(d1) from Alice's setup message,
    to pass to sign_bob as c_d1.
    """
    while True:
        d2 = rand_scalar(curve)
        Q2 = curve.base_mul(d2)
        _show(show, "setup: key share d2, send Q2 = d2*G (once Alice's message is here)",
              d2=d2, Q2=Q2)
        msg = _swap(channel, {"Q": Q2}, first=False)
        mta.check_key(msg["N"], curve.n, mask_bits)
        Q = curve.add(_point(msg["Q"]), Q2)
        _show(show, "setup: received N and Q1, public key Q = Q1 + Q2",
              N=msg["N"], Q1=_point(msg["Q"]), Q=Q)
        if Q is not None:
            if reuse:
                return msg["N"], d2, Q, msg["c_d1"]
            return msg["N"], d2, Q


def _finish(channel, curve: Curve, first: bool, e: int, k_i: int, delta_i: int,
            sigma_i: int, Gamma: Point, show: Show) -> Optional[tuple[int, int]]:
    """Steps 4 and 5, the same on both sides. None means: start again.

    Both parties see delta, r and s, so they always agree on starting again.
    """
    n = curve.n
    me, other = (1, 2) if first else (2, 1)
    _show(show, f"4. send delta{me} (k*gamma is masked by gamma, safe to reveal)",
          **{f"delta{me}": delta_i})
    delta_other = _swap(channel, {"delta": delta_i}, first)["delta"]
    delta = (delta_i + delta_other) % n
    if delta == 0:  # k = 0 or gamma = 0
        _show(show, "restart: delta = 0", delta=delta)
        return None
    # delta != 0 means gamma != 0, so R is never the point at infinity.
    R = curve.mul(pow(delta, -1, n), Gamma)  # (k*gamma)^-1 * gamma*G = k^-1 * G
    r = R[0] % n
    _show(show, "4. R = delta^-1 * (Gamma1 + Gamma2) = k^-1 * G, r = x(R) mod n",
          **{f"delta{other}": delta_other}, delta=delta, R=R, r=r)
    if r == 0:
        _show(show, "restart: r = 0", r=r)
        return None
    s_i = (e * k_i + r * sigma_i) % n
    _show(show, f"5. send s{me} = e*k{me} + r*sigma{me}", **{f"s{me}": s_i})
    s_other = _swap(channel, {"s": s_i}, first)["s"]
    s = (s_i + s_other) % n
    if s == 0:
        _show(show, "restart: s = 0", s=s)
        return None
    s_low = n - s if s > n // 2 else s  # low-s form, as Bitcoin and libsecp256k1 require
    _show(show, "5. s = s1 + s2, low s: the signature is (r, s)",
          **{f"s{other}": s_other}, s_raw=s, r=r, s=s_low)
    return r, s_low


def sign_alice(channel, curve: Curve, key: Key, d1: int, msg: bytes,
               show: Show = None, rng=None, ops=None, reuse: bool = False,
               batched: bool = False) -> tuple[int, int]:
    """Alice's side. Returns (r, s). rng only for reproducible demos and tests.

    reuse and batched: see the module docstring. Both sides must agree.
    """
    if batched:
        return _sign_alice_batched(channel, curve, key, d1, msg, show, rng, ops, reuse)
    n = curve.n
    e = message_hash(curve, msg)
    attempt = 0
    while True:
        attempt += 1
        k1, gamma1 = rand_scalar(curve, rng), rand_scalar(curve, rng)
        Gamma1 = curve.base_mul(gamma1)
        _show(show, "1. pick k1, gamma1, send Gamma1 = gamma1*G",
              attempt=attempt, e=e, k1=k1, gamma1=gamma1, Gamma1=Gamma1)
        Gamma2 = _point(_swap(channel, {"Gamma": Gamma1}, first=True)["Gamma"])
        _show(show, "1. received Gamma2", Gamma2=Gamma2)
        # Same order as in sign_bob. Alice always has the a side.
        alpha = {}
        for name, a in (("k1*gamma2", k1), ("gamma1*k2", gamma1)):
            alpha[name] = mta.mta_alice(channel, key, a, n, _mta_show(show, name), ops)
        # With reuse Bob already has Enc(k1) (just sent) and Enc(d1) (setup).
        # k*gamma = k1*gamma1 + k2*gamma2 + k1*gamma2 + gamma1*k2: own term + MtA shares
        delta1 = (k1 * gamma1 + alpha["k1*gamma2"] + alpha["gamma1*k2"]) % n
        _show(show, "2. delta1 = k1*gamma1 + alpha[k1*gamma2] + alpha[gamma1*k2]", delta1=delta1)
        for name, a in (("k1*d2", k1), ("d1*k2", d1)):
            alpha[name] = mta.mta_alice(channel, key, a, n, _mta_show(show, name), ops,
                                        send=not reuse)
        sigma1 = (k1 * d1 + alpha["k1*d2"] + alpha["d1*k2"]) % n
        _show(show, "3. sigma1 = k1*d1 + alpha[k1*d2] + alpha[d1*k2]", sigma1=sigma1)
        sig = _finish(channel, curve, True, e, k1, delta1, sigma1,
                      curve.add(Gamma1, Gamma2), show)
        if sig is not None:
            return sig


def sign_bob(channel, curve: Curve, N: int, d2: int, msg: bytes,
             show: Show = None, rng=None, mask: bool = True,
             mask_bits: int = mta.MASK_BITS, ops=None, reuse: bool = False,
             batched: bool = False, c_d1: Optional[int] = None) -> tuple[int, int]:
    """Bob's side. Returns (r, s).

    mask=False leaves out beta' in every MtA: the experiment in which Alice
    learns Bob's key share (mta.recover_b). Never in normal use.
    mask_bits below 40 only for the demo's study mode (see mta.py).
    reuse=True needs c_d1, Enc(d1) from setup_bob(..., reuse=True).
    """
    if reuse and c_d1 is None:
        raise ValueError("reuse needs c_d1 from setup_bob(..., reuse=True)")
    if batched:
        return _sign_bob_batched(channel, curve, N, d2, msg, show, rng, mask,
                                 mask_bits, ops, reuse, c_d1)
    n = curve.n
    e = message_hash(curve, msg)
    attempt = 0
    while True:
        attempt += 1
        k2, gamma2 = rand_scalar(curve, rng), rand_scalar(curve, rng)
        Gamma2 = curve.base_mul(gamma2)
        _show(show, "1. pick k2, gamma2, send Gamma2 = gamma2*G (once Gamma1 is here)",
              attempt=attempt, e=e, k2=k2, gamma2=gamma2, Gamma2=Gamma2)
        Gamma1 = _point(_swap(channel, {"Gamma": Gamma2}, first=False)["Gamma"])
        _show(show, "1. received Gamma1", Gamma1=Gamma1)
        beta = {}
        c_k1 = channel.recv()["c_A"] if reuse else None  # kept for k1*d2 as well
        for name, b, c_A in (("k1*gamma2", gamma2, c_k1), ("gamma1*k2", k2, None)):
            beta[name] = mta.mta_bob(channel, N, b, n, mask, _mta_show(show, name),
                                     mask_bits, ops, c_A)
        delta2 = (k2 * gamma2 + beta["k1*gamma2"] + beta["gamma1*k2"]) % n
        _show(show, "2. delta2 = k2*gamma2 + beta[k1*gamma2] + beta[gamma1*k2]", delta2=delta2)
        for name, b, c_A in (("k1*d2", d2, c_k1), ("d1*k2", k2, c_d1 if reuse else None)):
            beta[name] = mta.mta_bob(channel, N, b, n, mask, _mta_show(show, name),
                                     mask_bits, ops, c_A)
        sigma2 = (k2 * d2 + beta["k1*d2"] + beta["d1*k2"]) % n
        _show(show, "3. sigma2 = k2*d2 + beta[k1*d2] + beta[d1*k2]", sigma2=sigma2)
        sig = _finish(channel, curve, False, e, k2, delta2, sigma2,
                      curve.add(Gamma1, Gamma2), show)
        if sig is not None:
            return sig


# --- Batched flow: 4 messages per signature ---------------------------------

# The four MtAs in a fixed order, so lists of ciphertexts line up on both sides.
_MTAS = ("k1*gamma2", "gamma1*k2", "k1*d2", "d1*k2")


def _enc(key_or_N, ops, a: int, n: int) -> int:
    N = key_or_N.N if isinstance(key_or_N, Key) else key_or_N
    if ops is None:
        return mta.alice_encrypt(N, a, n)
    return ops.encrypt(a)


def _dec(key: Key, ops, c: int) -> int:
    return paillier.decrypt(key, c) if ops is None else ops.decrypt(c)


def _sign_alice_batched(channel, curve, key, d1, msg, show, rng, ops, reuse):
    n = curve.n
    e = message_hash(curve, msg)
    attempt = 0
    while True:
        attempt += 1
        k1, gamma1 = rand_scalar(curve, rng), rand_scalar(curve, rng)
        Gamma1 = curve.base_mul(gamma1)
        if reuse:   # Enc(k1) serves k1*gamma2 and k1*d2, Enc(d1) is from setup
            c_A = [_enc(key, ops, k1, n), _enc(key, ops, gamma1, n)]
        else:
            c_A = [_enc(key, ops, a, n) for a in (k1, gamma1, k1, d1)]
        _show(show, "1+2+3. send Gamma1 = gamma1*G and Alice's c_A in one message",
              attempt=attempt, e=e, k1=k1, gamma1=gamma1, Gamma1=Gamma1, c_A=c_A)
        channel.send({"Gamma": Gamma1, "c_A": c_A})
        m2 = channel.recv()
        Gamma2, delta2 = _point(m2["Gamma"]), m2["delta"]
        alpha = {}
        for name, c_B in zip(_MTAS, m2["c_B"]):
            plain = _dec(key, ops, c_B)
            alpha[name] = plain % n
            _show(show, f"MtA {name}: alpha = Dec(c_B) mod n",
                  **{f"c_B[{name}]": c_B, f"plain[{name}]": plain, f"alpha[{name}]": alpha[name]})
        delta1 = (k1 * gamma1 + alpha["k1*gamma2"] + alpha["gamma1*k2"]) % n
        sigma1 = (k1 * d1 + alpha["k1*d2"] + alpha["d1*k2"]) % n
        delta = (delta1 + delta2) % n
        _show(show, "2+3. delta1, sigma1 from the MtA shares; delta = delta1 + delta2",
              Gamma2=Gamma2, delta1=delta1, delta2=delta2, sigma1=sigma1, delta=delta)
        if delta == 0:
            channel.send({"delta": delta1})   # Bob sees delta = 0 as well
            continue
        R = curve.mul(pow(delta, -1, n), curve.add(Gamma1, Gamma2))
        r = R[0] % n
        if r == 0:
            channel.send({"delta": delta1})
            continue
        s1 = (e * k1 + r * sigma1) % n
        _show(show, "4+5. R = delta^-1 * (Gamma1 + Gamma2), send delta1 and s1",
              R=R, r=r, s1=s1)
        channel.send({"delta": delta1, "s": s1})
        s2 = channel.recv()["s"]
        s = (s1 + s2) % n
        if s == 0:
            continue
        s_low = n - s if s > n // 2 else s
        _show(show, "5. s = s1 + s2, low s: the signature is (r, s)", s2=s2, s_raw=s, s=s_low)
        return r, s_low


def _sign_bob_batched(channel, curve, N, d2, msg, show, rng, mask, mask_bits, ops,
                      reuse, c_d1):
    n = curve.n
    e = message_hash(curve, msg)
    attempt = 0
    while True:
        attempt += 1
        k2, gamma2 = rand_scalar(curve, rng), rand_scalar(curve, rng)
        Gamma2 = curve.base_mul(gamma2)
        m1 = channel.recv()
        Gamma1 = _point(m1["Gamma"])
        if reuse:
            c_k1, c_g1 = m1["c_A"]
            c_A = (c_k1, c_g1, c_k1, c_d1)
        else:
            c_A = tuple(m1["c_A"])
        beta, c_B = {}, []
        for name, c, b in zip(_MTAS, c_A, (gamma2, k2, d2, k2)):
            cb, beta[name], beta_prime = mta.bob_respond(N, c, b, n, mask, mask_bits, ops)
            c_B.append(cb)
            _show(show, f"MtA {name}: c_B = c_A^b * Enc(beta'), keep beta = -beta' mod n",
                  **{f"beta_prime[{name}]": beta_prime, f"beta[{name}]": beta[name]})
        delta2 = (k2 * gamma2 + beta["k1*gamma2"] + beta["gamma1*k2"]) % n
        sigma2 = (k2 * d2 + beta["k1*d2"] + beta["d1*k2"]) % n
        _show(show, "1+2+3. send Gamma2, all c_B and delta2 in one message",
              attempt=attempt, e=e, k2=k2, gamma2=gamma2, Gamma2=Gamma2, Gamma1=Gamma1,
              delta2=delta2, sigma2=sigma2)
        channel.send({"Gamma": Gamma2, "c_B": c_B, "delta": delta2})
        m3 = channel.recv()
        delta = (m3["delta"] + delta2) % n
        if delta == 0:
            continue
        R = curve.mul(pow(delta, -1, n), curve.add(Gamma1, Gamma2))
        r = R[0] % n
        if r == 0:
            continue
        s2 = (e * k2 + r * sigma2) % n
        _show(show, "4+5. R = delta^-1 * (Gamma1 + Gamma2), send s2",
              delta1=m3["delta"], delta=delta, R=R, r=r, s2=s2)
        channel.send({"s": s2})
        s = (m3["s"] + s2) % n
        if s == 0:
            continue
        s_low = n - s if s > n // 2 else s
        _show(show, "5. s = s1 + s2, low s: the signature is (r, s)",
              s1=m3["s"], s_raw=s, r=r, s=s_low)
        return r, s_low
