"""Timing helpers and the first benchmark tasks."""
import csv
import statistics
import time
from pathlib import Path

from coincurve import PublicKey

from . import ec_libsecp, ecdsa_baseline, ecdsa_pure, mta, paillier, protocol
from .config import Config
from .ecdsa_baseline import keygen, sign


def summarize(samples_ms: list[float]) -> dict:
    s = sorted(samples_ms)
    p95 = s[min(len(s) - 1, int(0.95 * len(s)))]
    return {
        "n": len(s),
        "mean_ms": statistics.fmean(s),
        "median_ms": statistics.median(s),
        "p95_ms": p95,
        "min_ms": s[0],
        "max_ms": s[-1],
    }


def baseline(rounds: int) -> list[float]:
    """Single-device signing, no network. The reference the protocol is compared to."""
    d, _ = keygen()
    out = []
    for i in range(rounds):
        msg = f"tx-{i}".encode()
        t0 = time.perf_counter()
        sign(d, msg)
        out.append((time.perf_counter() - t0) * 1000)
    return out


def echo_alice(channel, rounds: int, payload: int) -> list[float]:
    """Round trip time over the channel: send a message, wait for the echo."""
    pad = "x" * payload
    out = []
    for i in range(rounds):
        t0 = time.perf_counter()
        channel.send({"i": i, "pad": pad})
        channel.recv()
        out.append((time.perf_counter() - t0) * 1000)
    return out


def echo_bob(channel) -> None:
    """Send every message back until the other side disconnects."""
    try:
        while True:
            channel.send(channel.recv())
    except ConnectionError:
        pass


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


def _verifier(curve, cfg: Config):
    """Verification of the finished signature, with the chosen curve variant."""
    if cfg.curve == "libsecp256k1":
        return lambda Q, msg, sig: ecdsa_baseline.verify(PublicKey.from_point(*Q), msg, sig)
    return lambda Q, msg, sig: ecdsa_pure.verify(curve, Q, msg, sig)


def paillier_bits(curve, cfg: Config) -> int:
    """cfg.paillier_bits on secp256k1; the toy curve keeps its small key."""
    return cfg.paillier_bits if curve.n.bit_length() > 64 else mta.key_bits(curve.n)


def sign_alice(channel, curve, rounds: int, cfg: Config | None = None,
               key: paillier.Key | None = None) -> tuple[list[float], float] | dict:
    """Two-party signing with the variants in cfg. Returns the measurements.

    Phases, each timed on its own:
      keygen   Paillier key generation (skipped if key is given)
      setup    key shares and public key (2 messages)
      offline  only with paillier_enc=precomputed: the r^N pool, both sides
      sign     one sample per signature, plus messages and bytes per signature
      verify   checking each finished signature (normal ECDSA verification)
    Every signature is also checked with libsecp256k1 or the pure code,
    outside the timing, and a wrong one stops the run.

    Without cfg (the old call) it returns (samples, setup_ms) as before.
    """
    old_call = cfg is None
    cfg = cfg or Config()
    cfg.check_curve(curve.name)
    pcurve = ec_libsecp.resolve(curve, cfg.curve)
    t0 = time.perf_counter()
    keygen_ms = 0.0
    if key is None:
        key = paillier.keygen(paillier_bits(curve, cfg))
        keygen_ms = _ms(t0)
    t0 = time.perf_counter()
    reuse, batched = cfg.mta == "reuse", cfg.flow == "batched"
    key, d1, Q = protocol.setup_alice(channel, pcurve, key=key, reuse=reuse)
    setup_ms = _ms(t0)
    if old_call:
        setup_ms += keygen_ms
    ops = paillier.ops_for(cfg, key.N, key)
    t0 = time.perf_counter()
    if cfg.paillier_enc == "precomputed":
        ops.precompute(4 * rounds)
    offline_alice = _ms(t0)
    offline_bob = channel.recv()["ready"]  # Bob has filled his pool too
    verify = _verifier(curve, cfg)
    sign_ms, verify_ms, msgs, nbytes = [], [], [], []
    for i in range(rounds):
        msg = f"tx-{i}".encode()
        before = channel.stats()
        t0 = time.perf_counter()
        sig = protocol.sign_alice(channel, pcurve, key, d1, msg, ops=ops,
                                  reuse=reuse, batched=batched)
        sign_ms.append(_ms(t0))
        after = channel.stats()
        msgs.append(after["sent_msgs"] + after["recv_msgs"] - before["sent_msgs"] - before["recv_msgs"])
        nbytes.append(after["sent_bytes"] + after["recv_bytes"] - before["sent_bytes"] - before["recv_bytes"])
        t0 = time.perf_counter()
        ok = verify(Q, msg, sig)
        verify_ms.append(_ms(t0))
        if not ok or not ecdsa_pure.verify(curve, Q, msg, sig):
            raise RuntimeError(f"two-party signature {i} does not verify")
    if old_call:
        return sign_ms, setup_ms
    total_s = sum(sign_ms) / 1000
    return {
        "config": cfg.label(), "curve": curve.name,
        **{("curve_impl" if k == "curve" else k): v for k, v in cfg.to_dict().items()},
        "paillier_bits_used": key.N.bit_length(),
        "keygen_ms": round(keygen_ms, 3), "setup_ms": round(setup_ms, 3),
        "offline_ms": round(max(offline_alice, offline_bob), 3),
        **{k: (round(v, 4) if isinstance(v, float) else v)
           for k, v in summarize(sign_ms).items()},  # signing time, as in the first version
        "sig_per_s": round(rounds / total_s, 3) if total_s else None,
        "verify_mean_ms": round(statistics.fmean(verify_ms), 4),
        "msgs_per_sig": statistics.fmean(msgs),
        "bytes_per_sig": round(statistics.fmean(nbytes)),
        "pool_misses_alice": ops.pool_misses,
    }


def sign_bob(channel, curve, cfg: Config | None = None, rounds: int = 0) -> None:
    """Sign tx-0, tx-1, ... with Alice until she disconnects."""
    cfg = cfg or Config()
    pcurve = ec_libsecp.resolve(curve, cfg.curve)
    reuse, batched = cfg.mta == "reuse", cfg.flow == "batched"
    c_d1 = None
    if reuse:
        N, d2, _, c_d1 = protocol.setup_bob(channel, pcurve, reuse=True)
    else:
        N, d2, _ = protocol.setup_bob(channel, pcurve)
    ops = paillier.ops_for(cfg, N)
    t0 = time.perf_counter()
    if cfg.paillier_enc == "precomputed":
        ops.precompute(4 * rounds)
    channel.send({"ready": _ms(t0)})
    i = 0
    try:
        while True:
            protocol.sign_bob(channel, pcurve, N, d2, f"tx-{i}".encode(),
                              mask=cfg.mask, ops=ops, reuse=reuse, batched=batched,
                              c_d1=c_d1)
            i += 1
    except ConnectionError:
        pass


def append_csv(path: str, row: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    new = not p.exists()
    with p.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)
