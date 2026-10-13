"""Timing helpers and the first benchmark tasks."""
import csv
import statistics
import time
from pathlib import Path

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


def append_csv(path: str, row: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    new = not p.exists()
    with p.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)
