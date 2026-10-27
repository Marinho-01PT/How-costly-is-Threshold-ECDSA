"""Command line entry point.

Examples (same code in every variant, only the address changes):
  python -m twoparty --role bob   --listen 127.0.0.1:5050
  python -m twoparty --role alice --peer   127.0.0.1:5050 --task echo --rounds 200
  python -m twoparty --role alice --peer   127.0.0.1:5050 --task sign --curve toy --rounds 50
  python -m twoparty --task baseline --rounds 200
"""
import argparse
import datetime
import json
import platform
import sys

from . import bench, net
from .ec import CURVES


def addr(text: str) -> tuple[str, int]:
    host, port = text.rsplit(":", 1)
    return host, int(port)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="twoparty")
    p.add_argument("--role", choices=["alice", "bob"])
    p.add_argument("--listen", help="host:port to wait on (Bob)")
    p.add_argument("--peer", help="host:port of the other party (Alice)")
    p.add_argument("--task", choices=["echo", "baseline", "sign"], default="echo")
    p.add_argument("--rounds", type=int, default=100)
    p.add_argument("--payload", type=int, default=64, help="echo payload in bytes")
    p.add_argument("--curve", choices=sorted(CURVES), default="secp256k1",
                   help="curve for --task sign (Alice decides, Bob follows)")
    p.add_argument("--label", default="unlabelled", help="name of the variant, e.g. docker-50ms")
    p.add_argument("--out", help="append the result to this CSV file")
    p.add_argument("--once", action="store_true", help="Bob: serve one connection, then exit")
    a = p.parse_args(argv)

    if a.task == "baseline":
        report(a, bench.baseline(a.rounds), None)
        return 0
    if a.role == "bob":
        return run_bob(a)
    if a.role == "alice":
        return run_alice(a)
    p.error("--role is required for this task")


def run_bob(a) -> int:
    if not a.listen:
        sys.exit("Bob needs --listen host:port")
    srv = net.listen(*addr(a.listen))
    print(f"bob: listening on {a.listen}", flush=True)
    while True:
        ch = net.accept(srv)
        hello = ch.recv()
        if hello["task"] == "echo":
            bench.echo_bob(ch)
        elif hello["task"] == "sign":
            bench.sign_bob(ch, CURVES[hello["curve"]])
        ch.close()
        if a.once:
            return 0


def run_alice(a) -> int:
    if not a.peer:
        sys.exit("Alice needs --peer host:port")
    ch = net.connect(*addr(a.peer))
    ch.send({"task": a.task, "curve": a.curve})
    if a.task == "echo":
        samples = bench.echo_alice(ch, a.rounds, a.payload)
        report(a, samples, ch.stats())
    else:
        samples, setup_ms = bench.sign_alice(ch, CURVES[a.curve], a.rounds)
        report(a, samples, ch.stats(), {"curve": a.curve, "setup_ms": round(setup_ms, 4)})
    ch.close()
    return 0


def report(a, samples, stats, extra=None) -> None:
    row = {
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "label": a.label, "task": a.task, "host": platform.node(),
        **(extra or {}),
        **{k: round(v, 4) if isinstance(v, float) else v for k, v in bench.summarize(samples).items()},
        **(stats or {}),
    }
    print(json.dumps(row))
    if a.out:
        bench.append_csv(a.out, row)


if __name__ == "__main__":
    raise SystemExit(main())
