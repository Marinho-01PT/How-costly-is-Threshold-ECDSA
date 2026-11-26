"""Command line entry point.

Examples (same code in every variant, only the address changes):
  python -m twoparty --role bob   --listen 127.0.0.1:5050
  python -m twoparty --role alice --peer   127.0.0.1:5050 --task echo --rounds 200
  python -m twoparty --role alice --peer   127.0.0.1:5050 --task sign --curve toy --rounds 50
  python -m twoparty --task baseline --rounds 200

Building blocks (see config.py), one --set per row that differs from the original:
  python -m twoparty --role alice --peer 127.0.0.1:5050 --task sign \
      --set paillier_dec=crt --set bignum=gmpy2 --rounds 20
Benchmark matrix: the original, every variant on its own, all speed-ups together.
Starts its own Bob on localhost unless --peer is given:
  python -m twoparty --task matrix --rounds 10

Two laptops on the same Wi-Fi (no addresses, see lan.py):
  python -m twoparty lan                                  # the demo: host, prints a code
  python -m twoparty lan --code 4821                      # the demo: join
  python -m twoparty --role bob --lan                     # benchmark: Bob, prints a code
  python -m twoparty --role alice --task sign --lan --code 4821
  python -m twoparty --task matrix --lan --code 4821
"""
import argparse
import datetime
import json
import platform
import socket
import subprocess
import sys
import time
from dataclasses import replace

from . import bench, config, lan, net, paillier
from .config import Config
from .ec import CURVES


def addr(text: str) -> tuple[str, int]:
    host, port = text.rsplit(":", 1)
    return host, int(port)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] in (["lan"], ["demo"]):  # python -m twoparty lan ... = the demo over Wi-Fi
        from . import demo
        rest = argv[1:]
        return demo.main(rest if argv[0] == "demo" else ["lan", *rest])
    if argv[:1] == ["ui"]:  # python -m twoparty ui [--port 8765] [--no-browser]: the web lab
        from .ui_server import serve
        port = int(argv[argv.index("--port") + 1]) if "--port" in argv else 8765
        return serve(port=port, open_browser="--no-browser" not in argv)
    p = argparse.ArgumentParser(prog="twoparty")
    p.add_argument("--role", choices=["alice", "bob"])
    p.add_argument("--listen", help="host:port to wait on (Bob)")
    p.add_argument("--peer", help="host:port of the other party (Alice)")
    p.add_argument("--task", choices=["echo", "baseline", "sign", "matrix"], default="echo")
    p.add_argument("--set", action="append", default=[], metavar="ROW=VARIANT",
                   help="pick a building-block variant, e.g. paillier_enc=precomputed")
    p.add_argument("--rounds", type=int, default=100)
    p.add_argument("--payload", type=int, default=64, help="echo payload in bytes")
    p.add_argument("--curve", choices=sorted(CURVES), default="secp256k1",
                   help="curve for --task sign (Alice decides, Bob follows)")
    p.add_argument("--label", default="unlabelled", help="name of the variant, e.g. docker-50ms")
    p.add_argument("--out", help="append the result to this CSV file")
    p.add_argument("--once", action="store_true", help="Bob: serve one connection, then exit")
    p.add_argument("--lan", action="store_true",
                   help="find the other laptop on this Wi-Fi: Bob announces a code, Alice uses --code")
    p.add_argument("--code", help="--lan: the pairing code (Bob: optional, else a new one)")
    p.add_argument("--timeout", type=float, default=30.0, help="--lan: seconds Alice searches")
    p.add_argument("--beacon-port", type=int, default=lan.BEACON_PORT, help=argparse.SUPPRESS)
    p.add_argument("--beacon-addr", help=argparse.SUPPRESS)  # tests: send beacons here only
    a = p.parse_args(argv)

    if a.task == "baseline":
        report(a, bench.baseline(a.rounds), None)
        return 0
    if a.task == "matrix":
        return run_matrix(a)
    if a.role == "bob":
        return run_bob(a)
    if a.role == "alice":
        return run_alice(a)
    p.error("--role is required for this task")


def run_bob(a) -> int:
    beacon = None
    if a.lan:
        a.listen = a.listen or "0.0.0.0:5050"
    if not a.listen:
        sys.exit("Bob needs --listen host:port (or --lan)")
    srv = net.listen(*addr(a.listen))
    print(f"bob: listening on {a.listen}", flush=True)
    if a.lan:
        code = a.code or lan.new_code()
        port = srv.getsockname()[1]
        beacon = lan.Beacon(code, "bench", port, role="alice",
                            targets=[a.beacon_addr] if a.beacon_addr else None,
                            beacon_port=a.beacon_port).start()
        print(f"bob: pairing code {code}, this laptop is {lan.local_ip()}:{port}\n"
              f"     on the other laptop: python -m twoparty --task matrix --lan --code {code}",
              flush=True)
    while True:
        ch = net.accept(srv)
        hello = ch.recv()
        if hello["task"] == "echo":
            bench.echo_bob(ch)
        elif hello["task"] == "sign":
            cfg = Config.from_dict(hello.get("config"))
            ch.set_format(cfg.wire)
            bench.sign_bob(ch, CURVES[hello["curve"]], cfg, hello.get("rounds", 0))
        ch.close()
        if a.once:
            return 0


def parse_sets(items: list[str]) -> Config:
    """--set row=variant ... -> Config. Numbers and True/False are converted."""
    d = {}
    for item in items:
        k, _, v = item.partition("=")
        d[k] = {"true": True, "false": False}.get(v.lower(), int(v) if v.isdigit() else v)
    unknown = set(d) - set(Config.__dataclass_fields__)
    if unknown:
        sys.exit(f"unknown building block(s): {', '.join(sorted(unknown))}")
    return Config(**d)


def sign_session(peer: tuple[str, int], curve: str, rounds: int, cfg: Config,
                 key=None) -> dict:
    """One connection to Bob: setup, then rounds signatures with cfg."""
    ch = net.connect(*peer)
    try:
        ch.send({"task": "sign", "curve": curve, "rounds": rounds, "config": cfg.to_dict()})
        ch.set_format(cfg.wire)
        return bench.sign_alice(ch, CURVES[curve], rounds, cfg, key)
    finally:
        ch.close()


def find_peer(a) -> None:
    """--lan --code: look for Bob's beacon and set a.peer."""
    if not a.code:
        sys.exit("--lan needs --code (the code Bob printed)")
    print(f"# looking for Bob with code {a.code} (up to {a.timeout:.0f} s) ...", flush=True)
    found = lan.find(a.code, "bench", a.timeout, a.beacon_port)
    if found is None:
        sys.exit(lan.HINT.replace("--hub", "--peer"))
    a.peer = f"{found['host']}:{found['port']}"
    print(f"# found Bob at {a.peer}", flush=True)


def run_alice(a) -> int:
    if a.lan and not a.peer:
        find_peer(a)
    if not a.peer:
        sys.exit("Alice needs --peer host:port (or --lan --code CODE)")
    if a.task == "sign":
        row = sign_session(addr(a.peer), a.curve, a.rounds, parse_sets(a.set))
        report_row(a, row)
        return 0
    ch = net.connect(*addr(a.peer))
    ch.send({"task": a.task, "curve": a.curve})
    samples = bench.echo_alice(ch, a.rounds, a.payload)
    report(a, samples, ch.stats())
    ch.close()
    return 0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_matrix(a) -> int:
    """The original protocol, every variant on its own, then all speed-ups.

    One Paillier key per size is made first and reused, so the rows compare
    the signing, not the luck of the prime search (keygen_ms is reported once).
    """
    configs = config.variants_one_at_a_time() + [config.fastest()]
    if a.curve != "secp256k1":  # libsecp256k1 only knows secp256k1
        configs = list(dict.fromkeys(replace(c, curve="pure") for c in configs))
    for item in a.set:  # --set here filters: only rows with these values
        k, _, v = item.partition("=")
        configs = [c for c in configs if str(getattr(c, k)).lower() == v.lower()]
    bob = None
    if a.lan and not a.peer:
        find_peer(a)
    if a.peer:
        peer = addr(a.peer)
    else:
        peer = ("127.0.0.1", _free_port())
        bob = subprocess.Popen([sys.executable, "-m", "twoparty", "--role", "bob",
                                "--listen", f"{peer[0]}:{peer[1]}"],
                               stdout=subprocess.DEVNULL)
    out = a.out or f"benchmark/results/matrix-{datetime.date.today()}.csv"
    keys = {}
    try:
        for i, cfg in enumerate(configs, 1):
            bits = bench.paillier_bits(CURVES[a.curve], cfg)
            if bits not in keys:
                t0 = time.perf_counter()
                keys[bits] = paillier.keygen(bits)
                print(f"# Paillier key {bits} bit: {(time.perf_counter() - t0):.1f} s", flush=True)
            print(f"# [{i}/{len(configs)}] {cfg.label()}", flush=True)
            row = sign_session(peer, a.curve, a.rounds, cfg, keys[bits])
            a.out = out
            report_row(a, row)
    finally:
        if bob:
            bob.terminate()
    print(f"# written to {out}")
    return 0


def report_row(a, row: dict) -> None:
    row = {"time": datetime.datetime.now().isoformat(timespec="seconds"),
           "label": a.label, "task": a.task, "host": platform.node(), **row}
    print(json.dumps(row), flush=True)
    if a.out:
        bench.append_csv(a.out, row)


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
