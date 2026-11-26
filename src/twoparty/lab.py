"""The building-block lab: what the web interface (ui_server.py) runs.

Two things, both with real Alice and Bob parties over a socket:

  study(...)  ONE signature, recorded step by step. Every show() call of
              protocol.py and mta.py becomes a step, every message on the
              channel becomes a message event, each with the party, the time
              spent and the building-block rows that were at work.
  Job(...)    the benchmark: N signatures per configuration, one CSV row each
              (bench.sign_alice), streamed to the page as they finish.

The rows come from config.ROWS. A row is "live" when Config has a field of
that name; otherwise its variants are shown as planned. So new rows appear in
the interface as soon as config.py has them, without touching this file.
"""
import datetime
import json
import re
import subprocess
import sys
import threading
import time
from dataclasses import fields, replace
from pathlib import Path

from . import bench, config, ec_libsecp, ecdsa_baseline, ecdsa_pure, mta, net, paillier, protocol
from .config import Config
from .ec import CURVES

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "benchmark" / "results"


# ---- rows ---------------------------------------------------------------------

def _label(v) -> str:
    if isinstance(v, bool):
        return config.LABELS.get(v, str(v))
    if isinstance(v, int):
        return f"{v} bit"
    return config.LABELS.get(v, str(v))


def rows() -> list[dict]:
    """config.ROWS for the page: one entry per building block."""
    live = {f.name for f in fields(Config)}
    base = Config()
    out = []
    for name, title, variants, planned in config.ROWS:
        is_live = name in live
        out.append({
            "field": name, "title": title, "live": is_live,
            "default": getattr(base, name) if is_live else variants[0],
            "variants": [{"value": v, "label": _label(v), "planned": False} for v in variants],
            "planned": [{"value": v, "label": _label(v), "planned": True} for v in planned],
        })
    return out


def curves() -> list[dict]:
    return [{"name": c.name, "bits": c.n.bit_length()} for c in CURVES.values()]


def make_config(d: dict | None, curve_name: str) -> Config:
    """Config from the page. The page may send rows Config does not know (planned)."""
    cfg = Config.from_dict(d)
    cfg.check_curve(curve_name)
    return cfg


# ---- which building block is at work in a step ------------------------------

# Matched against the step text from protocol.py and mta.py, first match wins.
# Rows that do not exist (yet) are simply never highlighted.
_STEP_ROWS = [
    (r"^\d\. received", []),            # only a message arrived, nothing computed
    (r"setup: Paillier", ["paillier_bits", "curve", "bignum"]),
    (r"setup:", ["curve"]),
    (r"Enc\(a\)", ["mta", "paillier_enc", "bignum", "paillier_bits"]),
    (r"Enc\(beta'\)|c_A\^b", ["mta", "paillier_enc", "bignum", "mask", "paillier_bits"]),
    (r"Dec\(c_B\)", ["mta", "paillier_dec", "bignum", "paillier_bits"]),
    (r"pick k|Gamma|R = |verify", ["curve"]),
    (r"delta\d = |sigma\d = ", ["mta"]),
]


def step_rows(step: str) -> list[str]:
    for pattern, rs in _STEP_ROWS:
        if re.search(pattern, step):
            return rs
    return []


def _short_party_step(step: str) -> str:
    return step


def _jsonable(v):
    """Big ints as strings (JavaScript numbers lose digits), points as lists."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return round(v, 4)
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    return str(v)


# ---- study mode -------------------------------------------------------------

class _Recorder:
    """Collects steps and messages of both parties in time order."""

    def __init__(self):
        self.events = []
        self.lock = threading.Lock()
        self.last = {}      # party -> time of its previous event
        self.t0 = time.perf_counter()

    def add(self, party: str, kind: str, **data):
        now = time.perf_counter()
        with self.lock:
            spent = (now - self.last.get(party, self.t0)) * 1000
            self.last[party] = now
            self.events.append({"t": now, "party": party, "kind": kind,
                                "spent_ms": round(spent, 3), **data})

    def hook(self, party: str):
        def show(step, values):
            self.add(party, "step", step=step, rows=step_rows(step), values=_jsonable(values))
        return show


class _RecChannel:
    """A net.Channel that also reports every message it sends."""

    def __init__(self, ch: net.Channel, party: str, rec: _Recorder, rows_: list[str],
                 mark_recv: bool = False):
        self.ch, self.party, self.rec, self.rows = ch, party, rec, rows_
        self.mark_recv = mark_recv  # remote study: lets merge() put both sides in order

    def send(self, obj):
        before = self.ch.sent_bytes
        self.ch.send(obj)
        self.rec.add(self.party, "message", to="bob" if self.party == "alice" else "alice",
                     keys=list(obj), bytes=self.ch.sent_bytes - before,
                     values=_jsonable(obj), rows=self.rows)

    def recv(self):
        obj = self.ch.recv()
        if self.mark_recv:
            self.rec.add(self.party, "recv")
        return obj

    def __getattr__(self, name):
        return getattr(self.ch, name)


_KEYS: dict[int, paillier.Key] = {}
_KEYS_LOCK = threading.Lock()


def paillier_key(bits: int) -> paillier.Key:
    """One key per size for the lifetime of the server (keygen takes seconds)."""
    with _KEYS_LOCK:
        if bits not in _KEYS:
            _KEYS[bits] = paillier.keygen(bits)
        return _KEYS[bits]


def _bob_side(raw: net.Channel, cfg: Config, pcurve, msg: bytes, rec: _Recorder,
              mark_recv: bool = False) -> tuple[tuple[int, int], int]:
    """Bob's part of one recorded signature. Returns (signature, d2)."""
    ch = _RecChannel(raw, "bob", rec, ["wire", "flow"], mark_recv)
    reuse, batched = cfg.mta == "reuse", cfg.flow == "batched"
    c_d1 = None
    if reuse:
        N, d2, _, c_d1 = protocol.setup_bob(ch, pcurve, show=rec.hook("bob"), reuse=True)
    else:
        N, d2, _ = protocol.setup_bob(ch, pcurve, show=rec.hook("bob"))
    ops = paillier.ops_for(cfg, N)
    if cfg.paillier_enc == "precomputed":
        ops.precompute(4)
    sig = protocol.sign_bob(ch, pcurve, N, d2, msg, show=rec.hook("bob"), mask=cfg.mask,
                            ops=ops, reuse=reuse, batched=batched, c_d1=c_d1)
    return sig, d2


def _alice_side(raw: net.Channel, cfg: Config, pcurve, key, msg: bytes, rec: _Recorder,
                mark_recv: bool = False):
    """Alice's part. Returns (signature, public key Q, milliseconds)."""
    ch = _RecChannel(raw, "alice", rec, ["wire", "flow"], mark_recv)
    reuse, batched = cfg.mta == "reuse", cfg.flow == "batched"
    t_start = time.perf_counter()
    key, d1, Q = protocol.setup_alice(ch, pcurve, key=key, show=rec.hook("alice"), reuse=reuse)
    ops = paillier.ops_for(cfg, key.N, key)
    if cfg.paillier_enc == "precomputed":
        ops.precompute(4)
    sig = protocol.sign_alice(ch, pcurve, key, d1, msg, show=rec.hook("alice"), ops=ops,
                              reuse=reuse, batched=batched)
    return sig, Q, (time.perf_counter() - t_start) * 1000


def merge(alice: list[dict], bob: list[dict]) -> list[dict]:
    """Put the events of two machines in an order that respects every message.

    Their clocks are not comparable, so time cannot order them. Instead each
    side marks every message it receives ("recv"); a side may only go past
    its k-th recv once the other side's k-th message is placed. The markers
    are dropped from the result.
    """
    queues = {"alice": list(alice), "bob": list(bob)}
    other = {"alice": "bob", "bob": "alice"}
    sent = {"alice": 0, "bob": 0}
    got = {"alice": 0, "bob": 0}
    out = []
    while queues["alice"] or queues["bob"]:
        moved = False
        for party in ("alice", "bob"):
            q = queues[party]
            while q:
                e = q[0]
                if e["kind"] == "recv":
                    if sent[other[party]] <= got[party]:
                        break           # wait for the other side's message
                    got[party] += 1
                    q.pop(0)
                    moved = True
                    continue
                if e["kind"] == "message":
                    sent[party] += 1
                out.append(q.pop(0))
                moved = True
        if not moved:                   # should not happen; keep everything
            out += queues["alice"] + queues["bob"]
            break
    return [e for e in out if e["kind"] != "recv"]


def serve_study(raw: net.Channel, hello: dict) -> dict:
    """Bob's side of a study run for a partner on another machine (pairing.py).

    Runs one recorded signature as Bob, then sends his events back so the
    partner's page can show both sides. Returns a short summary for Bob's page.
    """
    cfg = Config.from_dict(hello.get("config"))
    curve = CURVES[hello["curve"]]
    pcurve = ec_libsecp.resolve(curve, cfg.curve)
    raw.set_format(cfg.wire)
    rec = _Recorder()
    sig, d2 = _bob_side(raw, cfg, pcurve, hello["message"].encode(), rec, mark_recv=True)
    for e in rec.events:
        e["t"] = round((e["t"] - rec.t0) * 1000, 3)
    # d2 only goes back in the experiment, to prove that Alice really stole it.
    raw.send({"events": rec.events, "d2": None if cfg.mask else str(d2)})
    return {"label": cfg.label(), "curve": hello["curve"], "message": hello["message"],
            "signature": _jsonable(sig),
            "steps": [{"step": e.get("step") or f"sends {', '.join(e['keys'])} to Alice",
                       "spent_ms": e["spent_ms"]}
                      for e in rec.events if e["kind"] in ("step", "message")]}


def study(cfg: Config, curve_name: str = "toy", message: str = "Alice and Bob send 1 coin to Carol",
          peer: tuple[str, int] | None = None, partner: str = "") -> dict:
    """One real signature, every step of both parties recorded.

    Without peer both parties run in this process. With peer, Bob is the
    partner's laptop (pairing.py): it signs as Bob and sends its events back.
    """
    curve = CURVES[curve_name]
    cfg.check_curve(curve_name)
    pcurve = ec_libsecp.resolve(curve, cfg.curve)
    msg = message.encode()
    key = paillier_key(bench.paillier_bits(curve, cfg))
    rec = _Recorder()
    out: dict = {}
    if peer is None:
        srv = net.listen("127.0.0.1", 0)
        port = srv.getsockname()[1]

        def bob_thread():
            raw_b = net.accept(srv)
            raw_b.set_format(cfg.wire)
            try:
                out["bob"], out["d2"] = _bob_side(raw_b, cfg, pcurve, msg, rec)
            except BaseException as exc:  # reported on Alice's side
                out["error"] = exc
            finally:
                raw_b.close()

        t = threading.Thread(target=bob_thread, daemon=True)
        t.start()
        raw = net.connect("127.0.0.1", port)
        raw.set_format(cfg.wire)
        try:
            sig, Q, total_ms = _alice_side(raw, cfg, pcurve, key, msg, rec)
        finally:
            raw.close()
            t.join(timeout=60)
            srv.close()
        if "error" in out:
            raise out["error"]
        events = sorted(rec.events, key=lambda e: e["t"])
    else:
        raw = net.connect(*peer)
        try:
            raw.send({"task": "study", "curve": curve_name, "config": cfg.to_dict(),
                      "message": message})
            raw.set_format(cfg.wire)
            sig, Q, total_ms = _alice_side(raw, cfg, pcurve, key, msg, rec, mark_recv=True)
            report = raw.recv()
        finally:
            raw.close()
        if report.get("d2") is not None:
            out["d2"] = int(report["d2"])
        for e in rec.events:
            e["t"] = (e["t"] - rec.t0) * 1000
        for e in report["events"]:
            e["remote"] = True
        events = merge(rec.events, report["events"])
        for i, e in enumerate(events):
            e["t"] = i        # order only; the two clocks are not comparable
    # Verification: normal ECDSA, with the chosen curve variant.
    t1 = time.perf_counter()
    if cfg.curve == "libsecp256k1":
        from coincurve import PublicKey
        valid = ecdsa_baseline.verify(PublicKey.from_point(*Q), msg, sig)
    else:
        valid = ecdsa_pure.verify(curve, Q, msg, sig)
    events.append({"t": events[-1]["t"] if events else 0, "party": "verifier", "kind": "step",
                   "step": "verify: anyone checks (r, s) against Q", "rows": ["curve"],
                   "values": _jsonable({"r": sig[0], "s": sig[1], "Q": Q, "valid": valid}),
                   "spent_ms": round((time.perf_counter() - t1) * 1000, 3)})
    t_first = events[0]["t"] if events else 0
    for i, e in enumerate(events):
        t = e.pop("t")
        e["at_ms"] = None if peer else round((t - t_first) * 1000, 3)
        e["index"] = i
    stolen = None
    if not cfg.mask:
        # The experiment: Alice reads d2 out of her MtA share for k1*d2.
        view = {}
        for e in events:
            if e["party"] == "alice" and e["kind"] == "step":
                view.update(e["values"])
        if "alpha[k1*d2]" in view and "k1" in view:
            stolen = mta.recover_b(int(view["alpha[k1*d2]"]), int(view["k1"]), curve.n)
    sign_msgs = [e for e in events if e["kind"] == "message"]
    return {
        "config": cfg.to_dict(), "label": cfg.label(), "curve": curve_name,
        "curve_bits": curve.n.bit_length(), "message": message,
        "bob": f"{partner} ({peer[0]})" if peer else "this laptop",
        "signature": _jsonable(sig), "public_key": _jsonable(Q), "valid": valid,
        "total_ms": round(total_ms, 3), "messages": len(sign_msgs),
        "signing_messages": len(sign_msgs) - 2,   # 2 belong to the setup
        "bytes": sum(e["bytes"] for e in sign_msgs),
        "stolen_d2": None if stolen is None else str(stolen),
        "stolen_ok": None if stolen is None else stolen == out.get("d2"),
        "events": events,
    }


# ---- benchmark mode -----------------------------------------------------------

def configs_for(kind: str, cfg: Config, curve_name: str) -> list[Config]:
    """current: just cfg. matrix: original + every variant alone. together: all speed-ups."""
    if kind == "current":
        out = [cfg]
    elif kind == "together":
        out = [Config(), config.fastest()]
    else:
        out = config.variants_one_at_a_time() + [config.fastest()]
    if curve_name != "secp256k1":
        out = [replace(c, curve="pure") for c in out]
    return list(dict.fromkeys(out))


class _LocalBob:
    """One Bob process for all benchmark runs of the server, started on demand."""

    def __init__(self):
        self.proc = None
        self.port = None
        self.lock = threading.Lock()

    def address(self) -> tuple[str, int]:
        with self.lock:
            if self.proc is None or self.proc.poll() is not None:
                import socket
                with socket.socket() as s:
                    s.bind(("127.0.0.1", 0))
                    self.port = s.getsockname()[1]
                self.proc = subprocess.Popen(
                    [sys.executable, "-m", "twoparty", "--role", "bob",
                     "--listen", f"127.0.0.1:{self.port}"],
                    stdout=subprocess.DEVNULL, cwd=str(ROOT))
            return "127.0.0.1", self.port

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()


LOCAL_BOB = _LocalBob()


def parse_peer(text: str | None) -> tuple[str, int] | None:
    if not text:
        return None
    host, _, port = text.strip().rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("peer must be host:port")
    return host, int(port)


class Job:
    """A benchmark run in a thread. events grows; listeners wait on cond."""

    def __init__(self, configs: list[Config], curve_name: str, rounds: int, peer=None, label="lab"):
        self.configs, self.curve_name, self.rounds = configs, curve_name, rounds
        self.peer, self.label = peer, label
        self.events: list[dict] = []
        self.rows: list[dict] = []
        self.cond = threading.Condition()
        self.done = False
        self.csv_path: Path | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _emit(self, ev: dict):
        with self.cond:
            self.events.append(ev)
            self.cond.notify_all()

    def _run(self):
        try:
            peer = self.peer or LOCAL_BOB.address()
            curve = CURVES[self.curve_name]
            stamp = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
            self.csv_path = RESULTS / f"lab-{stamp}.csv"
            self._emit({"type": "start", "total": len(self.configs), "rounds": self.rounds,
                        "peer": f"{peer[0]}:{peer[1]}", "csv": str(self.csv_path.relative_to(ROOT))})
            for i, cfg in enumerate(self.configs, 1):
                bits = bench.paillier_bits(curve, cfg)
                self._emit({"type": "running", "i": i, "label": cfg.label(),
                            "keygen": bits not in _KEYS})
                key = paillier_key(bits)
                row = self._session(peer, cfg, key)
                row = {"time": datetime.datetime.now().isoformat(timespec="seconds"),
                       "label": self.label, "task": "lab", "peer": f"{peer[0]}:{peer[1]}", **row}
                self.rows.append(row)
                bench.append_csv(str(self.csv_path), row)
                self._emit({"type": "row", "i": i, "row": row})
            self._emit({"type": "done"})
        except Exception as exc:  # shown on the page
            self._emit({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        finally:
            with self.cond:
                self.done = True
                self.cond.notify_all()

    def _session(self, peer, cfg: Config, key) -> dict:
        ch = net.connect(*peer)
        try:
            ch.send({"task": "sign", "curve": self.curve_name, "rounds": self.rounds,
                     "config": cfg.to_dict()})
            ch.set_format(cfg.wire)
            return bench.sign_alice(ch, CURVES[self.curve_name], self.rounds, cfg, key)
        finally:
            ch.close()


def dumps(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str)
