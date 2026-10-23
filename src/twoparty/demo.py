"""Watch the two-party protocol step by step, in three terminals.

    python -m twoparty.demo observer --listen 127.0.0.1:5050    # start this first
    python -m twoparty.demo bob      --hub    127.0.0.1:5050
    python -m twoparty.demo alice    --hub    127.0.0.1:5050

The observer is the network: Alice and Bob both connect to it and it passes
every message on. Once both are there, it asks how to run the session:

    mode        study      toy curve, tiny Paillier key, beta' only 16 n^2:
                           small numbers and the formulas filled in, to calculate along
                toy        toy curve, Paillier and beta' as advised (B = n^2 * 2^40)
                secp256k1  the real curve, 2048-bit Paillier, about 2 s per signature
    pace        all        Enter in all three terminals
                observer   Enter only in the observer
                run        no waiting, everything runs through
    experiment  yes        Bob leaves out beta', Alice steals his key share

--mode, --pace and --experiment answer these questions up front.

Alice and Bob print every value they compute, the observer only what the
network sees. With --events FILE the observer also writes everything,
Alice's and Bob's inside view included, as JSON lines (values typed as in
trace.py): the data a UI can be built on.

Same code as the benchmark (protocol.py, mta.py), only with the show hook.
Not port 5000 on macOS: AirPlay Receiver listens there and never answers.
"""
import argparse
import json
import select
import time

from coincurve import PublicKey

from . import ecdsa_baseline, ecdsa_pure, mta, net, protocol
from .ec import CURVES, SECP256K1
from .trace import encode

MTA_ORDER = ("k1*gamma2", "gamma1*k2", "k1*d2", "d1*k2")

MODES = {
    "study": {"curve": "toy", "mask_bits": 4},
    "toy": {"curve": "toy", "mask_bits": mta.MASK_BITS},
    "secp256k1": {"curve": "secp256k1", "mask_bits": mta.MASK_BITS},
}
QUESTIONS = [
    ("mode", "Which mode?", {
        "study": "small numbers and the formulas filled in, to calculate along",
        "toy": "toy curve, Paillier and beta' as advised (B = n^2 * 2^40)",
        "secp256k1": "the real curve, 2048-bit Paillier, about 2 s per signature"}),
    ("pace", "Which pace?", {
        "all": "Enter in all three terminals",
        "observer": "Enter only here, in the observer",
        "run": "no waiting, everything runs through"}),
    ("experiment", "Experiment?", {
        "no": "normal protocol",
        "yes": "Bob leaves out beta', Alice steals his key share"}),
]

# The side that listens greets first, so the side that connects knows it
# reached the demo and not some other program on that port.
GREETING = {"hello": "twoparty demo"}
GREETING_TIMEOUT = 5.0


def addr(text: str) -> tuple[str, int]:
    host, port = text.rsplit(":", 1)
    return host, int(port)


def greet(ch) -> None:
    ch.send(GREETING)


def expect_greeting(ch, where: str) -> None:
    """Wait for the greeting, give up with a clear message instead of hanging."""
    ch.sock.settimeout(GREETING_TIMEOUT)
    try:
        msg = ch.recv()
    except (TimeoutError, ConnectionError, ValueError):
        msg = None
    finally:
        ch.sock.settimeout(None)
    if msg != GREETING:
        raise SystemExit(
            f"{where} does not answer like the demo. Is the observer running there, "
            "and did it start first? On macOS port 5000 belongs to AirPlay Receiver: "
            "use another port, e.g. 5050.")


def fmt(v, full: bool = False) -> str:
    """Numbers in full up to 40 digits, otherwise the start and the end."""
    if isinstance(v, bool) or v is None:
        return str(v)
    if isinstance(v, int):
        s = str(v)
        return s if full or len(s) <= 40 else f"{s[:12]}...{s[-12:]} ({len(s)} digits)"
    if isinstance(v, (tuple, list)):
        return "(" + ", ".join(fmt(x, full) for x in v) + ")"
    return repr(v)


def print_values(values: dict, full: bool) -> None:
    width = max((len(k) for k in values), default=0)
    for k, v in values.items():
        print(f"    {k:<{width}} = {fmt(v, full)}")


# ---- study mode: the formula of each step with the numbers filled in ---------

def explain(step: str, values: dict, v: dict, curve, mask_bits: int) -> list[str]:
    """v holds everything this party has seen so far (this step included)."""
    n = curve.n
    me = "1" if "k1" in v or "d1" in v else "2"
    share = "alpha" if me == "1" else "beta"  # this party's MtA shares
    out = []
    if step.startswith("1. pick"):
        out.append(f"Gamma{me} = gamma{me} * G = {v['gamma' + me]} * {fmt(curve.G)} "
                   "(point multiplication on the curve)")
    elif step.startswith("2."):
        k, g = v["k" + me], v["gamma" + me]
        x, y = v[f"{share}[k1*gamma2]"], v[f"{share}[gamma1*k2]"]
        raw = k * g + x + y
        out.append(f"delta{me} = {k}*{g} + {x} + {y} = {raw} = {raw % n} mod {n}")
    elif step.startswith("3."):
        k, d = v["k" + me], v["d" + me]
        x, y = v[f"{share}[k1*d2]"], v[f"{share}[d1*k2]"]
        raw = k * d + x + y
        out.append(f"sigma{me} = {k}*{d} + {x} + {y} = {raw} = {raw % n} mod {n}")
    elif step.startswith("4. R"):
        delta = v["delta"]
        inv = pow(delta, -1, n)
        Gamma = curve.add(v["Gamma1"], v["Gamma2"])
        out += [f"delta = {v['delta1']} + {v['delta2']} = {v['delta1'] + v['delta2']} = {delta} mod {n}",
                f"delta^-1 = {inv} mod {n}  (check: {delta}*{inv} = {delta * inv} = 1 mod {n})",
                f"R = {inv} * (Gamma1 + Gamma2) = {inv} * {fmt(Gamma)} = {fmt(v['R'])}",
                f"r = x(R) mod n = {v['R'][0]} mod {n} = {v['r']}"]
    elif step.startswith("5. send"):
        e, k, r, sg = v["e"], v["k" + me], v["r"], v["sigma" + me]
        raw = e * k + r * sg
        out.append(f"s{me} = e*k{me} + r*sigma{me} = {e}*{k} + {r}*{sg} = {raw} = {raw % n} mod {n}")
    elif step.startswith("5. s ="):
        s_raw = v["s_raw"]
        out.append(f"s = {v['s1']} + {v['s2']} = {v['s1'] + v['s2']} = {s_raw} mod {n}")
        if s_raw > n // 2:
            out.append(f"low s: {s_raw} > {n // 2}, so s = {n} - {s_raw} = {v['s']}")
        else:
            out.append(f"low s: {s_raw} <= {n // 2}, so s stays {s_raw}")
    elif step.startswith("MtA"):
        for key, val in values.items():
            name, _, tag = key.partition("[")
            tag = "[" + tag
            if name == "c_A" and "a" + tag in v:
                out.append(f"c_A = (1 + a*N) * r^N mod N^2 with a = {v['a' + tag]} "
                           "and a random r (Paillier, use a calculator)")
            elif name == "alpha":
                out.append(f"alpha = plain mod n = {v['plain' + tag]} mod {n} = {val}")
            elif name == "beta_prime":
                out.append(f"beta' is random in [0, B), B = n^2 * 2^{mask_bits} = "
                           f"{mta.mask_bound(n, mask_bits)}")
            elif name == "beta":
                out.append(f"beta = -beta' mod n = -{v['beta_prime' + tag]} mod {n} = {val}")
    return out


class Narrator:
    """The show hook of one party: prints each step, keeps every value,
    waits for Enter if asked to, and sends the step to the observer's event log."""

    def __init__(self, who: str, settings: dict, curve, full: bool, ch):
        self.who, self.curve, self.full = who, curve, full
        self.pause = settings["pace"] == "all"
        self.study = settings["mode"] == "study"
        self.mask_bits = settings["mask_bits"]
        self.ch = ch if settings["events"] else None
        self.values: dict = {}

    def __call__(self, step: str, values: dict) -> None:
        self.values.update(values)
        print(f"\n[{self.who}] {step}")
        print_values(values, self.full)
        if self.study:
            for line in explain(step, values, self.values, self.curve, self.mask_bits):
                print(f"    > {line}")
        if self.ch is not None:
            self.ch.send({"event": {"step": step,
                                    "values": {k: encode(x) for k, x in values.items()}}})
        if self.pause:
            input("    (Enter) ")


def check(who: str, curve, Q, msg: bytes, sig) -> None:
    ok = ecdsa_pure.verify(curve, Q, msg, sig)
    line = f"\n[{who}] signature {'valid' if ok else 'INVALID'} for Q (pure-Python verifier)"
    if curve is SECP256K1:
        lib = ecdsa_baseline.verify(PublicKey.from_point(*Q), msg, sig)
        line += f", libsecp256k1: {'valid' if lib else 'INVALID'}"
    print(line)


# ---- Alice and Bob: connect to the observer, get the settings from it --------

def join(a, who: str):
    ch = net.connect(*addr(a.hub))
    expect_greeting(ch, a.hub)
    ch.send({"role": who.lower()})
    print(f"[{who}] connected to the observer at {a.hub}, waiting for its settings ...",
          flush=True)
    settings = ch.recv()["settings"]
    curve = CURVES[settings["curve"]]
    print(f"[{who}] mode {settings['mode']}, curve {curve.name} (n = {fmt(curve.n, a.full)}), "
          f"pace {settings['pace']}"
          + (", EXPERIMENT: Bob leaves out beta'" if settings["experiment"] else ""))
    return ch, settings, curve, Narrator(who, settings, curve, a.full, ch)


def run_alice(a) -> int:
    ch, settings, curve, say = join(a, "Alice")
    key, d1, Q = protocol.setup_alice(ch, curve, show=say, mask_bits=settings["mask_bits"])
    Q2 = curve.add(Q, curve.neg(curve.base_mul(d1)))  # Bob's public share
    while True:
        text = a.message if a.message is not None else input(
            "\n[Alice] message to sign (empty: quit): ")
        if not text:
            break
        ch.send({"msg": text})
        print(f"[Alice] waiting for Bob to approve {text!r} ...")
        if not ch.recv()["approve"]:
            print("[Alice] Bob declined, nothing was signed.")
        else:
            sig = protocol.sign_alice(ch, curve, key, d1, text.encode(), show=say)
            check("Alice", curve, Q, text.encode(), sig)
            attack(say.values, d1, Q2, curve, a.full)
        if a.message is not None:
            break
    ch.close()
    return 0


def attack(v: dict, d1: int, Q2, curve, full: bool) -> None:
    """Alice tries to get d2 out of her MtA share for k1*d2, and checks it against Q2."""
    guess = mta.recover_b(v["alpha[k1*d2]"], v["k1"], curve.n)
    print("\n[Alice] attack attempt: d2 = alpha[k1*d2] * k1^-1 mod n")
    print_values({"guess": guess, "guess*G": curve.base_mul(guess), "Q2": Q2}, full)
    if curve.base_mul(guess) == Q2:
        print("    guess*G == Q2: Bob's key share is stolen. Full key d = d1 + d2 =",
              fmt((d1 + guess) % curve.n, full))
    else:
        print("    guess*G != Q2: wrong, beta' hid Bob's share.")


def run_bob(a) -> int:
    ch, settings, curve, say = join(a, "Bob")
    N, d2, Q = protocol.setup_bob(ch, curve, show=say, mask_bits=settings["mask_bits"])
    try:
        while True:
            text = ch.recv()["msg"]
            print(f"\n[Bob] Alice wants to sign {text!r}")
            ok = settings["pace"] == "run" or input(
                "[Bob] approve? [y/N] ").strip().lower() in ("y", "yes", "j", "ja")
            ch.send({"approve": ok})
            if ok:
                sig = protocol.sign_bob(ch, curve, N, d2, text.encode(), show=say,
                                        mask=not settings["experiment"],
                                        mask_bits=settings["mask_bits"])
                check("Bob", curve, Q, text.encode(), sig)
    except ConnectionError:
        print("\n[Bob] Alice left.")
    ch.close()
    return 0


# ---- the observer: the network in the middle, and the one who decides --------

class Wire:
    """Explains each message, and works out what anyone on the network can."""

    def __init__(self, curve):
        self.curve = curve
        self.mta = 0
        self.seen: dict = {}

    def note(self, sender: str, msg: dict) -> str:
        if "N" in msg:
            return "setup: Alice's Paillier public key N and her public key share Q1 = d1*G"
        if "Q" in msg:
            return "setup: Bob's public key share Q2 = d2*G"
        if "msg" in msg:
            return "the message Alice wants to sign, in plain text"
        if "approve" in msg:
            return "Bob's answer: " + ("approved" if msg["approve"] else "declined")
        if "Gamma" in msg:
            if sender == "Alice":  # a new attempt starts
                self.mta, self.seen = 0, {}
            self.seen["Gamma" + sender] = tuple(msg["Gamma"])
            return f"{sender}'s Gamma = gamma*G, a public point (gamma stays hidden)"
        if "c_A" in msg:
            return (f"MtA {self._mta_name()}: c_A = Enc(a), Alice's input encrypted, "
                    "only she can decrypt")
        if "c_B" in msg:
            name = self._mta_name()
            self.mta += 1
            return f"MtA {name}: c_B = Enc(a*b + beta'), only Alice can decrypt"
        if "delta" in msg:
            self.seen["delta" + sender] = msg["delta"]
            return f"{sender}'s delta share, a share of k*gamma (gamma masks k)"
        if "s" in msg:
            self.seen["s" + sender] = msg["s"]
            return f"{sender}'s share of s"
        return "unknown message"

    def _mta_name(self) -> str:
        return MTA_ORDER[self.mta] if self.mta < len(MTA_ORDER) else "?"

    def what_we_know(self) -> dict:
        """With both deltas the network can compute R and r, with both s shares
        the signature. All of that becomes public anyway. k and d never show up."""
        c, s = self.curve, self.seen
        if "deltaBob" not in s or "deltaAlice" not in s:
            return {}
        n = c.n
        delta = (s["deltaAlice"] + s["deltaBob"]) % n
        if delta == 0:
            return {"delta": 0}
        R = c.mul(pow(delta, -1, n), c.add(s["GammaAlice"], s["GammaBob"]))
        out = {"delta": delta, "R": R, "r": R[0] % n}
        if "sAlice" in s and "sBob" in s:
            sig_s = (s["sAlice"] + s["sBob"]) % n
            out["s"] = n - sig_s if sig_s > n // 2 else sig_s
        return out


class EventLog:
    """--events FILE: one JSON line per event, for a UI. who is alice, bob or network."""

    def __init__(self, path):
        self.f = open(path, "w") if path else None
        self.i = 0

    def write(self, who: str, step: str, values: dict) -> None:
        if self.f is None:
            return
        self.i += 1
        self.f.write(json.dumps({"i": self.i, "time": round(time.time(), 3), "who": who,
                                 "step": step, "values": values}) + "\n")
        self.f.flush()


def _typed(v):
    """Network values come as JSON; points arrive as lists."""
    return encode(tuple(v) if isinstance(v, list) else v)


def choose(question: str, options: dict, given) -> str:
    """Ask in the terminal, unless the answer was given on the command line."""
    keys = list(options)
    if given is not None:
        print(f"[network] {question} {given} ({options[given]})")
        return given
    print(f"\n[network] {question}")
    for i, k in enumerate(keys, 1):
        print(f"    [{i}] {k:<10} {options[k]}")
    while True:
        ans = input("    choose (Enter = 1): ").strip().lower()
        if ans == "":
            return keys[0]
        if ans.isdigit() and 1 <= int(ans) <= len(keys):
            return keys[int(ans) - 1]
        if ans in options:
            return ans


def run_observer(a) -> int:
    srv = net.listen(*addr(a.listen))
    print(f"[network] waiting for Alice and Bob on {a.listen} ...", flush=True)
    peers = {}
    while len(peers) < 2:
        ch = net.accept(srv)
        greet(ch)
        role = ch.recv().get("role")
        if role not in ("alice", "bob") or role in peers:
            ch.close()
            continue
        peers[role] = ch
        print(f"[network] {role.capitalize()} is connected.", flush=True)
    srv.close()

    answers = {key: choose(q, opts, getattr(a, key)) for key, q, opts in QUESTIONS}
    settings = {"mode": answers["mode"], **MODES[answers["mode"]], "pace": answers["pace"],
                "experiment": answers["experiment"] == "yes", "events": bool(a.events)}
    log = EventLog(a.events)
    log.write("network", "settings", {k: encode(v) for k, v in settings.items()})
    for ch in peers.values():
        ch.send({"settings": settings})
    print("[network] settings sent, Alice and Bob talk through me now."
          + (f" Event log: {a.events}" if a.events else ""), flush=True)

    alice, bob = peers["alice"], peers["bob"]
    route = {alice.sock: (alice, bob, "Alice", "Bob"), bob.sock: (bob, alice, "Bob", "Alice")}
    wire = Wire(CURVES[settings["curve"]])
    count = 0
    try:
        while True:
            ready, _, _ = select.select(list(route), [], [])
            for sock in ready:
                src, dst, sender, receiver = route[sock]
                msg = src.recv()
                if "event" in msg:  # Alice's or Bob's inside view, only for the log
                    log.write(sender.lower(), msg["event"]["step"], msg["event"]["values"])
                    continue
                count += 1
                note = wire.note(sender, msg)
                print(f"\n[network] #{count} {sender} -> {receiver}: {note}")
                print_values(msg, a.full)
                log.write("network", f"{sender} -> {receiver}: {note}",
                          {k: _typed(v) for k, v in msg.items()})
                known = wire.what_we_know()
                if known and ("s" in msg or "delta" in msg):
                    print("    anyone on the network can now compute:")
                    print_values(known, a.full)
                if settings["pace"] != "run":
                    input(f"    (Enter: pass on to {receiver}) ")
                dst.send(msg)
    except ConnectionError:
        print("\n[network] connection closed.")
    alice.close()
    bob.close()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m twoparty.demo", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("role", choices=["observer", "alice", "bob"])
    p.add_argument("--listen", help="observer: host:port to wait on, e.g. 127.0.0.1:5050")
    p.add_argument("--hub", help="alice, bob: host:port of the observer")
    p.add_argument("--mode", choices=list(MODES), help="observer: skip the question")
    p.add_argument("--pace", choices=["all", "observer", "run"], help="observer: skip the question")
    p.add_argument("--experiment", choices=["no", "yes"], help="observer: skip the question")
    p.add_argument("--events", help="observer: write every event as JSON lines to this file")
    p.add_argument("--message", help="alice: sign this one message, then quit")
    p.add_argument("--full", action="store_true", help="print long numbers in full")
    a = p.parse_args(argv)
    if a.role == "observer":
        if not a.listen:
            p.error("the observer needs --listen host:port")
        return run_observer(a)
    if not a.hub:
        p.error(f"{a.role} needs --hub host:port (the observer)")
    return run_alice(a) if a.role == "alice" else run_bob(a)


if __name__ == "__main__":
    raise SystemExit(main())
