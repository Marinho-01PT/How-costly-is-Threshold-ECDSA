"""Record every step of key generation, sharing, signing and verification.

    python -m twoparty.trace --curve toy|secp256k1|all --out web/data/
    python -m twoparty.trace --vectors tests/vectors.json

Writes one JSON file per curve for the learning page in web/. Each step holds
{id, section, title, description, who, inputs, formula, worked, result, status}
with the real values computed by ec.py, ecdsa_pure.py and sharing.py.

To add a protocol step (MtA, two-party signing), append a Step to STEPS with a
compute function, replacing its "planned" entry. web/js/steps.js holds the
same registry in JavaScript for the editable toy mode; tests/vectors.json
keeps the two in line.

Demo values are fixed or come from a seeded RNG, so they are NOT secret.
"""
import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .ec import CURVES, Curve
from .ecdsa_pure import message_hash, rand_scalar, sign_steps, verify_steps
from .sharing import combine, share

SCHEMA = 1


class StepError(ValueError):
    """A step cannot be computed with these values (e.g. s = 0 for this k)."""


SECTIONS = [
    {"id": "keygen", "title": "Key generation"},
    {"id": "sharing", "title": "Splitting the key"},
    {"id": "sign", "title": "Signing on one device"},
    {"id": "verify", "title": "Verification"},
    {"id": "mta", "title": "Multiplicative to additive (MtA)"},
    {"id": "twoparty", "title": "Signing with two devices"},
    {"id": "reuse", "title": "What goes wrong if k is reused"},
]


@dataclass(frozen=True)
class Step:
    id: str
    section: str
    title: str
    who: str        # signer, verifier, dealer, attacker, alice, bob, both
    description: str
    formula: str = ""
    # Same formula with {name} placeholders for the values in inputs/result
    # (or curve constants n, p, G). The page fills in the numbers.
    worked: str = ""
    # compute(curve, ctx) -> (inputs, result) or (inputs, result, worked);
    # the third value replaces the worked template. Writes results into ctx.
    # None marks a planned step that is not implemented yet.
    compute: Optional[Callable[[Curve, dict], tuple[dict, dict]]] = None


# ---- step functions ---------------------------------------------------------
# Each one reads earlier values from ctx and stores its own results there.

def _keygen_d(c, ctx):
    d = ctx["d"]
    if not 1 <= d < c.n:
        raise StepError("d must be between 1 and n - 1")
    return {}, {"d": d}


def _keygen_Q(c, ctx):
    ctx["Q"] = c.base_mul(ctx["d"])
    return {"d": ctx["d"], "G": c.G}, {"Q": ctx["Q"]}


def _share_d1(c, ctx):
    d1 = ctx["d1"]
    if not 0 <= d1 < c.n:
        raise StepError("d1 must be between 0 and n - 1")
    return {}, {"d1": d1}


def _share_d2(c, ctx):
    d1, ctx["d2"] = share(ctx["d"], n=c.n, d1=ctx["d1"])
    return {"d": ctx["d"], "d1": d1}, {"d2": ctx["d2"]}


def _share_check(c, ctx):
    return {"d1": ctx["d1"], "d2": ctx["d2"]}, {"d": combine(ctx["d1"], ctx["d2"], n=c.n)}


def _share_public(c, ctx):
    Q1, Q2 = c.base_mul(ctx["d1"]), c.base_mul(ctx["d2"])
    return {"d1": ctx["d1"], "d2": ctx["d2"]}, {"Q1": Q1, "Q2": Q2, "Q": c.add(Q1, Q2)}


def _sign_e(c, ctx):
    if "e" not in ctx:
        ctx["e"] = message_hash(c, ctx["message"].encode())
    if not 0 <= ctx["e"] < c.n:
        raise StepError("e must be between 0 and n - 1")
    if "message" in ctx:
        return {"m": ctx["message"]}, {"e": ctx["e"]}
    return {}, {"e": ctx["e"]}, "{e}  (hash given directly)"


def _sign_k(c, ctx):
    k = ctx["k"]
    if not 1 <= k < c.n:
        raise StepError("k must be between 1 and n - 1")
    # All signing values come from ecdsa_pure.sign_steps, the steps below only
    # show them one by one.
    try:
        ctx["sig"] = sign_steps(c, ctx["d"], ctx["e"], k)
    except ValueError as exc:
        raise StepError(str(exc)) from exc
    return {}, {"k": k}


def _sign_R(c, ctx):
    return {"k": ctx["k"], "G": c.G}, {"R": ctx["sig"].R}


def _sign_r(c, ctx):
    return {"R": ctx["sig"].R}, {"r": ctx["sig"].r}


def _sign_kinv(c, ctx):
    return {"k": ctx["k"]}, {"k_inv": ctx["sig"].k_inv}


def _sign_s(c, ctx):
    st = ctx["sig"]
    return ({"k_inv": st.k_inv, "e": st.e, "r": st.r, "d": ctx["d"]},
            {"s_raw": st.s_raw})


def _sign_lows(c, ctx):
    st = ctx["sig"]
    return {"s_raw": st.s_raw}, {"s": st.s, "flipped": st.flipped}


def _verify_w(c, ctx):
    ctx["ver"] = verify_steps(c, ctx["Q"], ctx["e"], (ctx["sig"].r, ctx["sig"].s))
    return {"s": ctx["sig"].s}, {"w": ctx["ver"].w}


def _verify_u1(c, ctx):
    return {"e": ctx["e"], "w": ctx["ver"].w}, {"u1": ctx["ver"].u1}


def _verify_u2(c, ctx):
    return {"r": ctx["sig"].r, "w": ctx["ver"].w}, {"u2": ctx["ver"].u2}


def _verify_P(c, ctx):
    v = ctx["ver"]
    return {"u1": v.u1, "u2": v.u2, "G": c.G, "Q": ctx["Q"]}, {"P": v.P}


def _verify_check(c, ctx):
    v = ctx["ver"]
    xP = v.P[0] % c.n if v.P else None
    return {"P": v.P, "r": ctx["sig"].r}, {"x_P": xP, "valid": v.valid}


def _reuse_sig2(c, ctx):
    e2 = ctx["e2"]
    if not 0 <= e2 < c.n:
        raise StepError("e2 must be between 0 and n - 1")
    if e2 == ctx["e"]:
        raise StepError("the second message needs a different hash e2")
    try:
        ctx["sig2"] = sign_steps(c, ctx["d"], e2, ctx["k"])
    except ValueError as exc:
        raise StepError(str(exc)) from exc
    return {"e2": e2, "k": ctx["k"], "d": ctx["d"]}, {"r": ctx["sig2"].r, "s2": ctx["sig2"].s}


def _reuse_k(c, ctx):
    """The attacker sees (r, s) and (r, s2) with the same r. Because of the
    low-s rule either s may have been flipped, so they try s - s2 and s + s2
    and both signs, and keep the guess that leads to the public key Q."""
    n, e, e2, r = c.n, ctx["e"], ctx["e2"], ctx["sig"].r
    s, s2 = ctx["sig"].s, ctx["sig2"].s
    r_inv = pow(r, -1, n)
    for op, den in (("-", (s - s2) % n), ("+", (s + s2) % n)):
        if den == 0:
            continue
        base = (e - e2) * pow(den, -1, n) % n
        for sign, k_guess in ((1, base), (-1, (-base) % n)):
            d_guess = (s * k_guess - e) * r_inv % n
            if c.base_mul(d_guess) == ctx["Q"]:
                ctx["k_found"], ctx["d_found"], ctx["r_inv"] = k_guess, d_guess, r_inv
                return ({"e": e, "e2": e2, "s": s, "s2": s2},
                        {"k_found": k_guess, "variant": f"{'' if sign == 1 else '-'}(e - e2) / (s {op} s2)"})
    raise StepError("no guess matched Q")  # cannot happen for a valid pair


def _reuse_d(c, ctx):
    return ({"s": ctx["sig"].s, "k_found": ctx["k_found"], "e": ctx["e"], "r": ctx["sig"].r},
            {"d_found": ctx["d_found"]})


def _reuse_check(c, ctx):
    return ({"d_found": ctx["d_found"], "G": c.G, "Q": ctx["Q"]},
            {"Q_found": c.base_mul(ctx["d_found"]), "match": ctx["d_found"] == ctx["d"]})


# ---- the registry -------------------------------------------------------------

STEPS: list[Step] = [
    Step("keygen.d", "keygen", "Choose the private key", "signer",
         "The private key d is a random number between 1 and n - 1. Whoever knows d can sign.",
         "d ∈ [1, n − 1]", "{d}", _keygen_d),
    Step("keygen.Q", "keygen", "Compute the public key", "signer",
         "Q is d copies of the base point G added together. Going from d to Q is easy, "
         "going back from Q to d is the hard problem that keeps the key safe.",
         "Q = d · G", "{Q} = {d} · {G}", _keygen_Q),

    Step("share.d1", "sharing", "Pick the first share", "dealer",
         "Instead of one device holding d, it is split into two parts. "
         "The first part d1 is a random number. It goes to Alice.",
         "d1 ∈ [0, n − 1] at random", "{d1}", _share_d1),
    Step("share.d2", "sharing", "Compute the second share", "dealer",
         "The second part is whatever is missing to reach d. It goes to Bob. "
         "Since d1 is random, d2 on its own also looks random.",
         "d2 = d − d1 mod n", "{d2} = {d} − {d1} mod {n}", _share_d2),
    Step("share.check", "sharing", "The shares add up to d", "both",
         "Only both parts together give back the key. Each part alone fits every possible d.",
         "d = d1 + d2 mod n", "{d} = {d1} + {d2} mod {n}", _share_check),
    Step("share.public", "sharing", "Public parts of the shares", "both",
         "Each device can publish d1 · G or d2 · G. They add up to the public key Q, "
         "without anyone learning d.",
         "Q1 = d1 · G,  Q2 = d2 · G,  Q = Q1 + Q2", "{Q1} + {Q2} = {Q}", _share_public),

    Step("sign.e", "sign", "Hash the message", "signer",
         "Signing works on a number, not on text. The message is hashed with SHA-256 "
         "and the result is reduced mod n.",
         "e = SHA-256(m) mod n", "{e} = SHA-256({m}) mod {n}", _sign_e),
    Step("sign.k", "sign", "Choose a nonce", "signer",
         "k is a fresh random number for every signature. It must stay secret and must "
         "never be used twice (see the last section).",
         "k ∈ [1, n − 1] at random", "{k}", _sign_k),
    Step("sign.R", "sign", "Compute the nonce point", "signer",
         "Same operation as for the public key, now with k.",
         "R = k · G", "{R} = {k} · {G}", _sign_R),
    Step("sign.r", "sign", "Take its x coordinate", "signer",
         "The first half of the signature is the x coordinate of R, reduced mod n.",
         "r = x(R) mod n", "{r} = x({R}) mod {n}", _sign_r),
    Step("sign.kinv", "sign", "Invert the nonce", "signer",
         "k⁻¹ is the number that gives 1 when multiplied with k mod n.",
         "k⁻¹ · k = 1 mod n", "{k_inv} · {k} = 1 mod {n}", _sign_kinv),
    Step("sign.s", "sign", "Compute s", "signer",
         "The second half of the signature mixes the hash, r and the private key.",
         "s = k⁻¹ · (e + r · d) mod n", "{s_raw} = {k_inv} · ({e} + {r} · {d}) mod {n}", _sign_s),
    Step("sign.lows", "sign", "Use the low form of s", "signer",
         "Both s and n − s verify. Bitcoin and libsecp256k1 accept only the smaller one, "
         "so if s is above n / 2 it is replaced by n − s.",
         "if s > n / 2:  s = n − s", "{s}", _sign_lows),

    Step("verify.w", "verify", "Invert s", "verifier",
         "The verifier knows Q, the message and (r, s), but not d or k.",
         "w = s⁻¹ mod n", "{w} = {s}⁻¹ mod {n}", _verify_w),
    Step("verify.u1", "verify", "First factor", "verifier", "",
         "u1 = e · w mod n", "{u1} = {e} · {w} mod {n}", _verify_u1),
    Step("verify.u2", "verify", "Second factor", "verifier", "",
         "u2 = r · w mod n", "{u2} = {r} · {w} mod {n}", _verify_u2),
    Step("verify.P", "verify", "Rebuild the nonce point", "verifier",
         "If the signature is honest, u1 · G + u2 · Q is the same point R the signer used, "
         "because u1 + u2 · d = k mod n.",
         "P = u1 · G + u2 · Q", "{P} = {u1} · {G} + {u2} · {Q}", _verify_P),
    Step("verify.check", "verify", "Compare with r", "verifier",
         "The signature is valid if the x coordinate of P matches r.",
         "x(P) mod n = r", "{x_P} = {r}", _verify_check),

    Step("mta", "mta", "Multiplicative to additive conversion", "both",
         "Alice holds a, Bob holds b. MtA turns the product a · b into two shares "
         "alpha + beta = a · b mod n without either side learning the other's input. "
         "Planned: we are waiting for the description from our supervisors."),
    Step("twoparty.sign", "twoparty", "Joint signature", "both",
         "Alice and Bob create k together and use MtA for the products of secrets, "
         "so they produce a normal (r, s) without ever putting d together. "
         "Planned: follows once MtA is in place."),

    Step("reuse.sig2", "reuse", "Sign a second message with the same k", "signer",
         "A buggy signer uses k again for another message. Both signatures have the same r, "
         "so anyone can see that k was reused.",
         "s2 = k⁻¹ · (e2 + r · d) mod n", "{s2} = {k}⁻¹ · ({e2} + {r} · {d}) mod {n}", _reuse_sig2),
    Step("reuse.k", "reuse", "Recover the nonce", "attacker",
         "Subtracting the two equations for s removes d. Because of the low-s rule the attacker "
         "does not know if s or s2 was flipped, so they try s − s2 and s + s2 with both signs "
         "and keep the guess that leads to Q.",
         "k = (e − e2) / (s − s2) mod n", "{k_found} = {variant} mod {n}", _reuse_k),
    Step("reuse.d", "reuse", "Recover the private key", "attacker",
         "With k known, the equation for s has only one unknown left: d.",
         "d = (s · k − e) · r⁻¹ mod n", "{d_found} = ({s} · {k_found} − {e}) · {r}⁻¹ mod {n}", _reuse_d),
    Step("reuse.check", "reuse", "Check against the public key", "attacker",
         "The recovered d gives the public key Q. The key is lost.",
         "d · G = Q", "{d_found} · {G} = {Q_found}", _reuse_check),
]


# ---- running and encoding -------------------------------------------------------

def encode(v):
    """Typed JSON value: ints as hex strings (JSON numbers lose precision)."""
    if isinstance(v, bool):
        return {"kind": "bool", "value": v}
    if isinstance(v, int):
        return {"kind": "int", "value": hex(v)}
    if isinstance(v, str):
        return {"kind": "text", "value": v}
    if v is None:
        return {"kind": "infinity"}
    if isinstance(v, tuple) and len(v) == 2:
        return {"kind": "point", "x": hex(v[0]), "y": hex(v[1])}
    raise TypeError(f"cannot encode {v!r}")


def run_steps(curve: Curve, values: dict) -> list[dict]:
    """Run the registry. values: d, d1, k, e2 and either message or e.

    A step that fails gets status "error"; the steps after it that need its
    values get status "blocked". Planned steps are always "planned".
    """
    ctx = dict(values)
    out, failed = [], None
    for st in STEPS:
        rec = {"id": st.id, "section": st.section, "title": st.title, "who": st.who,
               "description": st.description, "formula": st.formula, "worked": st.worked}
        if st.compute is None:
            out.append({**rec, "status": "planned", "inputs": {}, "result": {}})
            continue
        if failed:
            out.append({**rec, "status": "blocked", "inputs": {}, "result": {},
                        "message": f"needs the step '{failed}' to work first"})
            continue
        try:
            inputs, result, *worked = st.compute(curve, ctx)
        except StepError as exc:
            failed = st.title
            out.append({**rec, "status": "error", "inputs": {}, "result": {}, "message": str(exc)})
            continue
        if worked:
            rec["worked"] = worked[0]
        out.append({**rec, "status": "done",
                    "inputs": {k: encode(v) for k, v in inputs.items()},
                    "result": {k: encode(v) for k, v in result.items()}})
    return out


def curve_info(c: Curve) -> dict:
    return {"name": c.name, "p": hex(c.p), "a": hex(c.a), "b": hex(c.b),
            "G": encode(c.G), "n": hex(c.n), "bits": c.n.bit_length()}


def build_trace(curve: Curve, values: dict) -> dict:
    return {
        "schema": SCHEMA,
        "generated_by": "python -m twoparty.trace",
        "note": "Demo values, not secret. Educational code, not constant-time.",
        "curve": curve_info(curve),
        "params": {k: encode(v) for k, v in values.items()},
        "sections": SECTIONS,
        "steps": run_steps(curve, values),
    }


# Toy values are small and easy to follow by hand; secp256k1 values come from
# a seeded RNG so the file stays the same between runs.
# The second message for the nonce reuse demo is the first one plus " again".
TOY_DEFAULTS = {"d": 42, "d1": 100, "k": 17}


def default_values(curve: Curve, seed: int, message: str) -> dict:
    if curve.name == "toy":
        values = dict(TOY_DEFAULTS)
    else:
        rng = random.Random(seed)
        values = {name: rand_scalar(curve, rng) for name in ("d", "d1", "k")}
    e2 = message_hash(curve, (message + " again").encode())
    return {**values, "message": message, "e2": e2}


def build_vectors(seed: int = 7) -> dict:
    """Cases for the JavaScript check: the JS registry must reproduce every step."""
    toy = CURVES["toy"]
    rng = random.Random(seed)
    cases = [
        ("toy", {"d": 42, "d1": 100, "k": 17, "e": 8, "e2": 128}),
        ("toy", {"d": 1, "d1": 0, "k": 1, "e": 0, "e2": 1}),
        ("toy", {"d": 312, "d1": 312, "k": 312, "e": 312, "e2": 5}),
        # s = 0: e = -r*d mod n makes this k fail
        ("toy", {"d": 5, "d1": 3, "k": 17, "e": (-toy.base_mul(17)[0] % toy.n * 5) % toy.n, "e2": 1}),
        ("toy", {"d": 5, "d1": 3, "k": 17, "e": 9, "e2": 9}),   # same hash twice
        ("toy", {"d": 0, "d1": 3, "k": 17, "e": 9, "e2": 1}),   # invalid d
        ("toy", {"d": 5, "d1": 3, "k": 0, "e": 9, "e2": 1}),    # invalid k
    ]
    for _ in range(30):
        cases.append(("toy", {name: rng.randrange(1, toy.n) for name in ("d", "d1", "k", "e", "e2")}))
    for _ in range(2):
        n = CURVES["secp256k1"].n
        cases.append(("secp256k1", {name: rng.randrange(1, n) for name in ("d", "d1", "k", "e", "e2")}))
    return {
        "schema": SCHEMA,
        "generated_by": "python -m twoparty.trace --vectors",
        "curves": {name: curve_info(c) for name, c in CURVES.items()},
        "cases": [{"curve": name, "values": {k: hex(v) for k, v in vals.items()},
                   "steps": [_slim(st) for st in run_steps(CURVES[name], vals)]}
                  for name, vals in cases],
    }


def _slim(step: dict) -> dict:
    """Only what the JS has to reproduce: no titles or explanations."""
    keep = ("id", "status", "inputs", "result", "worked", "message")
    return {k: step[k] for k in keep if k in step}


def _write(path: Path, data: dict, indent: int | None = 1) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent, ensure_ascii=False) + "\n")
    print(f"wrote {path}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m twoparty.trace")
    p.add_argument("--curve", choices=[*CURVES, "all"], default="all")
    p.add_argument("--out", default="web/data/", help="folder for <curve>.json")
    p.add_argument("--message", default="hello")
    p.add_argument("--seed", type=int, default=1, help="seed for the secp256k1 demo values")
    for name in ("d", "d1", "k", "e2"):
        p.add_argument(f"--{name}", type=lambda t: int(t, 0), help=f"override {name}")
    p.add_argument("--vectors", help="write the JS test vectors to this file instead")
    a = p.parse_args(argv)

    if a.vectors:
        _write(Path(a.vectors), build_vectors(), indent=None)
        return 0
    names = list(CURVES) if a.curve == "all" else [a.curve]
    for name in names:
        c = CURVES[name]
        values = default_values(c, a.seed, a.message)
        values.update({k: getattr(a, k) for k in ("d", "d1", "k", "e2") if getattr(a, k) is not None})
        trace = build_trace(c, values)
        bad = [s for s in trace["steps"] if s["status"] in ("error", "blocked")]
        if bad:
            print(f"{name}: step '{bad[0]['title']}' failed: {bad[0]['message']}")
            return 1
        _write(Path(a.out) / f"{name}.json", trace)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
