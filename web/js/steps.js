// The step registry in JavaScript. Mirrors STEPS in src/twoparty/trace.py
// for the editable toy mode: same ids, same values, same error messages.
// Titles, explanations and formulas are not repeated here; they come from the
// JSON written by Python. tests/js/vectors.test.mjs checks every step.
//
// To add a step (MtA, two-party signing): add a compute function under the
// same id as in trace.py. An id without a function here counts as planned.

import { inv, mod, samePoint } from "./ec.js";

export class StepError extends Error {}

function signSteps(c, d, e, k) {
  const n = c.n;
  if (k < 1n || k >= n) throw new StepError("k must be in [1, n-1]");
  const R = c.baseMul(k);
  const r = mod(R[0], n);
  if (r === 0n) throw new StepError("r = 0 for this k, pick another k");
  const kInv = inv(k, n);
  const sRaw = mod(kInv * (e + r * d), n);
  if (sRaw === 0n) throw new StepError("s = 0 for this k, pick another k");
  const flipped = sRaw > n / 2n;
  return { e, k, R, r, kInv, sRaw, s: flipped ? n - sRaw : sRaw, flipped };
}

const inRange = (v, lo, hi, msg) => {
  if (v < lo || v > hi) throw new StepError(msg);
};

// id -> (curve, ctx) => [inputs, result, worked?]
export const COMPUTE = {
  "keygen.d": (c, x) => {
    inRange(x.d, 1n, c.n - 1n, "d must be between 1 and n - 1");
    return [{}, { d: x.d }];
  },
  "keygen.Q": (c, x) => {
    x.Q = c.baseMul(x.d);
    return [{ d: x.d, G: c.G }, { Q: x.Q }];
  },
  "share.d1": (c, x) => {
    inRange(x.d1, 0n, c.n - 1n, "d1 must be between 0 and n - 1");
    return [{}, { d1: x.d1 }];
  },
  "share.d2": (c, x) => {
    x.d2 = mod(x.d - x.d1, c.n);
    return [{ d: x.d, d1: x.d1 }, { d2: x.d2 }];
  },
  "share.check": (c, x) => [{ d1: x.d1, d2: x.d2 }, { d: mod(x.d1 + x.d2, c.n) }],
  "share.public": (c, x) => {
    const Q1 = c.baseMul(x.d1), Q2 = c.baseMul(x.d2);
    return [{ d1: x.d1, d2: x.d2 }, { Q1, Q2, Q: c.add(Q1, Q2) }];
  },
  "sign.e": (c, x) => {
    // The page always passes e directly (no hashing in the browser).
    inRange(x.e, 0n, c.n - 1n, "e must be between 0 and n - 1");
    return [{}, { e: x.e }, "{e}  (hash given directly)"];
  },
  "sign.k": (c, x) => {
    inRange(x.k, 1n, c.n - 1n, "k must be between 1 and n - 1");
    x.sig = signSteps(c, x.d, x.e, x.k);
    return [{}, { k: x.k }];
  },
  "sign.R": (c, x) => [{ k: x.k, G: c.G }, { R: x.sig.R }],
  "sign.r": (c, x) => [{ R: x.sig.R }, { r: x.sig.r }],
  "sign.kinv": (c, x) => [{ k: x.k }, { k_inv: x.sig.kInv }],
  "sign.s": (c, x) => [{ k_inv: x.sig.kInv, e: x.e, r: x.sig.r, d: x.d }, { s_raw: x.sig.sRaw }],
  "sign.lows": (c, x) => [{ s_raw: x.sig.sRaw }, { s: x.sig.s, flipped: x.sig.flipped }],
  "verify.w": (c, x) => {
    const n = c.n, { r, s } = x.sig;
    const w = inv(s, n), u1 = mod(x.e * w, n), u2 = mod(r * w, n);
    const P = c.add(c.baseMul(u1), c.mul(u2, x.Q));
    x.ver = { w, u1, u2, P, valid: P !== null && mod(P[0], n) === r };
    return [{ s }, { w }];
  },
  "verify.u1": (c, x) => [{ e: x.e, w: x.ver.w }, { u1: x.ver.u1 }],
  "verify.u2": (c, x) => [{ r: x.sig.r, w: x.ver.w }, { u2: x.ver.u2 }],
  "verify.P": (c, x) => [{ u1: x.ver.u1, u2: x.ver.u2, G: c.G, Q: x.Q }, { P: x.ver.P }],
  "verify.check": (c, x) => {
    const P = x.ver.P;
    return [{ P, r: x.sig.r }, { x_P: P ? mod(P[0], c.n) : null, valid: x.ver.valid }];
  },
  "reuse.sig2": (c, x) => {
    inRange(x.e2, 0n, c.n - 1n, "e2 must be between 0 and n - 1");
    if (x.e2 === x.e) throw new StepError("the second message needs a different hash e2");
    x.sig2 = signSteps(c, x.d, x.e2, x.k);
    return [{ e2: x.e2, k: x.k, d: x.d }, { r: x.sig2.r, s2: x.sig2.s }];
  },
  "reuse.k": (c, x) => {
    const n = c.n, { e, e2 } = x, r = x.sig.r, s = x.sig.s, s2 = x.sig2.s;
    const rInv = inv(r, n);
    for (const [op, den] of [["−", mod(s - s2, n)], ["+", mod(s + s2, n)]]) {
      if (den === 0n) continue;
      const base = mod((e - e2) * inv(den, n), n);
      for (const [sign, kGuess] of [[1, base], [-1, mod(-base, n)]]) {
        const dGuess = mod((s * kGuess - e) * rInv, n);
        if (samePoint(c.baseMul(dGuess), x.Q)) {
          Object.assign(x, { kFound: kGuess, dFound: dGuess });
          const minus = sign === 1 ? "" : "−";
          return [{ e, e2, s, s2 }, { k_found: kGuess },
            `{k_found} = ${minus}({e} − {e2}) / ({s} ${op} {s2}) mod {n}`];
        }
      }
    }
    throw new StepError("no guess matched Q");
  },
  "reuse.d": (c, x) => [{ s: x.sig.s, k_found: x.kFound, e: x.e, r: x.sig.r }, { d_found: x.dFound }],
  "reuse.check": (c, x) => [
    { d_found: x.dFound, G: c.G, Q: x.Q },
    { Q_found: c.baseMul(x.dFound), match: x.dFound === x.d },
  ],
};

// Same typed values as trace.encode in Python.
export function encode(v) {
  if (typeof v === "boolean") return { kind: "bool", value: v };
  if (typeof v === "bigint") return { kind: "int", value: "0x" + v.toString(16) };
  if (typeof v === "string") return { kind: "text", value: v };
  if (v === null) return { kind: "infinity" };
  if (Array.isArray(v) && v.length === 2) {
    return { kind: "point", x: "0x" + v[0].toString(16), y: "0x" + v[1].toString(16) };
  }
  throw new TypeError(`cannot encode ${v}`);
}

const encodeAll = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, encode(v)]));

// Run the steps in the order of `ids` (taken from the Python JSON).
// values: { d, d1, k, e, e2 } as BigInt. Returns one record per step with
// id, status, inputs, result, and worked/message where Python has them.
export function runSteps(curve, values, ids) {
  const ctx = { ...values };
  let failed = false;
  return ids.map((id) => {
    const compute = COMPUTE[id];
    if (!compute) return { id, status: "planned", inputs: {}, result: {} };
    if (failed) {
      return { id, status: "blocked", inputs: {}, result: {}, message: "blocked by an earlier error" };
    }
    try {
      const [inputs, result, worked] = compute(curve, ctx);
      const rec = { id, status: "done", inputs: encodeAll(inputs), result: encodeAll(result) };
      if (worked !== undefined) rec.worked = worked;
      return rec;
    } catch (err) {
      if (!(err instanceof StepError)) throw err;
      failed = true;
      return { id, status: "error", inputs: {}, result: {}, message: err.message };
    }
  });
}
