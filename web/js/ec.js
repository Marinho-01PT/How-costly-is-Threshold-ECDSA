// Elliptic curve arithmetic with BigInt. Mirrors src/twoparty/ec.py.
// Points are [x, y] arrays of BigInt; the point at infinity is null.
// Used only when the user edits values; tests/js checks it against Python.

export const mod = (a, m) => ((a % m) + m) % m;

export function inv(a, m) {
  // Extended Euclid. Throws if a has no inverse mod m.
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new RangeError("no inverse");
  return mod(s0, m);
}

export class Curve {
  constructor({ name, p, a, b, G, n }) {
    Object.assign(this, { name, p, a, b, G, n });
  }

  static fromInfo(info) {
    const big = (h) => BigInt(h);
    return new Curve({
      name: info.name, p: big(info.p), a: big(info.a), b: big(info.b), n: big(info.n),
      G: [big(info.G.x), big(info.G.y)],
    });
  }

  onCurve(P) {
    if (P === null) return true;
    const [x, y] = P;
    return mod(y * y - (x * x * x + this.a * x + this.b), this.p) === 0n;
  }

  add(P, Q) {
    if (P === null) return Q;
    if (Q === null) return P;
    const p = this.p;
    const [x1, y1] = P;
    const [x2, y2] = Q;
    if (x1 === x2 && mod(y1 + y2, p) === 0n) return null;
    const lam = x1 === x2 && y1 === y2
      ? mod((3n * x1 * x1 + this.a) * inv(2n * y1, p), p)
      : mod((y2 - y1) * inv(x2 - x1, p), p);
    const x3 = mod(lam * lam - x1 - x2, p);
    return [x3, mod(lam * (x1 - x3) - y1, p)];
  }

  mul(k, P) {
    k = mod(k, this.n);
    let R = null;
    for (const bit of k === 0n ? "" : k.toString(2)) {
      R = this.add(R, R);
      if (bit === "1") R = this.add(R, P);
    }
    return R;
  }

  baseMul(k) {
    return this.mul(k, this.G);
  }
}

export const samePoint = (P, Q) =>
  P === Q || (P !== null && Q !== null && P[0] === Q[0] && P[1] === Q[1]);
