// A picture of the toy curve: every point as a dot, the points of the
// current step highlighted. Only for small curves; secp256k1 gets a note.

import { el, label, owner } from "./format.js";

const NS = "http://www.w3.org/2000/svg";
const SIZE = 360;
const PAD = 28;

const cache = new Map();

// All points of a small curve, found as the multiples of G (the group is cyclic).
function allPoints(curve) {
  if (!cache.has(curve.name)) {
    const pts = [];
    let P = null;
    for (let i = 1n; i < curve.n; i++) {
      P = curve.add(P, curve.G);
      pts.push(P);
    }
    cache.set(curve.name, pts);
  }
  return cache.get(curve.name);
}

function svgEl(tag, attrs, text) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

// Points named in the step: [{ name, x, y, role }], results first.
export function stepPoints(step) {
  const out = [];
  const seen = new Set();
  for (const [role, values] of [["result", step.result], ["input", step.inputs]]) {
    for (const [name, v] of Object.entries(values ?? {})) {
      if (v.kind !== "point") continue;
      const key = `${v.x},${v.y}`;
      const dup = seen.has(key);
      seen.add(key);
      out.push({ name, x: BigInt(v.x), y: BigInt(v.y), role, dup });
    }
  }
  return out;
}

export function renderPlot(curve, info, step) {
  const marks = stepPoints(step);
  if (!marks.length) return null;

  if (info.bits > 32) {
    return el("figure", { class: "plot plot-note" },
      el("p", {}, el("strong", {}, "Why there is no picture here. "),
        "secp256k1 has about 1.16 · 10⁷⁷ points, more than there are atoms in the Earth, "
        + "so they cannot be drawn. Switch to the toy curve to see what the points of this step look like."));
  }

  const p = Number(curve.p);
  const scale = (SIZE - 2 * PAD) / p;
  const sx = (x) => PAD + Number(x) * scale;
  const sy = (y) => SIZE - PAD - Number(y) * scale;

  const svg = svgEl("svg", {
    viewBox: `0 0 ${SIZE} ${SIZE}`, class: "plot-svg", role: "img",
    "aria-label": `All points of the toy curve as dots. Highlighted: ${marks
      .map((m) => `${label(m.name)} = (${m.x}, ${m.y})`).join(", ")}.`,
  });

  // Frame and a few axis labels.
  svg.append(svgEl("rect", {
    x: PAD, y: PAD, width: SIZE - 2 * PAD, height: SIZE - 2 * PAD, class: "plot-frame",
  }));
  for (const t of [0, 100, 200, 300]) {
    svg.append(svgEl("text", { x: sx(t), y: SIZE - PAD + 16, class: "plot-axis", "text-anchor": "middle" }, String(t)));
    svg.append(svgEl("text", { x: PAD - 6, y: sy(t) + 4, class: "plot-axis", "text-anchor": "end" }, String(t)));
  }
  svg.append(svgEl("text", { x: SIZE - PAD, y: SIZE - 4, class: "plot-axis", "text-anchor": "end" }, "x"));
  svg.append(svgEl("text", { x: 6, y: PAD - 10, class: "plot-axis" }, "y"));

  const dots = svgEl("g", { class: "plot-dots" });
  for (const [x, y] of allPoints(curve)) {
    dots.append(svgEl("circle", { cx: sx(x), cy: sy(y), r: 1.9 }));
  }
  svg.append(dots);

  // Highlights: inputs as rings, results as filled dots, with name labels.
  const labelled = [];
  for (const m of marks) {
    const cx = sx(m.x), cy = sy(m.y);
    const who = owner(m.name);
    const cls = `plot-mark plot-${m.role}${who ? ` plot-${who}` : ""}`;
    const g = svgEl("g", { class: cls });
    if (!m.dup) {
      g.append(svgEl("circle", { cx, cy, r: m.role === "result" ? 7 : 6, class: "plot-ring" }));
      g.append(svgEl("circle", { cx, cy, r: 3.2, class: "plot-core" }));
    }
    // Stack labels of points that sit on the same spot.
    const same = labelled.filter((l) => Math.abs(l.cx - cx) < 4 && Math.abs(l.cy - cy) < 4).length;
    const right = cx < SIZE - 80;
    const tx = right ? cx + 11 : cx - 11;
    const ty = cy + 4 + same * 15 - (cy > SIZE - PAD - 20 ? 14 : 0);
    const text = m.dup ? `= ${label(m.name)}` : label(m.name);
    g.append(svgEl("text", { x: tx, y: ty, class: "plot-label", "text-anchor": right ? "start" : "end" }, text));
    labelled.push({ cx, cy });
    svg.append(g);
  }

  const legend = el("ul", { class: "plot-legend" },
    marks.filter((m) => !m.dup).map((m) =>
      el("li", { class: `plot-key plot-${m.role}${owner(m.name) ? ` plot-${owner(m.name)}` : ""}` },
        el("span", { class: "plot-swatch", "aria-hidden": "true" }),
        `${label(m.name)} = (${m.x}, ${m.y})`,
        m.role === "input" ? el("span", { class: "plot-role" }, " used") : el("span", { class: "plot-role" }, " new"))));

  return el("figure", { class: "plot" }, svg,
    el("figcaption", {},
      legend,
      el("p", { class: "small" },
        `Each dot is one of the ${curve.n - 1n} points of the toy curve (plus the point at infinity, which `
        + "has no place on the grid). Because the numbers wrap around mod p, the curve looks like "
        + "scattered dots instead of a smooth line, but adding points still follows fixed rules.")));
}
