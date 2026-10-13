// Turning typed values from the trace JSON into DOM nodes.
// Small curves show decimals; secp256k1 shows shortened hex with expand and copy.

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  node.append(...children.flat().filter((c) => c !== null && c !== undefined && c !== false));
  return node;
}

// How value names are written on the page.
const LABELS = {
  d1: "d₁", d2: "d₂", Q1: "Q₁", Q2: "Q₂", e2: "e₂", s2: "s₂", u1: "u₁", u2: "u₂",
  k_inv: "k⁻¹", s_raw: "s before the low-s rule", x_P: "x(P) mod n",
  k_found: "k found", d_found: "d found", Q_found: "d found · G",
  flipped: "replaced by n − s", valid: "signature valid", match: "same key as the signer's",
  m: "message m",
};
export const label = (name) => LABELS[name] ?? name;

// Which party a value belongs to, for the Alice and Bob colours.
const OWNERS = { d1: "alice", Q1: "alice", d2: "bob", Q2: "bob" };
export const owner = (name) => OWNERS[name];

const SHORT_AFTER = 20; // hex digits shown in full before shortening

export function formatInt(hex, curve) {
  const v = BigInt(hex);
  return curve.bits <= 32 ? v.toString(10) : "0x" + v.toString(16);
}

// One number as a chip. A long number is a button that shows all its digits;
// with copy = true it also gets a copy button (used in the value tables).
export function numberNode(hex, curve, who, copy = false) {
  const full = formatInt(hex, curve);
  const cls = "num" + (who ? ` num-${who}` : "");
  if (full.length <= SHORT_AFTER + 2) return el("span", { class: cls }, full);

  const short = `${full.slice(0, 8)}…${full.slice(-6)}`;
  const chip = el("button", {
    type: "button", class: cls + " num-long", "aria-expanded": "false",
    title: "Show all digits", "aria-label": `${short}, show all digits`,
  }, short);
  chip.addEventListener("click", () => {
    const open = chip.getAttribute("aria-expanded") !== "true";
    chip.setAttribute("aria-expanded", String(open));
    chip.textContent = open ? full : short;
    chip.title = open ? "Shorten" : "Show all digits";
    chip.setAttribute("aria-label", open ? `${full}, shorten` : `${short}, show all digits`);
  });
  if (!copy) return chip;

  const btn = el("button", {
    type: "button", class: "copy-btn", "aria-label": `Copy ${short}`, title: "Copy the full number",
  }, "Copy");
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(full);
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => (btn.textContent = "Copy"), 1500);
  });
  return el("span", { class: "num-wrap" }, chip, btn);
}

export function valueNode(v, curve, who, copy = false) {
  switch (v.kind) {
    case "int":
      return numberNode(v.value, curve, who, copy);
    case "point":
      return el("span", { class: "point" },
        "(", numberNode(v.x, curve, who, copy), ", ", numberNode(v.y, curve, who, copy), ")");
    case "infinity":
      return el("span", { class: "num" }, "∞");
    case "bool":
      return el("span", { class: `flag flag-${v.value ? "yes" : "no"}` }, v.value ? "yes" : "no");
    case "text":
      return el("span", { class: "text-value" }, `"${v.value}"`);
    default:
      return el("span", {}, "?");
  }
}

// A worked formula like "{Q} = {d} · {G}" with the placeholders replaced by values.
export function workedNode(template, lookup, curve) {
  const out = el("span", { class: "worked" });
  for (const part of template.split(/(\{\w+\})/)) {
    const m = part.match(/^\{(\w+)\}$/);
    if (!m) {
      if (part) out.append(part);
      continue;
    }
    const v = lookup(m[1]);
    out.append(v ? valueNode(v, curve, owner(m[1])) : label(m[1]));
  }
  return out;
}
