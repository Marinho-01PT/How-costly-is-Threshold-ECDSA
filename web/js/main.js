// The learning page: loads the traces written by Python, shows one step at a
// time, and recomputes the toy curve with steps.js when the user edits values.

import { Curve } from "./ec.js";
import { el, label, owner, valueNode, workedNode } from "./format.js";
import { renderSharing } from "./sharing.js";
import { runSteps } from "./steps.js";

const CURVE_NAMES = ["toy", "secp256k1"];
const EDITABLE = ["d", "d1", "k", "e", "e2"];
const WHO = {
  signer: "Signer", verifier: "Verifier", dealer: "Key setup", attacker: "Attacker",
  both: "Alice and Bob", alice: "Alice", bob: "Bob",
};

const $ = (id) => document.getElementById(id);

const state = {
  traces: {},      // curve name -> trace JSON from Python
  curves: {},      // curve name -> Curve (BigInt)
  curve: "toy",
  index: 0,
  edited: null,    // null: show Python's values; else { d, d1, k, e, e2 } as BigInt
};

async function load() {
  try {
    for (const name of CURVE_NAMES) {
      const res = await fetch(`data/${name}.json`);
      if (!res.ok) throw new Error(`data/${name}.json: ${res.status}`);
      state.traces[name] = await res.json();
      state.curves[name] = Curve.fromInfo(state.traces[name].curve);
    }
  } catch (err) {
    $("step").replaceChildren(el("div", { class: "msg msg-error" },
      el("p", {}, "Could not load the trace files. "
        + "Generate them with python -m twoparty.trace and open the page through a local server, "
        + "for example python -m http.server -d web."),
      el("p", { class: "small" }, String(err))));
    return;
  }
  readHash();
  wire();
  renderAll();
}

// ---- which values are shown ------------------------------------------------------

const trace = () => state.traces[state.curve];
const info = () => trace().curve;

function pythonValues() {
  const p = trace().params;
  const r = Object.fromEntries(trace().steps.flatMap((s) =>
    Object.entries(s.result).filter(([, v]) => v.kind === "int").map(([k, v]) => [k, BigInt(v.value)])));
  return { d: BigInt(p.d.value), d1: BigInt(p.d1.value), k: BigInt(p.k.value), e: r.e, e2: BigInt(p.e2.value) };
}

// Python's text for each step, combined with the values to show.
function steps() {
  const meta = trace().steps;
  if (!state.edited) return meta;
  const computed = runSteps(state.curves[state.curve], state.edited, meta.map((s) => s.id));
  return meta.map((m, i) => ({ ...m, ...computed[i], worked: computed[i].worked ?? m.worked }));
}

// ---- rendering --------------------------------------------------------------------

function renderAll() {
  document.querySelectorAll("[data-curve]").forEach((b) =>
    b.setAttribute("aria-pressed", String(b.dataset.curve === state.curve)));
  renderCurveInfo();
  renderEditor();
  renderNav();
  renderStep();
  renderSharing($("sharing"), state.curves[state.curve], info(), state.edited ?? pythonValues());
}

function renderCurveInfo() {
  const c = info();
  const n = BigInt(c.n), p = BigInt(c.p);
  const small = c.bits <= 32;
  const num = (v) => (small ? v.toString() : `a ${v.toString(2).length}-bit number`);
  $("curve-info").replaceChildren(
    el("p", {},
      small
        ? `Toy curve: y² = x³ + 7 over the numbers mod p = ${p}. It has n = ${n} points, `
          + "small enough to check every step by hand. Same equation as secp256k1."
        : "secp256k1: y² = x³ + 7 over the numbers mod p, the curve used by Bitcoin and Ethereum. "
          + `p and n are each ${num(n)}, so the numbers below are shortened.`),
    el("p", { class: "small" }, "Base point G = ", valueNode(c.G, c), ", order n = ",
      valueNode({ kind: "int", value: c.n }, c)),
  );
}

function renderEditor() {
  const box = $("editor");
  if (state.curve !== "toy") {
    box.replaceChildren(el("p", { class: "small" },
      "On secp256k1 the numbers are fixed: they come straight from the Python trace. "
      + "Switch to the toy curve to change them."));
    $("source").textContent = "Values from Python";
    $("source").dataset.kind = "python";
    return;
  }
  const n = BigInt(info().n);
  const vals = state.edited ?? pythonValues();
  const hints = {
    d: ["Private key d", 1n], d1: ["Alice's share d₁", 0n], k: ["Nonce k", 1n],
    e: ["Message hash e", 0n], e2: ["Second hash e₂ (nonce reuse)", 0n],
  };
  const fields = EDITABLE.map((name) => {
    const [text, lo] = hints[name];
    const input = el("input", {
      id: `edit-${name}`, type: "number", class: "field-input", inputmode: "numeric",
      min: String(lo), max: String(n - 1n), step: "1", value: vals[name].toString(),
    });
    input.addEventListener("change", onEdit);
    input.addEventListener("input", onEdit);
    return el("div", { class: "field field-small" }, el("label", { for: input.id }, text), input);
  });
  const reset = el("button", { type: "button", class: "btn", disabled: !state.edited }, "Back to Python's values");
  reset.addEventListener("click", () => {
    state.edited = null;
    renderAll();
  });
  const msg = trace().params.message?.value;
  box.replaceChildren(
    el("div", { class: "edit-grid" }, fields),
    el("p", { class: "field-hint" },
      `Python used e = SHA-256("${msg}") mod n. Here you can type any hash directly. `
      + `Allowed range: 0 to ${n - 1n} (1 to ${n - 1n} for d and k).`),
    el("div", { class: "edit-actions" }, reset),
  );
  const source = $("source");
  source.textContent = state.edited
    ? "Computed in your browser, checked against Python test cases"
    : "Values from Python";
  source.dataset.kind = state.edited ? "browser" : "python";
}

function onEdit(ev) {
  const values = {};
  for (const name of EDITABLE) {
    const input = $(`edit-${name}`);
    const ok = /^\d+$/.test(input.value.trim());
    input.setAttribute("aria-invalid", String(!ok));
    if (!ok) return; // keep the last good values while the field is being typed
    values[name] = BigInt(input.value.trim());
  }
  state.edited = values;
  const source = $("source");
  source.textContent = "Computed in your browser, checked against Python test cases";
  source.dataset.kind = "browser";
  document.querySelector("#editor .btn").disabled = false;
  renderNav();
  renderStep();
  if (ev.type === "change") {
    renderSharing($("sharing"), state.curves[state.curve], info(), values);
  }
}

function renderNav() {
  const all = steps();
  const list = el("ol", { class: "nav-sections" });
  for (const sec of trace().sections) {
    const items = all.map((s, i) => [s, i]).filter(([s]) => s.section === sec.id);
    if (!items.length) continue;
    list.append(el("li", {},
      el("p", { class: "nav-section" }, sec.title),
      el("ol", { class: "nav-steps" }, items.map(([s, i]) =>
        el("li", {}, el("button", {
          type: "button", class: `nav-step status-${s.status}`,
          "aria-current": i === state.index ? "step" : null,
          onclick: () => go(i, true),
        }, s.title, s.status !== "done" ? el("span", { class: "tag" }, statusText(s.status)) : null))))));
  }
  $("nav").replaceChildren(list);
}

const statusText = (s) => ({ planned: "planned", error: "error", blocked: "blocked" }[s] ?? s);

function valueTable(caption, values, c) {
  const entries = Object.entries(values);
  if (!entries.length) return null;
  return el("div", { class: "values" },
    el("h3", { class: "sub" }, caption),
    el("dl", {}, entries.flatMap(([name, v]) => [
      el("dt", { class: owner(name) ? `who-${owner(name)}` : null }, label(name)),
      el("dd", {}, valueNode(v, c, owner(name), true)),
    ])));
}

function renderStep() {
  const all = steps();
  const s = all[state.index];
  const c = info();
  const sec = trace().sections.find((x) => x.id === s.section);
  const lookup = (name) => s.result[name] ?? s.inputs[name]
    ?? ({ n: { kind: "int", value: c.n }, p: { kind: "int", value: c.p }, G: c.G })[name];

  const body = [];
  if (s.status === "planned") {
    body.push(el("div", { class: "msg msg-planned" },
      el("p", {}, el("strong", {}, "Not implemented yet. "),
        "This step is a placeholder. It will follow the protocol description from our supervisors.")));
  } else {
    if (s.formula) body.push(el("p", { class: "formula", "aria-label": `Formula: ${s.formula}` }, s.formula));
    if (s.status === "done") {
      body.push(el("div", { class: "worked-box" },
        el("p", { class: "eyebrow" }, "With the numbers"), workedNode(s.worked, lookup, c)));
      body.push(el("div", { class: "values-grid" },
        valueTable("Inputs", s.inputs, c), valueTable("Result", s.result, c)));
    } else {
      body.push(el("div", { class: `msg msg-${s.status === "error" ? "error" : "planned"}` },
        el("p", {}, s.status === "error" ? "This step does not work with these values: " : "",
          s.message ?? "")));
    }
  }

  $("step").replaceChildren(el("article", { class: `step-card status-${s.status}` },
    el("p", { class: "eyebrow" }, sec?.title ?? ""),
    el("div", { class: "step-head" },
      el("h2", { id: "step-title", tabindex: "-1" }, s.title),
      el("span", { class: `who who-${s.who}` }, WHO[s.who] ?? s.who)),
    s.description ? el("p", { class: "desc" }, s.description) : null,
    body));

  $("counter").textContent = `Step ${state.index + 1} of ${all.length}`;
  $("prev").disabled = state.index === 0;
  $("next").disabled = state.index === all.length - 1;
}

// ---- navigation -------------------------------------------------------------------

function go(i, focusTitle = false) {
  const count = trace().steps.length;
  state.index = Math.max(0, Math.min(count - 1, i));
  writeHash();
  renderNav();
  renderStep();
  if (focusTitle) $("step-title").focus();
}

function writeHash() {
  const id = trace().steps[state.index].id;
  history.replaceState(null, "", `#${state.curve}/${id}`);
}

function readHash() {
  const [curve, id] = decodeURIComponent(location.hash.slice(1)).split("/");
  if (CURVE_NAMES.includes(curve)) state.curve = curve;
  const i = trace().steps.findIndex((s) => s.id === id);
  state.index = i >= 0 ? i : 0;
}

function wire() {
  // On phones the step list starts collapsed so the current step is visible first.
  if (window.matchMedia("(max-width: 860px)").matches) document.querySelector(".nav-details").open = false;
  $("prev").addEventListener("click", () => go(state.index - 1));
  $("next").addEventListener("click", () => go(state.index + 1));
  document.querySelectorAll("[data-curve]").forEach((b) => b.addEventListener("click", () => {
    if (state.curve === b.dataset.curve) return;
    const id = trace().steps[state.index].id;
    state.curve = b.dataset.curve;
    state.edited = null;
    state.index = Math.max(0, trace().steps.findIndex((s) => s.id === id));
    writeHash();
    renderAll();
  }));
  document.addEventListener("keydown", (ev) => {
    if (ev.altKey || ev.ctrlKey || ev.metaKey) return;
    if (ev.target.closest("input, textarea, select")) return;
    if (ev.key === "ArrowLeft") go(state.index - 1);
    if (ev.key === "ArrowRight") go(state.index + 1);
  });
}

load();
