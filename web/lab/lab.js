// Building-block lab: rows from /api/rows, study mode (one recorded signature,
// step by step) and benchmark mode (results arrive over Server-Sent Events).

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
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

const state = { rows: [], curves: [], curve: "toy", config: {}, trace: null, at: 0 };

const FAST = { curve: "libsecp256k1", bignum: "gmpy2", paillier_dec: "crt",
  paillier_enc: "precomputed", wire: "binary", mta: "reuse", flow: "batched" };
const SHORT = { curve: "secp256k1 only", paillier_bits: "secp256k1 only" };
const PARTY = { alice: "Alice", bob: "Bob", verifier: "Verifier" };
const key = (v) => JSON.stringify(v);
const ms = (x) => (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2));

// ---- theme ---------------------------------------------------------------
function applyTheme(t) {
  if (t === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  $("#theme").value = t;
  try { localStorage.setItem("lab-theme", t); } catch { /* storage blocked */ }
}
$("#theme").addEventListener("change", (e) => applyTheme(e.target.value));
let savedTheme = "auto";
try { savedTheme = localStorage.getItem("lab-theme") || "auto"; } catch { /* storage blocked */ }
applyTheme(savedTheme);

// ---- building blocks -----------------------------------------------------
function disabledFor(row, v) {
  if (row.field === "curve" && v.value === "libsecp256k1" && state.curve !== "secp256k1")
    return "libsecp256k1 only knows secp256k1";
  if (row.field === "paillier_bits" && state.curve !== "secp256k1")
    return "the small curve uses a small Paillier key";
  return null;
}

function renderRows() {
  $("#rows tbody").replaceChildren(...state.rows.map((row) => {
    const opts = [...row.variants, ...row.planned].map((v) => {
      const why = v.planned ? "planned, not built yet"
        : !row.live ? "the only variant so far" : disabledFor(row, v);
      // A row that is not live yet still runs its first variant.
      const checked = !v.planned && (row.live
        ? !why && key(state.config[row.field]) === key(v.value)
        : key(v.value) === key(row.variants[0].value));
      const input = el("input", { type: "radio", name: `row-${row.field}`, disabled: Boolean(why),
        checked, onchange: () => { state.config[row.field] = v.value; renderRows(); } });
      const tag = v.planned ? " (planned)" : row.live && why ? ` (${SHORT[row.field] || "n/a"})` : "";
      return el("label", { class: why && !checked ? "planned" : null, title: why || null }, input, " ", v.label, tag);
    });
    return el("tr", { "data-field": row.field },
      el("th", { scope: "row" }, row.title, el("span", { class: "field" }, row.live ? row.field : "planned")),
      el("td", {}, opts));
  }));
  const diff = state.rows.filter((r) => r.live && key(state.config[r.field]) !== key(r.default))
    .map((r) => `${r.field}=${state.config[r.field]}`);
  $("#config-label").textContent = diff.join(", ") || "original";
  highlight(!$("#study").hidden ? currentEvent()?.rows || [] : []);
}

function highlight(fields) {
  for (const tr of document.querySelectorAll("#rows tbody tr"))
    tr.classList.toggle("active", fields.includes(tr.dataset.field));
}

function setPreset(p) {
  for (const r of state.rows) if (r.live) state.config[r.field] = r.default;
  if (p === "fast") for (const [k, v] of Object.entries(FAST)) {
    const row = state.rows.find((r) => r.field === k && r.live);
    if (row && row.variants.some((x) => key(x.value) === key(v))) state.config[k] = v;
  }
  fixForCurve();
  renderRows();
}
function fixForCurve() {
  if (state.curve !== "secp256k1" && state.config.curve === "libsecp256k1") state.config.curve = "pure";
}
$("#preset-original").addEventListener("click", () => setPreset("original"));
$("#preset-fast").addEventListener("click", () => setPreset("fast"));
$("#curve").addEventListener("change", (e) => { state.curve = e.target.value; fixForCurve(); renderRows(); });

for (const r of document.querySelectorAll('input[name="mode"]')) {
  r.addEventListener("change", () => {
    const study = document.querySelector('input[name="mode"]:checked').value === "study";
    $("#study").hidden = !study;
    $("#auto").hidden = study;
    highlight(study ? currentEvent()?.rows || [] : []);
  });
}

// ---- numbers ---------------------------------------------------------------
function numberNode(text) {
  const s = String(text);
  if (!/^-?\d+$/.test(s) || s.length <= 30) return document.createTextNode(s);
  const short = `${s.slice(0, 12)}...${s.slice(-8)} (${s.length} digits)`;
  const span = el("span", { class: "num-short", title: "click: all digits", tabindex: "0", role: "button" }, short);
  const toggle = () => { span.textContent = span.textContent === short ? s : short; };
  span.addEventListener("click", toggle);
  span.addEventListener("keydown", (e) => { if (e.key === "Enter") toggle(); });
  return span;
}

function valueNode(v) {
  if (Array.isArray(v)) return el("span", {}, "(", ...v.flatMap((x, i) => (i ? [", ", valueNode(x)] : [valueNode(x)])), ")");
  if (v && typeof v === "object") {
    return el("span", {}, ...Object.entries(v).flatMap(([k, x], i) => [i ? "; " : "", `${k}=`, valueNode(x)]));
  }
  if (typeof v === "boolean") return document.createTextNode(v ? "true" : "false");
  return numberNode(v === null ? "-" : v);
}

// ---- study -----------------------------------------------------------------
function currentEvent() { return state.trace?.events[state.at]; }

$("#study-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("#study-run");
  const status = $("#study-status");
  btn.disabled = true;
  status.className = "status";
  status.textContent = state.curve === "secp256k1"
    ? "Signing... (first run on this curve makes a Paillier key: a few seconds)" : "Signing...";
  try {
    const res = await fetch("/api/study", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ config: state.config, curve: state.curve, message: $("#message").value }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    state.trace = data;
    status.textContent = "";
    renderStudy();
    $("#study-out").hidden = false;
  } catch (e) {
    status.className = "status error";
    status.textContent = `Error: ${e.message}`;
  } finally {
    btn.disabled = false;
  }
});

function renderStudy() {
  const t = state.trace;
  $("#summary").textContent =
    `${t.valid ? "Signature valid" : "SIGNATURE INVALID"} (checked against the public key). ` +
    `${t.signing_messages} messages for the signature plus 2 for the setup, ${t.bytes} bytes, ` +
    `${ms(t.total_ms)} ms from setup to signature. Curve ${t.curve}, configuration ${t.label}. ` +
    `Bob: ${t.bob}.`;
  $("#timeline tbody").replaceChildren(...t.events.map((e, i) => el("tr", { "data-i": i, onclick: () => go(i) },
    el("td", {}, String(i + 1)),
    el("td", {}, PARTY[e.party] + (e.remote ? " (partner)" : "")),
    el("td", {}, e.kind === "message" ? `sends ${e.keys.join(", ")} to ${PARTY[e.to]}` : e.step),
    el("td", {}, `${ms(e.spent_ms)} ms`))));
  go(0);
}

function go(i) {
  const t = state.trace;
  state.at = Math.max(0, Math.min(t.events.length - 1, i));
  const e = currentEvent();
  $("#counter").textContent = `step ${state.at + 1} of ${t.events.length}`;
  $("#prev").disabled = state.at === 0;
  $("#next").disabled = state.at === t.events.length - 1;
  const titles = Object.fromEntries(state.rows.map((r) => [r.field, r.title]));
  const blocks = e.rows.filter((r) => titles[r]).map((r) => titles[r]);
  const rows = [
    ["Party", PARTY[e.party]],
    ["Action", e.kind === "message"
      ? `sends a message to ${PARTY[e.to]}: ${e.keys.join(", ")} (${e.bytes} bytes as ${t.config.wire})`
      : e.step],
    ["Building blocks", blocks.join(", ") || "none from the list (plain arithmetic mod n)"],
    ["Time", `${ms(e.spent_ms)} ms since ${PARTY[e.party]}'s previous step; ${ms(e.at_ms)} ms since the start`],
  ];
  $("#step tbody").replaceChildren(...rows.map(([k, v]) => el("tr", {}, el("th", { scope: "row" }, k), el("td", {}, v))));
  const entries = Object.entries(e.values || {});
  $("#values tbody").replaceChildren(...(entries.length
    ? entries.map(([k, v]) => el("tr", {}, el("th", { scope: "row" }, k), el("td", {}, valueNode(v))))
    : [el("tr", {}, el("td", {}, "(none)"))]));
  const leak = $("#leak");
  leak.hidden = !(state.at === t.events.length - 1 && t.stolen_d2 !== null);
  if (!leak.hidden) {
    leak.textContent = "Experiment without beta': Alice computed Bob's key share d2 from her MtA share for k1*d2. " +
      (t.stolen_ok ? "It is correct, so she can now sign alone." : "The guess is wrong.");
  }
  for (const tr of document.querySelectorAll("#timeline tbody tr"))
    tr.classList.toggle("current", Number(tr.dataset.i) === state.at);
  highlight(e.rows);
}
$("#prev").addEventListener("click", () => go(state.at - 1));
$("#next").addEventListener("click", () => go(state.at + 1));
document.addEventListener("keydown", (ev) => {
  if (!state.trace || $("#study").hidden || ev.target.matches("input, select, textarea")) return;
  if (ev.key === "ArrowRight") go(state.at + 1);
  if (ev.key === "ArrowLeft") go(state.at - 1);
});

// ---- benchmark -------------------------------------------------------------
let results = [];

$("#auto-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("#auto-run");
  const status = $("#auto-status");
  status.className = "status";
  btn.disabled = true;
  try {
    const res = await fetch("/api/auto", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        config: state.config, curve: state.curve, kind: new FormData($("#auto-form")).get("kind"),
        rounds: Number($("#rounds").value), peer: $("#peer").value.trim() || null,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    results = data.configs.map((label) => ({ label: label.replaceAll(",", ", "), row: null, running: false }));
    $("#auto-out").hidden = false;
    $("#csv-note").textContent = "";
    drawResults();
    listen(data.job, btn);
  } catch (e) {
    status.className = "status error";
    status.textContent = `Error: ${e.message}`;
    btn.disabled = false;
  }
});

function listen(job, btn) {
  const status = $("#auto-status");
  const es = new EventSource(`/api/events/${job}`);
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    if (ev.type === "start") status.textContent = `Bob at ${ev.peer}; ${ev.total} configuration(s), ${ev.rounds} signatures each.`;
    if (ev.type === "running") {
      status.textContent = `Running ${ev.i} of ${results.length}: ${ev.label}${ev.keygen ? " (making a Paillier key first)" : ""}`;
      results[ev.i - 1].running = true;
      drawResults();
    }
    if (ev.type === "row") { Object.assign(results[ev.i - 1], { row: ev.row, running: false }); drawResults(); }
    if (ev.type === "done") {
      status.textContent = "Done.";
      $("#csv-note").replaceChildren("Saved as CSV in benchmark/results/. ", el("a", { href: `/api/csv/${job}` }, "Download"));
      es.close(); btn.disabled = false;
    }
    if (ev.type === "error") {
      status.className = "status error";
      status.textContent = `Error: ${ev.message}`;
      es.close(); btn.disabled = false;
    }
  };
  es.onerror = () => { es.close(); btn.disabled = false; };
}

function niceMax(x) {
  const p = 10 ** Math.floor(Math.log10(x));
  return [1, 2, 5, 10].map((m) => m * p).find((v) => v >= x);
}

function drawResults() {
  const done = results.filter((r) => r.row);
  const ref = done[0]?.row;
  const top = niceMax(Math.max(...done.map((r) => r.row.sig_per_s), 1e-6));
  const chart = $("#chart");
  chart.className = "chart";
  const kids = [];
  for (const r of results) {
    const v = r.row?.sig_per_s ?? 0;
    const f = ref && r.row ? v / ref.sig_per_s : null;
    kids.push(el("div", { class: "name" }, r.label),
      el("div", { class: "track" },
        r.row ? el("div", { class: `bar${f !== null && f < 1 ? " slower" : ""}`, style: `width:calc((100% - 15em) * ${v / top})` }) : null,
        el("span", { class: "val" }, r.row ? `${v.toFixed(2)}/s, ${f.toFixed(f >= 10 ? 0 : 2)}x first row`
          : r.running ? "running" : "waiting")));
  }
  kids.push(el("div", {}), el("div", { class: "axis" }, el("span", {}, "0"), el("span", {}, `${top / 2}`),
    el("span", {}, `${top} signatures/s`)));
  chart.replaceChildren(...kids);
  $("#results tbody").replaceChildren(...results.map((r) => {
    const x = r.row;
    if (!x) return el("tr", { class: "pending" }, el("td", {}, r.label), el("td", { colspan: 8 }, r.running ? "running" : "waiting"));
    return el("tr", {}, el("td", {}, r.label),
      ...[x.sig_per_s.toFixed(2), ms(x.mean_ms), ms(x.median_ms), ms(x.p95_ms), ms(x.verify_mean_ms),
        String(x.msgs_per_sig), String(x.bytes_per_sig), ms(x.offline_ms)].map((s) => el("td", {}, s)));
  }));
}

// ---- partner on the same Wi-Fi -----------------------------------------------
let pairTimer = null;

async function pairCall(path, body) {
  const res = await fetch(path, body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function showPair(st) {
  const status = $("#pair-status");
  status.className = "status";
  $("#pair-host").hidden = st.mode !== "host";
  if (st.mode === "host") {
    $("#pair-code").textContent = st.code;
    $("#pair-me").textContent = `${st.name}, ${st.ip}:${st.port}`;
    status.textContent = "Waiting for the partner. While a partner is connected, this laptop answers as Bob.";
    $("#pair-log tbody").replaceChildren(...(st.log.length ? st.log.slice().reverse().map((x) =>
      el("tr", {}, el("td", {}, x.time), el("td", {}, x.from), el("td", {}, x.error ? `${x.what || x.task}: ${x.error}` : x.what)))
      : [el("tr", {}, el("td", { colspan: 3, class: "note" }, "no session yet"))]));
    const last = st.last_study;
    $("#bob-last").hidden = !last;
    if (last) {
      $("#bob-last-info").textContent = `Message "${last.message}", curve ${last.curve}, configuration ${last.label}, Alice at ${last.from}.`;
      $("#bob-steps tbody").replaceChildren(...last.steps.map((x, i) =>
        el("tr", {}, el("td", {}, String(i + 1)), el("td", {}, x.step), el("td", {}, `${ms(x.spent_ms)} ms`))));
    }
  } else if (st.mode === "joined") {
    status.textContent = `Connected. Bob is ${st.partner} (${st.peer}). Study mode and benchmark now run against that laptop.`;
    $("#peer").value = "";
    $("#peer").placeholder = `empty = partner ${st.partner}`;
  } else {
    status.textContent = "";
    $("#peer").placeholder = "empty = local Bob";
  }
}

async function setPairMode(mode) {
  clearInterval(pairTimer);
  $("#pair-join").hidden = mode !== "join";
  try {
    if (mode === "host") {
      showPair(await pairCall("/api/pair/host", {}));
      pairTimer = setInterval(async () => {
        try { showPair(await pairCall("/api/pair")); } catch { /* server gone */ }
      }, 1500);
    } else {
      showPair(await pairCall("/api/pair/leave", {}));
      if (mode === "join") { $("#pair-status").textContent = "Type the code shown on your partner's laptop."; $("#join-code").focus(); }
    }
  } catch (e) {
    $("#pair-status").className = "status error";
    $("#pair-status").textContent = `Error: ${e.message}`;
  }
}

for (const r of document.querySelectorAll('input[name="pairmode"]'))
  r.addEventListener("change", (e) => setPairMode(e.target.value));

$("#pair-join").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("#join-run");
  btn.disabled = true;
  $("#pair-status").className = "status";
  $("#pair-status").textContent = "Looking for the partner on this network (up to 15 s)...";
  try {
    showPair(await pairCall("/api/pair/join", { code: $("#join-code").value }));
  } catch (e) {
    $("#pair-status").className = "status error pre";
    $("#pair-status").textContent = e.message;
  } finally {
    btn.disabled = false;
  }
});

// ---- start -----------------------------------------------------------------
(async () => {
  const data = await (await fetch("/api/rows")).json();
  state.rows = data.rows;
  state.curves = data.curves;
  for (const r of state.rows) if (r.live) state.config[r.field] = r.default;
  $("#curve").replaceChildren(...state.curves.map((c) => el("option", { value: c.name, selected: c.name === state.curve },
    c.name === "toy" ? `toy (${c.bits} bit, small numbers)` : `${c.name} (${c.bits} bit)`)));
  renderRows();
  try {   // after a page reload: show the pairing the server still has
    const st = await pairCall("/api/pair");
    if (st.mode !== "alone") {
      document.querySelector(`input[name="pairmode"][value="${st.mode === "host" ? "host" : "join"}"]`).checked = true;
      $("#pair-join").hidden = st.mode !== "joined";
      if (st.mode === "host") setPairMode("host"); else showPair(st);
    }
  } catch { /* older server */ }
})();
