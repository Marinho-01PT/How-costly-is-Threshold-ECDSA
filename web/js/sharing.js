// The secret sharing panel: d = d₁ + d₂ mod n, and why d₁ alone says nothing.
// Same formula as sharing.share in Python (checked by the share.d2 test vectors).

import { mod } from "./ec.js";
import { el, numberNode } from "./format.js";

function parse(text) {
  const t = text.trim();
  if (!/^(0x[0-9a-f]+|\d+)$/i.test(t)) return null;
  return BigInt(t);
}

export function renderSharing(root, curve, info, start) {
  const n = curve.n;
  const small = info.bits <= 32;
  const hex = (v) => "0x" + v.toString(16);
  const show = (v) => (small ? v.toString() : hex(v));

  const field = (id, labelText, value, hint) => {
    const input = el("input", {
      id, class: "field-input", inputmode: small ? "numeric" : "text", spellcheck: "false",
      autocomplete: "off", value: show(value), "aria-describedby": `${id}-hint`,
    });
    return {
      input,
      node: el("div", { class: "field" },
        el("label", { for: id }, labelText), input,
        el("p", { class: "field-hint", id: `${id}-hint` }, hint)),
    };
  };

  const range = small ? `a number from 1 to ${n - 1n}` : "a number below n, decimal or 0x hex";
  const fd = field("share-d", "Private key d", start.d, range);
  const fd1 = field("share-d1", "Alice's share d₁", start.d1, small ? `a number from 0 to ${n - 1n}` : range);
  const out = el("div", { class: "share-out", "aria-live": "polite" });

  const guess = small
    ? el("input", { id: "share-guess", type: "range", min: "1", max: String(n - 1n), value: "1", class: "slider" })
    : el("input", { id: "share-guess", class: "field-input", spellcheck: "false", value: "0x1" });
  const guessOut = el("p", { class: "guess-out", "aria-live": "polite" });

  function update() {
    const d = parse(fd.input.value);
    const d1 = parse(fd1.input.value);
    const okD = d !== null && d >= 1n && d < n;
    const okD1 = d1 !== null && d1 >= 0n && d1 < n;
    fd.input.setAttribute("aria-invalid", String(!okD));
    fd1.input.setAttribute("aria-invalid", String(!okD1));
    if (!okD || !okD1) {
      out.replaceChildren(el("p", { class: "msg msg-error" }, "Enter " + range + " in both fields."));
      guessOut.replaceChildren();
      return;
    }
    const d2 = mod(d - d1, n);
    out.replaceChildren(
      el("p", { class: "share-line" },
        el("span", { class: "share-name" }, "Bob's share"), " d₂ = d − d₁ mod n = ",
        numberNode(hex(d2), info, "bob")),
      el("p", { class: "share-line" },
        "Check: d₁ + d₂ mod n = ", numberNode(hex(mod(d1 + d2, n)), info), " = d"),
    );

    const g = parse(guess.value);
    if (g === null || g < 1n || g >= n) {
      guessOut.replaceChildren("Enter a possible key to test.");
      return;
    }
    guessOut.replaceChildren(
      "If the key were ", numberNode(hex(g), info), ", Bob would hold d₂ = ",
      numberNode(hex(mod(g - d1, n)), info, "bob"),
      ". That is a perfectly normal share, so Alice's d₁ cannot rule this key out. ",
      small
        ? `The same holds for all ${n - 1n} possible keys.`
        : "The same holds for every possible key.",
    );
  }

  for (const input of [fd.input, fd1.input, guess]) input.addEventListener("input", update);

  root.replaceChildren(
    el("div", { class: "share-grid" }, fd.node, fd1.node),
    out,
    el("h3", { class: "sub" }, "What does d₁ alone reveal?"),
    el("p", {},
      "Alice only sees d₁. Pick any key d below: there is always a d₂ that fits, "
      + "so d₁ is consistent with every possible d and tells Alice nothing about the key."),
    el("div", { class: "field" },
      el("label", { for: "share-guess" }, "Try a key"), guess),
    guessOut,
  );
  update();
}
