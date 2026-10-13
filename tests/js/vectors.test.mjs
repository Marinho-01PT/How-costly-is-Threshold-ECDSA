// Checks that the JavaScript in web/js computes exactly what Python computed.
// Run: node --test tests/js/   (vectors from: python -m twoparty.trace --vectors tests/vectors.json)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { Curve } from "../../web/js/ec.js";
import { runSteps } from "../../web/js/steps.js";

const vectors = JSON.parse(readFileSync(new URL("../vectors.json", import.meta.url)));
const curves = Object.fromEntries(
  Object.entries(vectors.curves).map(([name, info]) => [name, Curve.fromInfo(info)]),
);

test("generators are on their curves", () => {
  for (const c of Object.values(curves)) {
    assert.ok(c.onCurve(c.G));
    assert.equal(c.baseMul(c.n), null);
  }
});

vectors.cases.forEach((cs, i) => {
  const label = `case ${i} (${cs.curve}: ${Object.entries(cs.values).map(([k, v]) => `${k}=${v}`).join(" ")})`;
  test(label, () => {
    const values = Object.fromEntries(Object.entries(cs.values).map(([k, v]) => [k, BigInt(v)]));
    const got = runSteps(curves[cs.curve], values, cs.steps.map((s) => s.id));
    got.forEach((step, j) => assert.deepEqual(step, cs.steps[j], `step ${step.id}`));
  });
});
