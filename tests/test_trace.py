import json
from pathlib import Path

import pytest

from twoparty import trace
from twoparty.ec import CURVES, TOY
from twoparty.ecdsa_pure import verify

ROOT = Path(__file__).resolve().parents[1]
STEP_KEYS = {"id", "section", "title", "description", "plain", "terms", "who", "inputs",
             "formula", "worked", "result", "status"}


def dec(v):
    if v["kind"] == "int":
        return int(v["value"], 16)
    if v["kind"] == "point":
        return int(v["x"], 16), int(v["y"], 16)
    if v["kind"] == "infinity":
        return None
    return v["value"]


def results(t):
    """step id -> {name: decoded value}"""
    return {s["id"]: {k: dec(v) for k, v in s["result"].items()} for s in t["steps"]}


@pytest.fixture(params=list(CURVES))
def tr(request):
    c = CURVES[request.param]
    return c, trace.build_trace(c, trace.default_values(c, seed=1, message="hello"))


def test_schema(tr):
    _, t = tr
    assert t["schema"] == trace.SCHEMA
    section_ids = {s["id"] for s in t["sections"]}
    for s in t["steps"]:
        assert STEP_KEYS <= s.keys()
        assert s["section"] in section_ids
        assert s["status"] in ("done", "planned")
    assert [s["id"] for s in t["steps"]] == [s.id for s in trace.STEPS]
    json.dumps(t)  # serialisable


def test_values_are_consistent(tr):
    c, t = tr
    r = results(t)
    d = r["keygen.d"]["d"]
    assert r["keygen.Q"]["Q"] == c.base_mul(d)
    assert (r["share.d1"]["d1"] + r["share.d2"]["d2"]) % c.n == d == r["share.check"]["d"]
    assert r["share.public"]["Q"] == r["keygen.Q"]["Q"]
    sig = (r["sign.r"]["r"], r["sign.lows"]["s"])
    assert verify(c, r["keygen.Q"]["Q"], b"hello", sig)
    assert r["verify.check"]["valid"] is True
    assert r["reuse.d"]["d_found"] == d and r["reuse.check"]["match"] is True


def test_planned_placeholders(tr):
    _, t = tr
    planned = {s["id"] for s in t["steps"] if s["status"] == "planned"}
    assert planned == {"mta", "twoparty.sign"}


def test_worked_placeholders_resolve(tr):
    """Every {name} in a worked formula must be a value of that step or a curve constant."""
    import re
    _, t = tr
    for s in t["steps"]:
        if s["status"] != "done":
            continue
        known = {*s["inputs"], *s["result"], "n", "p", "G"}
        assert set(re.findall(r"\{(\w+)\}", s["worked"])) <= known, s["id"]


def test_toy_defaults_hand_checkable():
    r = results(trace.build_trace(TOY, trace.default_values(TOY, 1, "hello")))
    assert r["keygen.d"]["d"] == 42 and r["share.d2"]["d2"] == 255
    assert r["sign.e"]["e"] == 8 and r["sign.r"]["r"] == 92


def test_bad_k_gives_error_then_blocked():
    steps = trace.run_steps(TOY, {"d": 5, "d1": 3, "k": 0, "e": 9, "e2": 1})
    status = {s["id"]: s["status"] for s in steps}
    assert status["sign.k"] == "error" and status["verify.check"] == "blocked"
    assert status["keygen.Q"] == "done" and status["mta"] == "planned"


def test_same_hash_twice_only_breaks_reuse():
    steps = trace.run_steps(TOY, {"d": 5, "d1": 3, "k": 17, "e": 9, "e2": 9})
    status = {s["id"]: s["status"] for s in steps}
    assert status["verify.check"] == "done" and status["reuse.sig2"] == "error"


def test_reuse_finds_key_for_many_inputs():
    for d in range(1, TOY.n, 13):
        for k in range(1, TOY.n, 17):
            steps = trace.run_steps(TOY, {"d": d, "d1": 1, "k": k, "e": 3, "e2": 200})
            r = {s["id"]: s for s in steps}
            if r["sign.k"]["status"] != "done":
                continue
            assert dec(r["reuse.d"]["result"]["d_found"]) == d


def test_cli_writes_both_curves(tmp_path):
    assert trace.main(["--out", str(tmp_path)]) == 0
    for name in CURVES:
        assert json.loads((tmp_path / f"{name}.json").read_text())["curve"]["name"] == name


def test_cli_rejects_bad_override(tmp_path):
    assert trace.main(["--curve", "toy", "--k", "0", "--out", str(tmp_path)]) == 1


def test_committed_files_are_up_to_date(tmp_path):
    """web/data and tests/vectors.json must match what the code produces now."""
    trace.main(["--out", str(tmp_path)])
    trace.main(["--vectors", str(tmp_path / "vectors.json")])
    for name in CURVES:
        assert (tmp_path / f"{name}.json").read_text() == (ROOT / "web/data" / f"{name}.json").read_text()
    assert (tmp_path / "vectors.json").read_text() == (ROOT / "tests/vectors.json").read_text()


def test_plain_words_and_glossary(tr):
    _, t = tr
    for s in t["steps"]:
        assert s["plain"], s["id"]
        assert s["terms"] and set(s["terms"]) <= t["glossary"].keys(), s["id"]
    used = {term for s in t["steps"] for term in s["terms"]}
    assert used == t["glossary"].keys()  # no unused glossary entries
