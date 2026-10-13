"""Runs the JavaScript check (tests/js) from pytest. Skipped if Node is missing."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node") or next(
    (p for p in ("/opt/homebrew/bin/node", "/usr/local/bin/node") if Path(p).exists()), None)


def test_vectors_cover_errors_and_both_curves():
    cases = json.loads((ROOT / "tests/vectors.json").read_text())["cases"]
    statuses = {s["status"] for c in cases for s in c["steps"]}
    assert {"done", "error", "blocked", "planned"} <= statuses
    assert {c["curve"] for c in cases} == {"toy", "secp256k1"}


@pytest.mark.skipif(NODE is None, reason="Node.js not installed")
def test_js_matches_python():
    out = subprocess.run([NODE, "--test", "tests/js/"], cwd=ROOT,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-2000:]
