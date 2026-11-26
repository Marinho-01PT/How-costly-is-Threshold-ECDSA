"""The building-block lab (lab.py) and its web server (ui_server.py)."""
import json
import threading
import urllib.request

import pytest

from twoparty import config, lab, ui_server
from twoparty.config import Config


@pytest.fixture(scope="module")
def server():
    srv = ui_server.make_server("127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()
    lab.LOCAL_BOB.stop()


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.status, r.headers.get("Content-Type"), r.read()


def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_rows_follow_config(server):
    status, _, body = get(server + "/api/rows")
    data = json.loads(body)
    assert status == 200
    assert [r["field"] for r in data["rows"]] == [r[0] for r in config.ROWS]
    live = {f for f in Config.__dataclass_fields__}
    for r in data["rows"]:
        assert r["live"] == (r["field"] in live)
    assert {c["name"] for c in data["curves"]} >= {"toy", "secp256k1"}


def test_study_toy_curve(server):
    status, t = post(server + "/api/study", {"config": {}, "curve": "toy", "message": "1 coin to Carol"})
    assert status == 200 and t["valid"] is True
    msgs = [e for e in t["events"] if e["kind"] == "message"]
    assert t["signing_messages"] == 14 and len(msgs) == 16      # 14 + 2 for the setup
    assert {e["party"] for e in t["events"]} == {"alice", "bob", "verifier"}
    enc = [e for e in t["events"] if e["kind"] == "step" and "Enc(a)" in e["step"]]
    assert len(enc) == 4 and all("paillier_enc" in e["rows"] for e in enc)
    assert all(isinstance(e["spent_ms"], float) for e in t["events"])


def test_study_experiment_shows_the_leak():
    t = lab.study(Config(mask=False), "toy")
    assert t["valid"] and t["stolen_ok"] is True


def test_study_rejects_libsecp_on_toy(server):
    status, body = post(server + "/api/study", {"config": {"curve": "libsecp256k1"}, "curve": "toy"})
    assert status == 400 and "secp256k1" in body["error"]


def test_study_fast_variants_on_secp256k1():
    t = lab.study(config.fastest(), "secp256k1")
    assert t["valid"] and t["signing_messages"] >= 4


def test_auto_run_streams_metrics(server):
    status, job = post(server + "/api/auto", {"config": {}, "curve": "toy", "rounds": 2, "kind": "together"})
    assert status == 200 and job["configs"][0] == "original"
    status, ctype, body = get(f"{server}/api/events/{job['job']}")
    events = [json.loads(line[6:]) for line in body.decode().splitlines() if line.startswith("data: ")]
    assert events[0]["type"] == "start" and events[-1]["type"] == "done"
    rows = [e["row"] for e in events if e["type"] == "row"]
    assert len(rows) == len(job["configs"])
    for r in rows:
        assert r["sig_per_s"] > 0 and r["msgs_per_sig"] >= 4 and r["n"] == 2
    status, ctype, csv_body = get(f"{server}/api/csv/{job['job']}")
    assert status == 200 and csv_body.decode().startswith("time,")
    path = lab.ROOT / events[0]["csv"]
    assert path.exists()
    path.unlink()   # keep benchmark/results clean


def test_static_page(server):
    status, ctype, body = get(server + "/")
    assert status == 200 and b"building-block lab" in body
    status, ctype, _ = get(server + "/lab.js")
    assert ctype.startswith("text/javascript")


def test_parse_peer():
    assert lab.parse_peer("192.168.1.20:5050") == ("192.168.1.20", 5050)
    assert lab.parse_peer("") is None
    with pytest.raises(ValueError):
        lab.parse_peer("nonsense")
