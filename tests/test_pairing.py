"""Pairing in the web lab: one laptop is Bob, the other joins with the code.

Both "laptops" are Pairing objects in this process. The beacons go to
127.0.0.1 on a test port, so the test does not depend on the Wi-Fi."""
import pytest

from twoparty import lab, pairing
from twoparty.config import Config

PORT = 50613


@pytest.fixture
def pair():
    bob = pairing.Pairing(beacon_port=PORT)
    alice = pairing.Pairing(beacon_port=PORT)
    st = bob.host("Bruno", targets=["127.0.0.1"])
    alice.join(st["code"], timeout=5)
    yield bob, alice
    bob.stop()
    alice.stop()


def test_join_finds_bob(pair):
    bob, alice = pair
    st = alice.status()
    assert st["mode"] == "joined" and st["partner"] == "Bruno"
    assert alice.bob()[0][1] == bob.status()["port"]


def test_wrong_code_is_not_found():
    bob = pairing.Pairing(beacon_port=PORT + 1)
    code = bob.host("Bruno", targets=["127.0.0.1"])["code"]
    other = str((int(code) + 1) % 10000).zfill(4)
    try:
        with pytest.raises(LookupError):
            pairing.Pairing(beacon_port=PORT + 1).join(other, timeout=1.5)
    finally:
        bob.stop()


@pytest.mark.parametrize("cfg", [Config(), Config(mta="reuse", flow="batched", wire="binary")],
                         ids=lambda c: c.label())
def test_study_with_partner_as_bob(pair, cfg):
    bob, alice = pair
    peer, partner = alice.bob()
    t = lab.study(cfg, "toy", "1 coin to Carol", peer=peer, partner=partner)
    assert t["valid"] and t["bob"].startswith("Bruno")
    assert any(e.get("remote") for e in t["events"])
    # Order respects every message: nobody receives before it was sent.
    sent = {"alice": 0, "bob": 0}
    for e in t["events"]:
        if e["kind"] == "message":
            sent[e["party"]] += 1
    assert sent["alice"] + sent["bob"] == t["messages"]
    assert bob.status()["last_study"]["label"] == cfg.label()


def test_experiment_with_partner(pair):
    _, alice = pair
    peer, partner = alice.bob()
    t = lab.study(Config(mask=False), "toy", "steal", peer=peer, partner=partner)
    assert t["stolen_ok"] is True


def test_benchmark_with_partner(pair):
    _, alice = pair
    peer, _ = alice.bob()
    job = lab.Job([Config()], "toy", 3, peer=peer).start()
    job.thread.join(timeout=60)
    assert job.rows and job.rows[0]["n"] == 3 and job.rows[0]["msgs_per_sig"] >= 14
    if job.csv_path and job.csv_path.exists():
        job.csv_path.unlink()


def test_merge_waits_for_messages():
    a = [{"kind": "step", "party": "alice", "n": 1}, {"kind": "message", "party": "alice"},
         {"kind": "recv", "party": "alice"}, {"kind": "step", "party": "alice", "n": 2}]
    b = [{"kind": "recv", "party": "bob"}, {"kind": "step", "party": "bob", "n": 1},
         {"kind": "message", "party": "bob"}]
    out = lab.merge(a, b)
    order = [(e["party"], e["kind"]) for e in out]
    assert order == [("alice", "step"), ("alice", "message"), ("bob", "step"),
                     ("bob", "message"), ("alice", "step")]
