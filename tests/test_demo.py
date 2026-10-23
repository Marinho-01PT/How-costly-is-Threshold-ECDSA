import json
import threading

import pytest

from twoparty import demo, net


def free_port() -> int:
    srv = net.listen("127.0.0.1", 0)
    port = srv.getsockname()[1]
    srv.close()
    return port


def run_demo(mode="toy", experiment="no", events=None, message="pay 1 BTC to Bob"):
    """Observer and Bob in threads, Alice here. pace=run: nobody waits for Enter."""
    hub = f"127.0.0.1:{free_port()}"
    obs_args = ["observer", "--listen", hub, "--mode", mode, "--pace", "run",
                "--experiment", experiment]
    if events:
        obs_args += ["--events", str(events)]
    threads = [threading.Thread(target=demo.main, args=(obs_args,), daemon=True),
               threading.Thread(target=demo.main, args=(["bob", "--hub", hub],), daemon=True)]
    for t in threads:
        t.start()
    assert demo.main(["alice", "--hub", hub, "--message", message]) == 0
    for t in threads:
        t.join(timeout=10)


def test_demo_signs(capsys):
    run_demo()
    out = capsys.readouterr().out
    assert "[Alice] signature valid" in out and "[Bob] signature valid" in out
    assert "MtA k1*d2: alpha = Dec(c_B) mod n" in out
    assert "wrong, beta' hid Bob's share" in out
    # 2 setup + 2 (message, approval) + 14 for the signature (+ 12 per restart)
    assert "[network] #18 " in out
    assert "anyone on the network can now compute" in out


def test_study_mode_fills_in_the_formulas(capsys):
    run_demo(mode="study")
    out = capsys.readouterr().out
    assert "mode study" in out
    for line in ("> alpha = plain mod n = ", "> beta = -beta' mod n = ", "> delta1 = ",
                 "> sigma2 = ", "> delta^-1 = ", "> s1 = e*k1 + r*sigma1 = ", "> low s: "):
        assert line in out, line
    assert "B = n^2 * 2^4 = 1567504" in out
    assert "[Alice] signature valid" in out


def test_experiment_steals_the_key(capsys):
    run_demo(experiment="yes")
    out = capsys.readouterr().out
    assert "EXPERIMENT: Bob leaves out beta'" in out
    assert "Bob's key share is stolen" in out


def test_event_log_has_all_three_views(tmp_path, capsys):
    path = tmp_path / "events.jsonl"
    run_demo(mode="study", events=path)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert {e["who"] for e in events} == {"alice", "bob", "network"}
    assert events[0]["step"] == "settings"
    alpha = [e for e in events if e["who"] == "alice" and "alpha[k1*d2]" in e["values"]]
    assert alpha and alpha[0]["values"]["alpha[k1*d2]"]["kind"] == "int"
    # The network only ever sees what was sent, never Alice's or Bob's secrets.
    network_keys = {k for e in events if e["who"] == "network" for k in e["values"]}
    assert not network_keys & {"k1", "k2", "d1", "d2", "gamma1", "gamma2", "beta_prime"}


def test_demo_secp256k1_shortens_numbers(capsys):
    run_demo(mode="secp256k1")
    out = capsys.readouterr().out
    assert "libsecp256k1: valid" in out
    assert "digits)" in out  # the 2048-bit Paillier numbers are cut short


def test_fmt():
    assert demo.fmt(42) == "42"
    assert demo.fmt((1, 2)) == "(1, 2)"
    big = 10**50
    assert demo.fmt(big).endswith("(51 digits)") and demo.fmt(big, full=True) == str(big)


def test_silent_port_gives_a_clear_error(monkeypatch):
    """Like AirPlay on port 5000: accepts the connection, never answers.
    Alice must stop with an explanation instead of hanging."""
    monkeypatch.setattr(demo, "GREETING_TIMEOUT", 0.5)
    srv = net.listen("127.0.0.1", 0)
    port = srv.getsockname()[1]
    threading.Thread(target=srv.accept, daemon=True).start()
    with pytest.raises(SystemExit, match="AirPlay"):
        demo.main(["alice", "--hub", f"127.0.0.1:{port}", "--message", "hi"])
    srv.close()
