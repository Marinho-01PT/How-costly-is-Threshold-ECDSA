"""Finding the other laptop: beacons with a pairing code, then the demo and
the benchmark over the found address. Runs on loopback (127.0.0.1), with a
free UDP port instead of 5051, so it works without Wi-Fi and in parallel."""
import socket
import threading

from twoparty import __main__ as cli
from twoparty import demo, lan


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def free_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_find_with_the_right_code():
    bp = free_udp_port()
    b = lan.Beacon("4821", "demo", 5050, name="Keanu", role="alice",
                   targets=["127.0.0.1"], beacon_port=bp, interval=0.05).start()
    try:
        found = lan.find("4821", "demo", timeout=3, beacon_port=bp)
    finally:
        b.stop()
    assert found["port"] == 5050 and found["name"] == "Keanu"
    assert found["host"] == "127.0.0.1" and found["role"] == "alice"


def test_other_code_or_task_is_ignored():
    bp = free_udp_port()
    beacons = [lan.Beacon("1111", "demo", 5050, targets=["127.0.0.1"], beacon_port=bp,
                          interval=0.05).start(),
               lan.Beacon("4821", "bench", 5050, targets=["127.0.0.1"], beacon_port=bp,
                          interval=0.05).start()]
    try:
        assert lan.find("4821", "demo", timeout=0.6, beacon_port=bp) is None
    finally:
        for b in beacons:
            b.stop()


def test_garbage_packets_are_ignored():
    bp = free_udp_port()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def spam():
        for _ in range(5):
            s.sendto(b"not json", ("127.0.0.1", bp))
            s.sendto(b'{"app": "other"}', ("127.0.0.1", bp))
    t = threading.Timer(0.1, spam)
    t.start()
    assert lan.find("4821", "demo", timeout=0.5, beacon_port=bp) is None
    s.close()


def test_codes_and_addresses():
    codes = {lan.new_code() for _ in range(50)}
    assert all(len(c) == 4 and c.isdigit() for c in codes) and len(codes) > 10
    ip = lan.local_ip()
    socket.inet_aton(ip)  # a valid IPv4 address
    assert lan.broadcast_targets("192.168.1.23") == ["255.255.255.255", "192.168.1.255"]
    assert lan.broadcast_targets("127.0.0.1") == ["255.255.255.255"]


def test_demo_over_lan(capsys):
    """Host (relay + Bob) in a thread, the joiner finds it by code and plays Alice."""
    bp = free_udp_port()
    common = ["--beacon-port", str(bp), "--beacon-addr", "127.0.0.1"]
    host = threading.Thread(target=demo.main, daemon=True, args=([
        "lan", "--host", "--code", "4821", "--port", str(free_tcp_port()), "--name", "Bruno",
        "--mode", "toy", "--pace", "run", "--experiment", "no", *common],))
    host.start()
    assert cli.main(["lan", "--code", "4821", "--timeout", "10",
                     "--message", "Alice and Bob send 1 BTC to Carol", *common]) == 0
    host.join(timeout=10)
    out = capsys.readouterr().out
    assert "Pairing code: 4821" in out
    assert "found the host (Bruno)" in out and "plays Alice" in out
    assert "[Alice] signature valid" in out and "[Bob] signature valid" in out
    assert "[network] #" not in out  # the relay on the host stays quiet


def test_demo_join_without_host_gives_the_hint(capsys):
    assert demo.main(["lan", "--code", "9999", "--timeout", "0.3",
                      "--beacon-port", str(free_udp_port())]) == 1
    out = capsys.readouterr().out
    assert "No partner found" in out and "hotspot" in out


def test_benchmark_over_lan(capsys):
    bp = free_udp_port()
    port = free_tcp_port()
    common = ["--beacon-port", str(bp), "--beacon-addr", "127.0.0.1"]
    bob = threading.Thread(target=cli.main, daemon=True, args=(
        ["--role", "bob", "--lan", "--code", "4821", "--listen", f"127.0.0.1:{port}",
         "--once", *common],))
    bob.start()
    assert cli.main(["--role", "alice", "--task", "sign", "--curve", "toy", "--rounds", "3",
                     "--lan", "--code", "4821", "--timeout", "10", *common]) == 0
    bob.join(timeout=10)
    out = capsys.readouterr().out
    assert "pairing code 4821" in out and f"found Bob at 127.0.0.1:{port}" in out
    assert '"task": "sign"' in out and '"n": 3' in out
