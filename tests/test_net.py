import threading
import time

from twoparty import bench, net


def test_echo_over_localhost():
    srv = net.listen("127.0.0.1", 0)
    port = srv.getsockname()[1]

    def serve():
        ch = net.accept(srv)
        bench.echo_bob(ch)
        ch.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    ch = net.connect("127.0.0.1", port)
    samples = bench.echo_alice(ch, rounds=20, payload=32)
    stats = ch.stats()
    ch.close()
    t.join(timeout=2)
    srv.close()

    assert len(samples) == 20
    assert all(s >= 0 for s in samples)
    assert stats["sent_msgs"] == 20 and stats["recv_msgs"] == 20
    assert stats["sent_bytes"] == stats["recv_bytes"]


def test_big_numbers_survive_json():
    srv = net.listen("127.0.0.1", 0)
    port = srv.getsockname()[1]
    big = 2**255 + 12345

    def serve():
        ch = net.accept(srv)
        ch.send(ch.recv())
        ch.close()

    threading.Thread(target=serve, daemon=True).start()
    ch = net.connect("127.0.0.1", port)
    ch.send({"x": big})
    assert ch.recv() == {"x": big}
    ch.close()
    srv.close()


def test_no_timeout_after_connecting():
    """The other side may take its time (the demo waits for Enter):
    recv must not give up after the 5 s connect timeout."""
    srv = net.listen("127.0.0.1", 0)
    port = srv.getsockname()[1]

    def serve():
        ch = net.accept(srv)
        time.sleep(6)  # longer than the connect timeout
        ch.send({"ok": True})
        ch.close()

    threading.Thread(target=serve, daemon=True).start()
    ch = net.connect("127.0.0.1", port)
    assert ch.sock.gettimeout() is None
    assert ch.recv() == {"ok": True}
    ch.close()
    srv.close()
