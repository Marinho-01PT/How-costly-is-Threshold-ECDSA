import threading

import pytest

from twoparty import mta, net, paillier
from twoparty.ec import TOY


@pytest.fixture(scope="session")
def toy_key():
    return paillier.keygen(mta.key_bits(TOY.n))  # 58 bits


@pytest.fixture(scope="session")
def secp_key():
    """2048 bits, as for the real protocol. Takes a few seconds, made once."""
    return paillier.keygen(2048)


@pytest.fixture
def run_pair():
    """Run alice(channel) here and bob(channel) in a thread, over localhost.

    Returns (alice's result, bob's result, alice's channel stats). An error on
    Bob's side is raised here, so a test cannot pass while Bob crashed.
    """
    def run(alice, bob):
        srv = net.listen("127.0.0.1", 0)
        port = srv.getsockname()[1]
        out = {}

        def serve():
            ch = net.accept(srv)
            try:
                out["bob"] = bob(ch)
            except BaseException as exc:
                out["error"] = exc
            finally:
                ch.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        ch = net.connect("127.0.0.1", port)
        try:
            result = alice(ch)
            stats = ch.stats()
        finally:
            ch.close()
            t.join(timeout=60)
            srv.close()
            if "error" in out:
                raise out["error"]
        return result, out["bob"], stats

    return run
