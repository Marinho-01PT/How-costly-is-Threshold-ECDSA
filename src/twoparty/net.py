"""A small message channel between the two parties.

Messages are JSON objects with a 4-byte length prefix. The channel counts
messages and bytes, so the benchmark can report them next to the timings.
"""
import json
import socket
import struct
import time


class Channel:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        # Without this, small messages can wait up to 40 ms and spoil the timings.
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sent_msgs = self.recv_msgs = 0
        self.sent_bytes = self.recv_bytes = 0

    def send(self, obj) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode()
        self.sock.sendall(struct.pack(">I", len(data)) + data)
        self.sent_msgs += 1
        self.sent_bytes += 4 + len(data)

    def recv(self):
        (n,) = struct.unpack(">I", self._read(4))
        data = self._read(n)
        self.recv_msgs += 1
        self.recv_bytes += 4 + n
        return json.loads(data)

    def _read(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed the connection")
            buf.extend(chunk)
        return bytes(buf)

    def stats(self) -> dict:
        return {
            "sent_msgs": self.sent_msgs, "recv_msgs": self.recv_msgs,
            "sent_bytes": self.sent_bytes, "recv_bytes": self.recv_bytes,
        }

    def close(self) -> None:
        self.sock.close()


def listen(host: str, port: int) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    return srv


def accept(srv: socket.socket) -> Channel:
    sock, _ = srv.accept()
    return Channel(sock)


def connect(host: str, port: int, retries: int = 50, delay: float = 0.1) -> Channel:
    """Connect to the other party, retrying while it is still starting up."""
    last = None
    for _ in range(retries):
        try:
            return Channel(socket.create_connection((host, port), timeout=5))
        except OSError as exc:
            last = exc
            time.sleep(delay)
    raise ConnectionError(f"could not reach {host}:{port}") from last
