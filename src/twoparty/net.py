"""A small message channel between the two parties.

Messages have a 4-byte length prefix. The body is JSON (numbers as decimal
text, the original variant) or, after set_format("binary"), a compact binary
encoding with numbers as raw bytes. The channel counts messages and bytes, so
the benchmark can report them next to the timings.

The first message of a session (the "hello" that names the task) is always
JSON. Both sides switch to the chosen format right after it.
"""
import json
import socket
import struct
import time


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def encode(obj) -> bytes:
    """Binary form of a message: dicts, lists, ints, floats, str, bool and None."""
    if obj is None:
        return b"N"
    if obj is True or obj is False:
        return b"T" if obj else b"F"
    if isinstance(obj, int):
        mag = abs(int(obj))
        raw = mag.to_bytes((mag.bit_length() + 7) // 8, "big")
        return (b"-" if obj < 0 else b"i") + _varint(len(raw)) + raw
    if isinstance(obj, float):
        return b"f" + struct.pack(">d", obj)
    if isinstance(obj, str):
        raw = obj.encode()
        return b"s" + _varint(len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        return b"l" + _varint(len(obj)) + b"".join(encode(x) for x in obj)
    if isinstance(obj, dict):
        parts = [b"d", _varint(len(obj))]
        for k, v in obj.items():
            kb = str(k).encode()
            parts += [_varint(len(kb)), kb, encode(v)]
        return b"".join(parts)
    raise TypeError(f"cannot encode {type(obj).__name__}")


def decode(data: bytes):
    obj, i = _decode(data, 0)
    if i != len(data):
        raise ValueError("trailing bytes in message")
    return obj


def _read_varint(data: bytes, i: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        b = data[i]
        i += 1
        n |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return n, i


def _decode(data: bytes, i: int):
    tag = data[i:i + 1]
    i += 1
    if tag == b"N":
        return None, i
    if tag in (b"T", b"F"):
        return tag == b"T", i
    if tag in (b"i", b"-"):
        n, i = _read_varint(data, i)
        v = int.from_bytes(data[i:i + n], "big")
        return (-v if tag == b"-" else v), i + n
    if tag == b"f":
        return struct.unpack(">d", data[i:i + 8])[0], i + 8
    if tag == b"s":
        n, i = _read_varint(data, i)
        return data[i:i + n].decode(), i + n
    if tag == b"l":
        n, i = _read_varint(data, i)
        out = []
        for _ in range(n):
            v, i = _decode(data, i)
            out.append(v)
        return out, i
    if tag == b"d":
        n, i = _read_varint(data, i)
        out = {}
        for _ in range(n):
            kl, i = _read_varint(data, i)
            k = data[i:i + kl].decode()
            out[k], i = _decode(data, i + kl)
        return out, i
    raise ValueError(f"unknown tag {tag!r}")


class Channel:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        # Without this, small messages can wait up to 40 ms and spoil the timings.
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sent_msgs = self.recv_msgs = 0
        self.sent_bytes = self.recv_bytes = 0
        self.fmt = "json"

    def set_format(self, fmt: str) -> None:
        if fmt not in ("json", "binary"):
            raise ValueError("format must be json or binary")
        self.fmt = fmt

    def send(self, obj) -> None:
        if self.fmt == "binary":
            data = encode(obj)
        else:
            data = json.dumps(obj, separators=(",", ":")).encode()
        self.sock.sendall(struct.pack(">I", len(data)) + data)
        self.sent_msgs += 1
        self.sent_bytes += 4 + len(data)

    def recv(self):
        (n,) = struct.unpack(">I", self._read(4))
        data = self._read(n)
        self.recv_msgs += 1
        self.recv_bytes += 4 + n
        return decode(data) if self.fmt == "binary" else json.loads(data)

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
            sock = socket.create_connection((host, port), timeout=5)
        except OSError as exc:
            last = exc
            time.sleep(delay)
            continue
        # The timeout is only for connecting. Left on, every later recv would
        # fail after 5 s, e.g. while the other side waits for Enter in the demo.
        sock.settimeout(None)
        return Channel(sock)
    raise ConnectionError(f"could not reach {host}:{port}") from last
