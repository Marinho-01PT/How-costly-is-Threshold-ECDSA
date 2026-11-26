"""Find the other laptop on the same Wi-Fi, without typing IP addresses.

One person hosts: the program picks a 4-digit pairing code, prints it, and
announces itself every half second by UDP broadcast on port 5051:

    {"app": "twoparty", "v": 1, "code": "4821", "task": "demo",
     "name": "Keanu", "role": "bob", "port": 5050}

The other person types the code. Their program listens for a beacon with that
code (and the same task and version), takes the sender's address from the
packet and connects to it over TCP. Beacons with another code are ignored, so
on a university Wi-Fi you do not end up with a stranger's laptop. The code is
not a password: anyone on the network can read the beacons. It only prevents
mix-ups, which is all the demo needs.

Standard library only. Limits, and what the hint says:
  - Both laptops must be in the same network (same Wi-Fi, no VPN).
  - Many university and public networks (eduroam, guest Wi-Fi) block traffic
    between devices ("client isolation"). Then use a phone hotspot.
  - macOS asks once whether Python may accept incoming connections. Allow it,
    otherwise neither the beacon nor the connection gets through.
"""
import json
import secrets
import socket
import threading
import time

BEACON_PORT = 5051
VERSION = 1
APP = "twoparty"

HINT = """No partner found. Check:
  1. Same network: both laptops on the same Wi-Fi (no VPN, not one on Ethernet
     in another network).
  2. Same pairing code, and the host started first.
  3. macOS firewall: when macOS asks whether Python may accept incoming
     connections, click Allow (System Settings > Network > Firewall).
  4. University or guest Wi-Fi (e.g. eduroam) often blocks traffic between
     devices. Use a phone hotspot instead, both laptops on it.
  5. Still nothing: type the address the host printed, e.g. --hub 192.168.1.23:5050"""


def new_code() -> str:
    """A 4-digit pairing code."""
    return f"{secrets.randbelow(10000):04d}"


def local_ip() -> str:
    """This laptop's address in the local network (not 127.0.0.1).

    Connecting a UDP socket sends nothing; it only asks the OS which interface
    and address it would use for that destination, i.e. the default route. With
    Wi-Fi and Ethernet both on, that is the one the other laptop most likely
    sees. Without any network it falls back to 127.0.0.1.
    """
    for probe in ("192.168.0.1", "10.255.255.255", "8.8.8.8"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((probe, 1))
            ip = s.getsockname()[0]
            if not ip.startswith("127.") and ip != "0.0.0.0":
                return ip
        except OSError:
            pass
        finally:
            s.close()
    return "127.0.0.1"


def broadcast_targets(ip: str) -> list[str]:
    """Where to send beacons: the general broadcast and the /24 guess.

    macOS sometimes sends 255.255.255.255 only on one interface; the
    subnet-directed address (e.g. 192.168.1.255) reaches the Wi-Fi in that case.
    Home and hotspot networks are almost always /24.
    """
    out = ["255.255.255.255"]
    if not ip.startswith("127."):
        out.append(ip.rsplit(".", 1)[0] + ".255")
    return out


class Beacon:
    """Announce this host until stop() is called (runs in a daemon thread)."""

    def __init__(self, code: str, task: str, port: int, name: str = "", role: str = "",
                 targets: list[str] | None = None, beacon_port: int = BEACON_PORT,
                 interval: float = 0.5, extra: dict | None = None):
        self.msg = json.dumps({"app": APP, "v": VERSION, "code": code, "task": task,
                               "name": name, "role": role, "port": port,
                               **(extra or {})}).encode()
        self.targets = targets or broadcast_targets(local_ip())
        self.beacon_port = beacon_port
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "Beacon":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            while not self._stop.is_set():
                for t in self.targets:
                    try:
                        s.sendto(self.msg, (t, self.beacon_port))
                    except OSError:
                        pass  # e.g. no network right now; keep trying
                self._stop.wait(self.interval)
        finally:
            s.close()


def find(code: str, task: str, timeout: float = 20.0,
         beacon_port: int = BEACON_PORT) -> dict | None:
    """Wait for a beacon with this code and task. Returns it with "host" set
    to the sender's address, or None after timeout."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):  # two programs on one machine may listen
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("", beacon_port))
    deadline = time.monotonic() + timeout
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            s.settimeout(left)
            try:
                data, (host, _) = s.recvfrom(4096)
            except (TimeoutError, socket.timeout):
                return None
            try:
                msg = json.loads(data)
            except ValueError:
                continue
            if (isinstance(msg, dict) and msg.get("app") == APP and msg.get("v") == VERSION
                    and msg.get("code") == code and msg.get("task") == task):
                return {**msg, "host": host}
    finally:
        s.close()
