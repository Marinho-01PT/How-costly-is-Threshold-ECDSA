"""Pairing for the web lab: two laptops on the same Wi-Fi, one plays Bob.

One person clicks "Be Bob" and gets a 4-digit code. This laptop then listens
on its Wi-Fi address and announces itself with lan.Beacon. The other person
types the code and clicks "Join": lan.find() returns Bob's address, and from
then on study mode and benchmark mode on that laptop use the partner as Bob.

Bob serves three kinds of sessions on one port:
  study   one recorded signature (lab.serve_study), events go back to Alice
  sign    the benchmark (bench.sign_bob), as with python -m twoparty --role bob
  ping    "are you there?", for the status line

The code only keeps you from pairing with a stranger by mistake. It is not a
password: anyone on the network can read the beacons.
"""
import datetime
import socket
import threading

from . import bench, lab, lan, net
from .config import Config
from .ec import CURVES

TASK = "lab"   # beacons of the lab never match the terminal demo's, and vice versa


def default_name() -> str:
    return socket.gethostname().split(".")[0]


class Pairing:
    def __init__(self, beacon_port: int = lan.BEACON_PORT):
        self.beacon_port = beacon_port
        self.lock = threading.Lock()
        self.mode = "alone"           # alone | host | joined
        self.code = None
        self.name = default_name()
        self.peer = None              # (host, port) of Bob, when joined
        self.partner = ""
        self.log: list[dict] = []     # sessions this laptop served as Bob
        self.last_study = None        # what Bob did in the last study run
        self._srv = None
        self._beacon = None

    # ---- state for the page
    def status(self) -> dict:
        with self.lock:
            return {"mode": self.mode, "code": self.code, "name": self.name,
                    "ip": lan.local_ip(),
                    "port": self._srv.getsockname()[1] if self._srv else None,
                    "peer": f"{self.peer[0]}:{self.peer[1]}" if self.peer else None,
                    "partner": self.partner, "log": self.log[-8:],
                    "last_study": self.last_study}

    # ---- be Bob
    def host(self, name: str = "", targets=None) -> dict:
        self.stop()
        srv = net.listen("0.0.0.0", 0)
        port = srv.getsockname()[1]
        code = lan.new_code()
        with self.lock:
            self.mode, self.code, self.name = "host", code, name or default_name()
            self._srv = srv
            self.log, self.last_study = [], None
            self._beacon = lan.Beacon(code, TASK, port, name=self.name, role="alice",
                                      targets=targets, beacon_port=self.beacon_port).start()
        threading.Thread(target=self._serve, args=(srv,), daemon=True).start()
        return self.status()

    def _serve(self, srv) -> None:
        srv.settimeout(0.5)                  # wake up now and then to see if stop() was called
        while self._srv is srv:
            try:
                ch = net.accept(srv)
            except socket.timeout:
                continue
            except OSError:
                return                       # stop() closed the socket
            ch.sock.settimeout(None)
            threading.Thread(target=self._session, args=(ch,), daemon=True).start()

    def _session(self, ch: net.Channel) -> None:
        who = ch.sock.getpeername()[0]
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "from": who}
        try:
            hello = ch.recv()
            task = hello.get("task")
            entry["task"] = task
            if task == "ping":
                ch.send({"pong": self.name})
                return
            if task == "study":
                result = lab.serve_study(ch, hello)
                entry["what"] = f"study, {result['label']}"
                with self.lock:
                    self.last_study = {**result, "from": who}
            elif task == "sign":
                cfg = Config.from_dict(hello.get("config"))
                ch.set_format(cfg.wire)
                entry["what"] = f"benchmark, {cfg.label()}, {hello.get('rounds')} signatures"
                bench.sign_bob(ch, CURVES[hello["curve"]], cfg, hello.get("rounds", 0))
            else:
                entry["what"] = f"unknown task {task!r}"
        except ConnectionError:
            pass                             # Alice closed after the benchmark: normal
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            ch.close()
            if entry.get("task") != "ping":
                with self.lock:
                    self.log.append(entry)

    # ---- join a partner
    def join(self, code: str, timeout: float = 15.0) -> dict:
        code = code.strip()
        if not (code.isdigit() and len(code) == 4):
            raise ValueError("the code has 4 digits")
        self.stop()
        found = lan.find(code, TASK, timeout=timeout, beacon_port=self.beacon_port)
        if found is None:
            raise LookupError(lan.HINT)
        peer = (found["host"], int(found["port"]))
        ch = net.connect(*peer, retries=10)  # check that Bob really answers
        try:
            ch.send({"task": "ping"})
            ch.recv()
        finally:
            ch.close()
        with self.lock:
            self.mode, self.code, self.peer = "joined", code, peer
            self.partner = found.get("name") or found["host"]
        return self.status()

    def bob(self):
        """(peer, partner name) to use as Bob, or (None, '') to run Bob here."""
        with self.lock:
            return (self.peer, self.partner) if self.mode == "joined" else (None, "")

    def stop(self) -> dict:
        with self.lock:
            if self._beacon:
                self._beacon.stop()
            if self._srv:
                try:
                    self._srv.close()
                except OSError:
                    pass
            self._srv = self._beacon = None
            self.mode, self.code, self.peer, self.partner = "alone", None, None, ""
        return self.status()


PAIRING = Pairing()
