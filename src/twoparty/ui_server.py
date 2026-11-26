"""Local web server for the building-block lab (web/lab/). Standard library only.

    python -m twoparty ui            -> http://127.0.0.1:8765

API (JSON):
    GET  /api/rows                 building blocks and their variants (config.ROWS)
    POST /api/study                one recorded signature
                                   {config, curve, message} -> trace
    POST /api/auto                 start a benchmark
                                   {config, curve, rounds, kind, peer} -> {job}
    GET  /api/events/<job>         Server-Sent Events: start, running, row, done, error
    GET  /api/csv/<job>            the job's CSV (also saved in benchmark/results/)

Static files: / is web/lab/, /shared/ is web/ (the visualizer's CSS and helpers).
"""
import json
import mimetypes
import threading
import uuid
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import lab, pairing

WEB = lab.ROOT / "web"
JOBS: dict[str, lab.Job] = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "twoparty-lab"

    def log_message(self, fmt, *args):  # quiet; errors still reach the page
        pass

    # ---- helpers
    def _json(self, obj, status=HTTPStatus.OK):
        data = lab.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _static(self, path: str):
        if path in ("", "/"):
            path = "/index.html"
        base = WEB / "lab"
        if path.startswith("/shared/"):
            base, path = WEB, path[len("/shared"):]
        f = (base / path.lstrip("/")).resolve()
        if not str(f).startswith(str(WEB.resolve())) or not f.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        data = f.read_bytes()
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        if f.suffix == ".js":
            ctype = "text/javascript"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # ---- routes
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/pair":
            return self._json(pairing.PAIRING.status())
        if path == "/api/rows":
            return self._json({"rows": lab.rows(), "curves": lab.curves()})
        if path.startswith("/api/events/"):
            return self._events(path.rsplit("/", 1)[1])
        if path.startswith("/api/csv/"):
            job = JOBS.get(path.rsplit("/", 1)[1])
            if not job or not job.csv_path or not job.csv_path.exists():
                return self.send_error(HTTPStatus.NOT_FOUND)
            data = job.csv_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{job.csv_path.name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        return self._static(path)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            body = self._body()
            if path == "/api/pair/host":
                return self._json(pairing.PAIRING.host(body.get("name", "")))
            if path == "/api/pair/join":
                try:
                    return self._json(pairing.PAIRING.join(str(body.get("code", ""))))
                except LookupError as exc:
                    return self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
                except OSError as exc:
                    return self._json({"error": f"found the partner but could not connect: {exc}"},
                                      HTTPStatus.BAD_GATEWAY)
            if path == "/api/pair/leave":
                return self._json(pairing.PAIRING.stop())
            curve = body.get("curve", "toy")
            cfg = lab.make_config(body.get("config"), curve)
            peer, partner = pairing.PAIRING.bob()
            if path == "/api/study":
                return self._json(lab.study(cfg, curve, body.get("message") or
                                            "Alice and Bob send 1 coin to Carol",
                                            peer=peer, partner=partner))
            if path == "/api/auto":
                rounds = max(1, min(int(body.get("rounds", 10)), 1000))
                configs = lab.configs_for(body.get("kind", "current"), cfg, curve)
                job = lab.Job(configs, curve, rounds, lab.parse_peer(body.get("peer")) or peer).start()
                jid = uuid.uuid4().hex[:12]
                JOBS[jid] = job
                return self._json({"job": jid, "configs": [c.label() for c in configs]})
        except (ValueError, KeyError) as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            return self._json({"error": f"{type(exc).__name__}: {exc}"},
                              HTTPStatus.INTERNAL_SERVER_ERROR)
        self.send_error(HTTPStatus.NOT_FOUND)

    def _events(self, jid: str):
        job = JOBS.get(jid)
        if job is None:
            return self.send_error(HTTPStatus.NOT_FOUND)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        sent = 0
        try:
            while True:
                with job.cond:
                    while sent >= len(job.events) and not job.done:
                        job.cond.wait(timeout=15)
                        if sent >= len(job.events) and not job.done:
                            self.wfile.write(b": keep-alive\n\n")
                            self.wfile.flush()
                    new = job.events[sent:]
                    finished = job.done
                for ev in new:
                    self.wfile.write(f"data: {lab.dumps(ev)}\n\n".encode())
                sent += len(new)
                self.wfile.flush()
                if finished and sent >= len(job.events):
                    return
        except (BrokenPipeError, ConnectionResetError):
            return


def make_server(host="127.0.0.1", port=8765) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def serve(host="127.0.0.1", port=8765, open_browser=True) -> int:
    srv = make_server(host, port)
    url = f"http://{host}:{srv.server_address[1]}/"
    print(f"building-block lab on {url}  (Ctrl+C to stop)", flush=True)
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        lab.LOCAL_BOB.stop()
        pairing.PAIRING.stop()
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
