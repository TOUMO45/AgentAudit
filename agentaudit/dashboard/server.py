"""Stdlib-only HTTP server for the AgentAudit dashboard.

No new dependencies (charter rule 3): ``http.server`` + ``json`` only.

    python -m agentaudit.dashboard.server [--port 8770] [--open]

Endpoints
    GET  /                  dashboard UI
    GET  /api/state         full snapshot (scans, org, policies, agents)
    GET  /api/policies      generated Cedar policies + deployment status
    GET  /api/agents        live agent discovery
    POST /api/scan          {"target": "<path>"} -> run a REAL audit
    POST /api/scan-remote   {"url": "https://github.com/<owner>/<repo>"}
                            -> shallow-clone a public repo, Layer 2 static scan
    POST /api/scan-all      {"targets": [...]}   -> org-wide real audit
    POST /api/reset         clear dashboard state (for honest empty-state demo)
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agentaudit.dashboard.backend import DashboardState

UI_FILE = Path(__file__).parent / "ui.html"
STATE = DashboardState()


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentAudit/0.2"

    def log_message(self, fmt, *args):  # quieter console
        print(f"  [http] {self.address_string()} {fmt % args}")

    # --- helpers ---------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, indent=2).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    # --- routes ----------------------------------------------------------
    def do_GET(self):  # noqa: N802
        if self.path in ("/", "/index.html"):
            if not UI_FILE.exists():
                return self._json({"error": "ui.html missing"}, 500)
            return self._send(200, UI_FILE.read_bytes(), "text/html; charset=utf-8")
        if self.path == "/api/state":
            return self._json(STATE.snapshot())
        if self.path == "/api/policies":
            return self._json(STATE.policies_view())
        if self.path == "/api/agents":
            return self._json(STATE.agents_view())
        return self._json({"error": "not found", "path": self.path}, 404)

    def do_POST(self):  # noqa: N802
        body = self._body()
        try:
            if self.path == "/api/scan":
                target = body.get("target")
                if not target:
                    return self._json({"error": "missing 'target'"}, 400)
                if not Path(target).exists():
                    return self._json({"error": f"no such file: {target}"}, 400)
                rec = STATE.run_scan(
                    target,
                    remediate=body.get("remediate", True),
                    dry_run=body.get("dry_run", True),
                    gateway_arn=body.get("gateway_arn", ""),
                    gateway_id=body.get("gateway_id", ""),
                )
                return self._json({"ok": True, "scan": rec})

            if self.path == "/api/scan-remote":
                url = body.get("url")
                if not url or not isinstance(url, str):
                    return self._json({"error": "missing 'url'", "code": "invalid_url"}, 400)
                from agentaudit.dashboard.remote_scan import RemoteScanError
                try:
                    rec = STATE.run_remote_scan(url)
                except RemoteScanError as exc:
                    return self._json(
                        {"error": str(exc), "code": exc.code}, exc.http_status
                    )
                return self._json({"ok": True, "scan": rec})

            if self.path == "/api/scan-all":
                targets = body.get("targets") or []
                missing = [t for t in targets if not Path(t).exists()]
                if missing:
                    return self._json({"error": "missing files", "files": missing}, 400)
                return self._json({"ok": True, "result": STATE.run_org_scan(targets)})

            if self.path == "/api/reset":
                STATE.clear()
                return self._json({"ok": True, "state": "empty"})
        except Exception as e:  # never leak a stack trace as a 200
            return self._json({"error": f"{type(e).__name__}: {e}"}, 500)

        return self._json({"error": "not found", "path": self.path}, 404)


def _bind(host: str, port: int, tries: int = 10) -> ThreadingHTTPServer:
    """Bind the HTTP server, walking forward from ``port`` if it is in use."""
    last_err: OSError | None = None
    for p in range(port, port + tries):
        try:
            return ThreadingHTTPServer((host, p), Handler)
        except OSError as e:  # port already bound
            last_err = e
    raise last_err if last_err else OSError("could not bind a port")


def serve(host: str = "127.0.0.1", port: int = 8770, open_browser: bool = True) -> int:
    """Start the dashboard HTTP server and (optionally) open a browser to it.

    The UI is served over HTTP from ``/`` so that ``fetch('/api/...')`` resolves
    against a real origin. It is never opened as a ``file://`` path — doing so
    breaks every API call and leaves the pipeline stuck on RUNNING.
    """
    srv = _bind(host, port)
    actual_port = srv.server_address[1]
    url = f"http://{host}:{actual_port}/"

    print(f"AgentAudit dashboard -> {url}", flush=True)
    print("  serving over HTTP (never file://); all data is live, nothing is mocked", flush=True)
    if actual_port != port:
        print(f"  note: port {port} was busy, using {actual_port}", flush=True)

    if open_browser:
        print("  opening your browser...", flush=True)

        def _open():
            time.sleep(0.6)  # let serve_forever get going first
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()
    else:
        print("  (--no-open) open the URL above yourself", flush=True)

    print("  press Ctrl+C to stop", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        srv.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentaudit-dashboard")
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--open", dest="open_browser", action="store_true", default=True,
                    help="open a browser to the dashboard (default)")
    ap.add_argument("--no-open", dest="open_browser", action="store_false",
                    help="do not open a browser (headless / CI use)")
    args = ap.parse_args(argv)
    return serve(host=args.host, port=args.port, open_browser=args.open_browser)


if __name__ == "__main__":
    raise SystemExit(main())
