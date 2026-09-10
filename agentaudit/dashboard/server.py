"""Stdlib-only HTTP server for the AgentAudit dashboard.

No new dependencies (charter rule 3): ``http.server`` + ``json`` only.

    python -m agentaudit.dashboard.server [--port 8770] [--open]

Endpoints
    GET  /                  dashboard UI
    GET  /api/state         full snapshot (scans, org, policies, agents)
    GET  /api/policies      generated Cedar policies + deployment status
    GET  /api/agents        live agent discovery
    POST /api/scan          {"target": "<path>"} -> run a REAL audit
    POST /api/scan-all      {"targets": [...]}   -> org-wide real audit
    POST /api/reset         clear dashboard state (for honest empty-state demo)
"""

from __future__ import annotations

import argparse
import json
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"AgentAudit dashboard -> http://{args.host}:{args.port}")
    print("  (all data is live; nothing is mocked)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
