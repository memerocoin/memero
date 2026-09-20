#!/usr/bin/env python3
"""Memero block explorer: serves static files and proxies JSON-RPC to the daemon.

Read-only: only GET / and POST /rpc are handled. The daemon RPC is bound to
127.0.0.1:50709, so this proxy (which must also run on the VPS) reaches it
server-side, avoiding CORS and keeping the daemon RPC private.
"""
import http.server
import json
import os
import socketserver
import urllib.request

DAEMON_RPC = os.environ.get("MEMERO_DAEMON_RPC", "http://127.0.0.1:50709/json_rpc")
HOST = os.environ.get("MEMERO_EXPLORER_HOST", "0.0.0.0")
PORT = int(os.environ.get("MEMERO_EXPLORER_PORT", "8080"))
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "")


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            path = "/index.html"
        filepath = os.path.join(STATIC_DIR, path.lstrip("/"))
        if path.startswith("/") and os.path.isfile(filepath) and not path.startswith("/."):
            try:
                with open(filepath, "rb") as f:
                    self._send(200, f.read(), "text/html" if path.endswith(".html") else "text/plain")
            except OSError:
                self._send(500, b"error reading file")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if self.path != "/rpc":
            self._send(404, b"not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = urllib.request.Request(
                DAEMON_RPC, data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
                self._send(200, data)
        except Exception as e:
            self._send(502, json.dumps({"error": {"message": str(e)}}).encode())

    def log_message(self, fmt, *args):
        pass  # quiet


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    httpd = Server((HOST, PORT), Handler)
    print(f"Memero explorer on {HOST}:{PORT} -> {DAEMON_RPC}")
    httpd.serve_forever()
