#!/usr/bin/env python3
"""Memero public RPC endpoint — read-only proxy to the daemon.

Exposes a curated, read-only subset of the daemon JSON-RPC to the public
(via the Cloudflare tunnel at node.memero.lol). Dangerous/state-changing
methods (mining, relay, send, pop, flush, ban) are rejected.

Bound to 127.0.0.1 by default; the tunnel reaches it locally.
"""
import http.server
import json
import os
import urllib.request

DAEMON_RPC = os.environ.get("MEMERO_DAEMON_RPC", "http://127.0.0.1:50709/json_rpc")
HOST = os.environ.get("MEMERO_NODE_HOST", "127.0.0.1")
PORT = int(os.environ.get("MEMERO_NODE_PORT", "8084"))

# Read-only / safe methods to expose publicly.
ALLOWED_METHODS = {
    "get_info",
    "get_version",
    "get_block",
    "get_block_header_by_hash",
    "get_block_header_by_height",
    "get_blocks",
    "get_hashes",
    "get_connections",
    "get_peer_list",
    "get_transaction_pool",
    "get_transaction_pool_hashes",
    "get_transactions",
    "get_tx_outputs",
    "get_coinbase_tx_sum",
    "get_output_size_histogram",
    "is_output_key_image_spent",
    "sync_info",
    "mining_status",
}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = json.dumps({
            "jsonrpc": "2.0", "id": "0",
            "result": {
                "service": "memero-node",
                "endpoint": "/json_rpc",
                "methods": sorted(ALLOWED_METHODS),
            },
        })
        self._send(200, body)

    def do_POST(self):
        if self.path != "/json_rpc":
            self._send(404, json.dumps({"error": "not found"}))
            return
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        try:
            req = json.loads(body)
            method = req.get("method")
            if method not in ALLOWED_METHODS:
                self._send(200, json.dumps({
                    "jsonrpc": "2.0", "id": req.get("id"),
                    "error": {"code": -32601, "message": f"method not allowed: {method}"},
                }))
                return
        except Exception:
            self._send(400, json.dumps({"error": "bad request"}))
            return

        try:
            r = urllib.request.Request(DAEMON_RPC, data=body,
                                       headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(r, timeout=15) as resp:
                self._send(200, resp.read())
        except Exception as e:
            self._send(502, json.dumps({"error": str(e)}))

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    httpd = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"memero node RPC on {HOST}:{PORT} -> {DAEMON_RPC}")
    httpd.serve_forever()
