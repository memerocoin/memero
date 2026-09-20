#!/usr/bin/env python3
"""Memero web wallet — minimal JSON-RPC server wrapping the memero CLI wallet.

Self-custody-lite: wallet keys are stored on the VPS under WALLET_DIR, encrypted
by the memero wallet's own KDF password. This is a hosted wallet — not
non-custodial — suitable for bootstrapping the network.

Endpoints:
  GET  /            -> serve the wallet web UI (index.html)
  GET  /assets/*    -> serve static assets
  POST /rpc         -> JSON-RPC {method, params}

RPC methods:
  get_info              -> {version, height}
  create_wallet         -> {address, seed}
  restore_wallet        -> {address}
  get_address           -> {address}
  get_balance           -> {balance, unlocked_balance}
  refresh               -> {height}
  transfer              -> {txid}
  get_transfers         -> {in: [...], out: [...]}   (best-effort)
"""
import http.server
import json
import os
import subprocess
import threading
import urllib.request

MEMERO_BIN = os.environ.get("MEMERO_BIN", "/usr/local/bin/memero")
DAEMON_ADDR = os.environ.get("MEMERO_DAEMON", "localhost:50709")
WALLET_DIR = os.environ.get("MEMERO_WALLET_DIR", "/home/memero/.memero-web")
HOST = os.environ.get("MEMERO_WALLET_HOST", "127.0.0.1")
PORT = int(os.environ.get("MEMERO_WALLET_PORT", "8082"))
BASEDIR = os.path.dirname(os.path.abspath(__file__))

os.makedirs(WALLET_DIR, exist_ok=True)
_lock = threading.Lock()


def _run(args, stdin_text=None, timeout=120):
    """Run a subprocess, return (stdout, stderr, returncode)."""
    p = subprocess.run(
        args, input=stdin_text, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def _wallet_path(name):
    # sanitize name to a filename
    safe = "".join(c for c in name if c.isalnum() or c in "-_")
    return os.path.join(WALLET_DIR, safe)


def _do_wallet(name, password, commands, extra_args=None):
    """Open a wallet, pipe commands in, return (stdout, stderr)."""
    path = _wallet_path(name)
    args = [MEMERO_BIN, "--open", path, "--password", password, "--daemon-address", DAEMON_ADDR]
    if extra_args:
        args += extra_args
    stdin = commands + "\nexit\n"
    out, err, rc = _run(args, stdin)
    return out, err, rc


def create_wallet(name, password):
    path = _wallet_path(name)
    if os.path.exists(path):
        raise ValueError("wallet already exists")
    args = [MEMERO_BIN, "--new", path, "--password", password, "--daemon-address", DAEMON_ADDR]
    out, err, rc = _run(args)
    if rc != 0:
        raise RuntimeError("create failed: " + err.strip())
    addr = None
    seed = None
    for line in out.splitlines():
        if "Generated new wallet:" in line:
            addr = line.split("Generated new wallet:")[-1].strip()
    # seed is 25 words between the two lines of asterisks
    lines = out.splitlines()
    in_seed = False
    words = []
    for ln in lines:
        if ln.strip().startswith("****"):
            if in_seed:
                break
            in_seed = True
            continue
        if in_seed:
            words += ln.split()
    seed = " ".join(words[:25]) if len(words) >= 25 else (" ".join(words) if words else None)
    return {"address": addr, "seed": seed}


def restore_wallet(name, password, seed):
    path = _wallet_path(name)
    if os.path.exists(path):
        raise ValueError("wallet already exists")
    args = [MEMERO_BIN, "--new", path, "--password", password,
            "--restore", "--electrum-seed", seed, "--daemon-address", DAEMON_ADDR]
    out, err, rc = _run(args)
    if rc != 0:
        raise RuntimeError("restore failed: " + err.strip())
    addr = None
    for line in out.splitlines():
        if "Generated new wallet:" in line or "Opened wallet:" in line:
            addr = line.split(":")[-1].strip()
            break
    return {"address": addr}


def get_address(name, password):
    out, err, rc = _do_wallet(name, password, "address")
    if rc != 0 and rc != 1:
        raise RuntimeError("address failed: " + err.strip())
    # The address appears as a long (>50 char) token on a line, possibly
    # after a "[wallet X]:" interactive prompt prefix.
    for line in out.splitlines():
        parts = line.split()
        for p in parts:
            # strip a trailing "]:" from the wallet short-name prefix
            cand = p.rstrip(",:")
            if len(cand) > 50 and cand[0].isalnum():
                return {"address": cand}
    raise RuntimeError("could not parse address")


def get_balance(name, password):
    out, err, rc = _do_wallet(name, password, "account")
    if rc not in (0, 1):
        raise RuntimeError("balance failed: " + err.strip())
    balance = unlocked = None
    for line in out.splitlines():
        if "Total" in line:
            parts = line.split()
            # "Total       245.66      0"
            nums = [p for p in parts if p.replace(".", "").replace("-", "").isdigit()]
            if len(nums) >= 2:
                balance, unlocked = nums[0], nums[1]
    if balance is None:
        # try the per-account line
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1].startswith(("0", "1", "2")):
                nums = [p for p in parts if p.replace(".", "").isdigit()]
                if len(nums) >= 2:
                    balance, unlocked = nums[0], nums[1]
                    break
    return {"balance": balance or "0", "unlocked_balance": unlocked or "0"}


def refresh(name, password):
    out, err, rc = _do_wallet(name, password, "refresh")
    return {"status": "ok"}


def transfer(name, password, address, amount):
    cmd = f"transfer {address} {amount}\n"
    out, err, rc = _do_wallet(name, password, cmd)
    # parse txid if present
    txid = None
    for line in out.splitlines():
        if "txid" in line.lower():
            txid = line.split()[-1].strip()
            break
    if txid is None:
        raise RuntimeError("transfer failed (no txid): " + (err or out).strip()[-200:])
    return {"txid": txid}


def get_transfers(name, password):
    # The wallet CLI has no direct "transfers" command in this version,
    # so we approximate by refreshing and returning a note.
    out, err, rc = _do_wallet(name, password, "account")
    return {"in": [], "out": [], "note": "detailed history coming soon"}


def error(code, message):
    return {"jsonrpc": "2.0", "id": "0", "error": {"code": code, "message": message}}


def dispatch(method, params):
    with _lock:
        if method == "get_info":
            # ask daemon for height
            try:
                req = urllib.request.Request(
                    f"http://{DAEMON_ADDR}/json_rpc",
                    data=json.dumps({"jsonrpc": "2.0", "id": "0", "method": "get_info"}).encode(),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10) as r:
                    res = json.loads(r.read())["result"]
                return {"version": res.get("version", "?"), "height": res.get("height")}
            except Exception:
                return {"version": "memero", "height": None}

        name = params.get("name", "default")
        password = params.get("password", "")

        if method == "create_wallet":
            return create_wallet(name, password)
        if method == "restore_wallet":
            return restore_wallet(name, password, params.get("seed", ""))
        if method == "get_address":
            return get_address(name, password)
        if method == "get_balance":
            return get_balance(name, password)
        if method == "refresh":
            return refresh(name, password)
        if method == "transfer":
            return transfer(name, password, params.get("address"), params.get("amount"))
        if method == "get_transfers":
            return get_transfers(name, password)
        raise ValueError("unknown method: " + method)


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            path = "/index.html"
        fp = os.path.join(BASEDIR, path.lstrip("/"))
        if path.startswith("/") and os.path.isfile(fp) and not "/." in path:
            try:
                with open(fp, "rb") as f:
                    ctype = "text/html" if path.endswith(".html") else "application/octet-stream"
                    if path.endswith(".css"): ctype = "text/css"
                    if path.endswith(".js"): ctype = "application/javascript"
                    if path.endswith(".png"): ctype = "image/png"
                    self._send(200, f.read(), ctype)
            except OSError:
                self._send(500, b"error")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if self.path != "/rpc":
            self._send(404, b"not found")
            return
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        try:
            req = json.loads(body)
            method = req.get("method")
            params = req.get("params", {})
            result = dispatch(method, params)
            self._send(200, json.dumps({"jsonrpc": "2.0", "id": "0", "result": result}))
        except ValueError as e:
            self._send(200, json.dumps(error(-32601, str(e))))
        except Exception as e:
            self._send(200, json.dumps(error(-32000, str(e))))

    def log_message(self, fmt, *args):
        pass


def main():
    httpd = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Memero web wallet on {HOST}:{PORT} (daemon {DAEMON_ADDR}, wallets in {WALLET_DIR})")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
