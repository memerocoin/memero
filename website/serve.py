#!/usr/bin/env python3
"""Serve the Memero marketing website (static files only)."""
import http.server
import os
import socketserver

DIR = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get("MEMERO_SITE_HOST", "0.0.0.0")
PORT = int(os.environ.get("MEMERO_SITE_PORT", "8081"))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    def log_message(self, fmt, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    httpd = Server((HOST, PORT), Handler)
    print(f"Serving {DIR} on {HOST}:{PORT}")
    httpd.serve_forever()
