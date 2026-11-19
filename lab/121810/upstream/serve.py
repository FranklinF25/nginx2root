#!/usr/bin/env python3
"""Tiny upstream service for the CVE-2026-121810 lab (stdlib only).

Endpoints:
  GET /health            -> 200 "ok"          (container healthcheck)
  GET /ok                -> 200 small body    (reachable upstream)
  GET /slow?ms=N         -> 200 after N ms    (hold-the-request variant)
Anything else -> 404. Single-threaded ThreadingHTTPServer is plenty.
"""
import http.server
import socketserver
import threading
import time
from urllib.parse import urlparse, parse_qs


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health" or u.path == "/ok":
            body = b"upstream ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/slow":
            ms = int(parse_qs(u.query).get("ms", ["100"])[0])
            time.sleep(min(ms, 10000) / 1000.0)
            body = b"upstream slow ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # keep the container log clean; nginx logs are the signal


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", 8080), Handler) as httpd:
        httpd.serve_forever()
