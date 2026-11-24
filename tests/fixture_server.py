#!/usr/bin/env python3
"""Deliberately misconfigured fixture server for KL-DeepScan selftests.

Listens on http://127.0.0.1:8791 and intentionally exhibits problems the
scanner should detect:
  - no security headers at all
  - session cookie without HttpOnly / Secure / SameSite
  - CORS reflecting any Origin, with credentials allowed
  - Server header leaking a software version
  - /.git/HEAD exposed ("ref: refs/heads/main")
  - /search?q= reflects input unescaped (XSS marker target)
  - TRACE method answered with 200

Localhost only. Never expose this server to a network.

Usage: python3 tests/fixture_server.py [port]
"""
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
DEFAULT_PORT = 8791


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"  # version leak on purpose
    sys_version = ""

    def log_message(self, *args):  # keep test output clean
        pass

    def _respond(self, body, content_type="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8")
        self.send_response(200)
        # NOTE: deliberately NO security headers (no CSP, no X-Frame-Options,
        # no X-Content-Type-Options, no HSTS, no Referrer-Policy).
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        origin = self.headers.get("Origin")
        if origin:
            # Deliberately dangerous: reflect any origin + allow credentials.
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")
        # Deliberately flag-less session cookie.
        self.send_header("Set-Cookie", "session=fixture-session-id")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/.git/HEAD":
            self._respond("ref: refs/heads/main\n", "text/plain; charset=utf-8")
        elif parsed.path == "/search":
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            # Deliberately unescaped reflection.
            self._respond("<html><body><h1>Results for: %s</h1></body></html>" % q)
        else:
            self._respond(
                "<html><head><title>KL-DeepScan fixture</title></head><body>"
                "<h1>Deliberately vulnerable fixture</h1>"
                '<p>Try <a href="/search?q=test">/search</a>.</p>'
                "</body></html>")

    def do_POST(self):
        self.do_GET()

    def do_TRACE(self):
        # Deliberately enabled: XST risk.
        self._respond("TRACE echo", "text/plain; charset=utf-8")

    def do_OPTIONS(self):
        self._respond("")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    server = ThreadingHTTPServer((HOST, port), FixtureHandler)
    print("fixture server listening on http://%s:%d" % (HOST, port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # audit:allow — Ctrl-C memang cara normal menghentikan fixture server
        pass


if __name__ == "__main__":
    main()
