"""A tiny, deliberately vulnerable internal app for the patch-on-top demo.

It stands in for the case FixProof serves that no outside platform can: a private
app whose fix has not shipped in any public version. There is no CVE and no image
tag to compare against — only the team's own unreleased patch. `GET /download?file=`
joins the requested name onto the served directory with no normalization, so an
encoded `../` escapes the web root and reads a canary planted outside it.

Pure standard library, so the image boots instantly and needs no dependencies.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

BASE = "/app/public"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parts = urlparse(self.path)
        if parts.path == "/download":
            name = (parse_qs(parts.query).get("file") or [""])[0]
            # VULNERABLE: user input is joined to BASE with no containment check,
            # so "../../secret_canary.txt" resolves outside the web root.
            path = os.path.join(BASE, name)
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except OSError:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args) -> None:  # keep container logs quiet
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
