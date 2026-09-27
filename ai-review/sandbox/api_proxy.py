# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

"""Forward an agent's model API calls upstream, adding the API key on the way.

The agent containers sit on a network with no route out; this proxy is the only thing they can
reach. It holds the one API key for the current turn, so the agent never sees a key: it sends a
placeholder, which is replaced here. Only the routes in PROXY_ROUTES are forwarded, so the key
cannot be used to manage the account (files, batches, keys) either.

Environment:
  PROXY_UPSTREAM   - base URL to forward to, e.g. https://api.anthropic.com
  PROXY_AUTH       - x-api-key (Anthropic) or bearer (OpenAI)
  PROXY_API_KEY    - the key to add
  PROXY_ROUTES     - regex matched against "<METHOD> <path>" (query string excluded)
  PROXY_PORT       - port to listen on (default 8080)

Standard library only.
"""

from __future__ import annotations

import http.client
import os
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


UPSTREAM = urllib.parse.urlsplit(os.environ["PROXY_UPSTREAM"])
AUTH = os.environ["PROXY_AUTH"]
API_KEY = os.environ["PROXY_API_KEY"]
ROUTES = re.compile(os.environ["PROXY_ROUTES"])
PORT = int(os.environ.get("PROXY_PORT", "8080"))
if AUTH not in ("x-api-key", "bearer") or not API_KEY:
    sys.exit("PROXY_AUTH must be x-api-key or bearer, and PROXY_API_KEY must be set")

# Never forwarded: hop-by-hop headers, and any credential the agent sends
DROP_HEADERS = {
    "authorization",
    "x-api-key",
    "host",
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
}


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def read_body(self) -> bytes:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            body = b""
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    # Trailers end with an empty line
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return body
                body += self.rfile.read(size)
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def forward(self) -> None:
        self.close_connection = True
        path = urllib.parse.urlsplit(self.path).path
        if not ROUTES.fullmatch(f"{self.command} {path}"):
            self.log_message("refused %s %s", self.command, path)
            self.send_error(403, "route not allowed by the AI review proxy")
            return
        body = self.read_body()
        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP_HEADERS}
        if AUTH == "x-api-key":
            headers["x-api-key"] = API_KEY
        else:
            headers["Authorization"] = f"Bearer {API_KEY}"
        headers["Content-Length"] = str(len(body))
        connection_class = http.client.HTTPSConnection if UPSTREAM.scheme == "https" else http.client.HTTPConnection
        upstream = connection_class(UPSTREAM.netloc, timeout=600)
        started = False
        try:
            upstream.request(self.command, UPSTREAM.path.rstrip("/") + self.path, body=body, headers=headers)
            response = upstream.getresponse()
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in DROP_HEADERS:
                    self.send_header(key, value)
            # Re-chunk so streamed (server-sent event) responses reach the agent as they arrive
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            started = True
            if self.command == "HEAD":
                return
            while chunk := response.read1(65536):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        except OSError as error:
            self.log_message("upstream error: %s", error)
            if not started:
                self.send_error(502, "AI review proxy could not reach the API")
        finally:
            upstream.close()

    # The names BaseHTTPRequestHandler dispatches to; the routes decide what is forwarded
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = forward  # noqa: N815


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Proxy)
    print(f"AI review proxy listening on {PORT} for {UPSTREAM.netloc}", flush=True)
    server.serve_forever()
