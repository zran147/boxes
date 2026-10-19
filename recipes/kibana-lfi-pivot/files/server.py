#!/usr/bin/env python3
"""Small deliberately-vulnerable service used by the easy-machine recipes."""
import os
import subprocess
import sys
import urllib.parse
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = sys.argv[1]
PORT = int(sys.argv[2])
PATH = os.environ.get("BOX_PATH", "").strip("/")
USER = os.environ.get("BOX_U", "")
PASS = os.environ.get("BOX_P", "")
LEAK = os.environ.get("BOX_LEAK_FILE", "")
UPLOAD = "/tmp/boxes-upload.sh"


def run(cmd):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return p.stdout + p.stderr
    except Exception as e:  # noqa: BLE001
        return str(e)


def route(suffix):
    return (f"/{PATH}" if PATH else "") + suffix


class Handler(BaseHTTPRequestHandler):
    def _send(self, data, code=200, headers=None):
        if isinstance(data, str):
            data = data.encode()
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorised(self):
        return "session=ok" in self.headers.get("Cookie", "")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        except Exception:
            body = ""
        if MODE in ("upload", "upload_auth"):
            if path == route("/login"):
                form = urllib.parse.parse_qs(body)
                if form.get("username", [""])[0] == USER and form.get("password", [""])[0] == PASS:
                    self._send("ok\n", headers={
                        "Set-Cookie": "session=ok; Path=/",
                        "Location": route("/"),
                    })
                else:
                    self._send("bad credentials\n", 403)
                return
            if path == route("/upload"):
                if MODE == "upload_auth" and not self._authorised():
                    self._send("login required\n", 403)
                    return
                Path(UPLOAD).write_text(body)
                self._send("uploaded\n")
                return
        if MODE == "command_auth" and path == route("/login"):
            form = urllib.parse.parse_qs(body)
            if form.get("username", [""])[0] == USER and form.get("password", [""])[0] == PASS:
                self._send("ok\n", headers={
                    "Set-Cookie": "session=ok; Path=/",
                    "Location": route("/"),
                })
            else:
                self._send("bad credentials\n", 403)
            return
        if MODE == "sqli" and path == "/login":
            form = urllib.parse.parse_qs(body)
            username = form.get("username", [""])[0]
            if "OR 1=1" in username.upper() or "'" in username:
                self._send(f"user={USER}\npass={PASS}\n")
            else:
                self._send("invalid\n", 401)
            return
        self._send("not found\n", 404)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        query = urllib.parse.parse_qs(url.query)
        if MODE == "lfi" and path == route("/graph.php"):
            try:
                self._send(Path(query.get("file", [""])[0]).read_bytes())
            except Exception as e:  # noqa: BLE001
                self._send(str(e), 404)
            return
        if MODE in ("command", "command_auth") and path == route("/run"):
            if MODE == "command_auth" and not self._authorised():
                self._send("login required\n", 403)
                return
            self._send(run(query.get("cmd", [""])[0]))
            return
        if MODE == "shellshock" and path == route("/user.sh"):
            ua = self.headers.get("User-Agent", "")
            marker = "() { :;};"
            if marker in ua:
                self._send(run(ua.split(marker, 1)[1].strip()))
            else:
                self._send("hello\n")
            return
        if MODE in ("upload", "upload_auth"):
            if path == route("/shell"):
                if MODE == "upload_auth" and not self._authorised():
                    self._send("login required\n", 403)
                    return
                try:
                    self._send(run(Path(UPLOAD).read_text()))
                except Exception as e:  # noqa: BLE001
                    self._send(str(e), 500)
                return
            self._send("upload page\n")
            return
        if MODE == "sqli":
            self._send("login page\n")
            return
        if MODE == "leak" and path in (
            route("/leak"), route("/hype_key"), "/leak", "/hype_key"
        ):
            try:
                self._send(Path(LEAK).read_bytes())
            except Exception as e:  # noqa: BLE001
                self._send(str(e), 404)
            return
        self._send("not found\n", 404)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
