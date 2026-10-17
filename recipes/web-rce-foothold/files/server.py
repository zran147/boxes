from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
import urllib.parse


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urllib.parse.urlparse(self.path)
        if url.path == "/":
            self._send(b"ok\n")
            return
        if url.path == "/run":
            cmd = urllib.parse.parse_qs(url.query).get("cmd", [""])[0]
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                self._send((out.stdout + out.stderr).encode())
            except Exception as exc:  # noqa: BLE001
                self._send(str(exc).encode(), 500)
            return
        self._send(b"not found\n", 404)

    def log_message(self, *args) -> None:
        pass


HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
