#!/bin/sh
# Build the vulnerable web app and the user flag it exposes.
set -eu
u="${BOX_WEB_USER:?BOX_WEB_USER is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
mkdir -p "/home/$u"
printf 'FLAG{user-%s}\n' "$u" > "/home/$u/user.txt"
chown "$u:$u" "/home/$u/user.txt"
chmod 0640 "/home/$u/user.txt"

mkdir -p /opt/app
cat > /opt/app/server.py <<'PY'
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
PY

nohup su -s /bin/sh "$u" -c 'exec python3 /opt/app/server.py' >/var/log/app.log 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS http://127.0.0.1:8080/ >/dev/null 2>&1; then
        exit 0
    fi
    sleep 0.5
done
echo "web app failed to start" >&2
cat /var/log/app.log >&2 || true
exit 1
