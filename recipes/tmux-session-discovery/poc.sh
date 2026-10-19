set -eu
out=$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/.devs/dev_sess")
s.sendall(b"list")
print(s.recv(4096).decode())
PY
)
echo "$out"
echo "$out" | grep -q 'dev_sess' || { echo "root session not discovered" >&2; exit 1; }
