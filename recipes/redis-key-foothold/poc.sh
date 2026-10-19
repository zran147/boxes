set -eu
key=$(mktemp)
rm -f "$key"
ssh-keygen -q -t rsa -b 2048 -N '' -f "$key"
pub=$(cat "$key.pub")
python3 - "$BOX_HOST" "$pub" <<'PY'
import socket, sys
host, pub = sys.argv[1], sys.argv[2]
s = socket.create_connection((host, 6379), timeout=5)
s.sendall(("PUBKEY:" + pub + "\n").encode())
print(s.recv(1024).decode())
s.close()
PY
