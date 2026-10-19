#!/usr/bin/env python3
"""A root-owned command socket used by the tmux-hijack recipes."""
import os
import socket
import subprocess

path = "/tmp/.devs/dev_sess"
os.makedirs(os.path.dirname(path), exist_ok=True)
os.chmod(os.path.dirname(path), 0o755)
try:
    os.unlink(path)
except FileNotFoundError:
    pass
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(path)
os.chmod(path, 0o666)
sock.listen(5)
while True:
    conn, _ = sock.accept()
    try:
        command = conn.recv(4096).decode(errors="replace").strip()
        if command == "list":
            conn.sendall(b"dev_sess\n")
        else:
            p = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=15
            )
            conn.sendall((p.stdout + p.stderr).encode())
    finally:
        conn.close()
