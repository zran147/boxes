#!/usr/bin/env python3
"""Tiny DNS responder used by the zone-transfer discovery recipes."""
import socket
import struct
import sys

PORT = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", PORT))
while True:
    data, addr = sock.recvfrom(512)
    if len(data) < 12:
        continue
    i = 12
    while i < len(data) and data[i] != 0:
        i += data[i] + 1
    qend = min(i + 5, len(data))
    question = data[12:qend]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
    header = data[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0)
    sock.sendto(header + question + answer, addr)
