#!/usr/bin/env python3
"""Repro 9 (login half) for orbien #11: field limits.

Sends a Login with a 200-char hostname (cap is 64) but an otherwise
valid digest, and expects the server to reject it: either a LoginResp
with a non-empty error, or a closed connection.

Prints exactly one line: REJECTED (fixed) or ACCEPTED (bug present).

Usage: 07-login-limits.py HOST PORT TOKEN
Requires the server to run with tcpMux=false (plain control streams).
"""
import hashlib
import hmac as hmac_mod
import json
import socket
import struct
import sys
import time

HOST, PORT, TOKEN = sys.argv[1], int(sys.argv[2]), sys.argv[3]


def send_msg(sock, type_byte, payload):
    body = json.dumps(payload).encode()
    sock.sendall(bytes([type_byte]) + struct.pack("<I", len(body)) + body)


def digest(timestamp):
    return hmac_mod.new(
        TOKEN.encode(), str(timestamp).encode(), hashlib.sha256
    ).hexdigest()


def read_msg(sock):
    header = b""
    while len(header) < 5:
        chunk = sock.recv(5 - len(header))
        if not chunk:
            return None, None
        header += chunk
    mtype, length = header[0], struct.unpack("<I", header[1:5])[0]
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            return None, None
        body += chunk
    return mtype, json.loads(body)


rejected = False
try:
    s = socket.create_connection((HOST, PORT), timeout=10)
    ts = int(time.time())
    send_msg(s, ord("A"), {
        "version": "0.2.0",
        "hostname": "h" * 200,
        "os": "linux",
        "arch": "x86_64",
        "user": "user",
        "auth_digest": digest(ts),
        "timestamp": ts,
        "session_id": "",
        "pool_count": 1,
    })
    mtype, payload = read_msg(s)
    if mtype is None:
        rejected = True  # server closed the connection: rejected
    elif mtype == ord("a") and payload.get("error"):
        rejected = True
    s.close()
except OSError:
    rejected = True

print("REJECTED" if rejected else "ACCEPTED")
