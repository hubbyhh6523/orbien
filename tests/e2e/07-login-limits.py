#!/usr/bin/env python3
"""Repro 9 (login half) for orbien #11: field limits.

Sends a Login with a 200-char hostname (cap is 64) but an otherwise
valid #12 challenge response, and expects the server to reject it:
either a LoginResp with a non-empty error, or a closed connection.

The response must be valid, so the rejection comes from field
validation, not from challenge authentication: the script sends Hello,
reads the server's Challenge, and computes the HMAC exactly as the client
does (HMAC-SHA256, key=token, message "login" + nonce + session id +
user + hostname + pool count + version + capabilities, newline
separated). A stale timestamp-only digest would fail the challenge
and prove nothing about the field limit.

Prints exactly one line: REJECTED (fixed) or ACCEPTED (bug present).

Usage: 07-login-limits.py HOST PORT TOKEN
Requires the server to run with tcpMux=false (plain control streams).
"""
import hashlib
import hmac as hmac_mod
import json
import os
import socket
import struct
import sys
import time

HOST, PORT, TOKEN = sys.argv[1], int(sys.argv[2]), sys.argv[3]


def send_msg(sock, type_byte, payload):
    body = json.dumps(payload).encode()
    sock.sendall(bytes([type_byte]) + struct.pack("<I", len(body)) + body)


def challenge_response(nonce, session_id, user, hostname, pool_count, version, capabilities):
    msg = "\n".join([
        "login",
        nonce,
        session_id,
        user,
        hostname,
        str(pool_count),
        version,
        ",".join(capabilities),
    ])
    return hmac_mod.new(TOKEN.encode(), msg.encode(), hashlib.sha256).hexdigest()


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
    # #12: send Hello first (announces the stream), then read the
    # server's Challenge and answer it.
    send_msg(s, ord("H"), {})
    mtype, challenge = read_msg(s)
    if mtype != ord("C"):
        print(f"expected Challenge, got {mtype!r}", file=sys.stderr)
        sys.exit(2)
    ts = int(time.time())
    hostname = "h" * 200
    send_msg(s, ord("A"), {
        "version": "0.2.0",
        "hostname": hostname,
        "os": "linux",
        "arch": "x86_64",
        "user": "user",
        "timestamp": ts,
        "session_id": "",
        "pool_count": 1,
        "resume_proof": "",
        "challenge_response": challenge_response(
            challenge["nonce"], "", "user", hostname, 1, "0.2.0",
            ["challenge-auth-v1"],
        ),
        "client_nonce": os.urandom(32).hex(),
        "capabilities": ["challenge-auth-v1"],
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
