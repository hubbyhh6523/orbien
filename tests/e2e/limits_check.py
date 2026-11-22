#!/usr/bin/env python3
"""Socket-level checks for #13 pre-login limits (08-limits.sh).

Subcommands (each exits 0 on pass, 1 on fail):
  silent-close HOST PORT DEADLINE  -- connect, send nothing, expect EOF
                                     within DEADLINE+3s.
  slow-byte HOST PORT DEADLINE     -- send 1 byte every 0.4s, expect EOF
                                     within DEADLINE+3s (deadline is from
                                     accept, so slow dribble must not extend it).
  oversized-first HOST PORT        -- send a Login header declaring a 5000
                                     byte body and no body; expect EOF < 3s.
  flood-cap HOST PORT CAP          -- open CAP silent conns, then one more;
                                     the extra one must get EOF within 2s
                                     (cap enforced), the held ones stay open.
  visitor-flood HOST PORT N        -- open N concurrent TCP conns to a tunnel
                                     port and count how many get any reply
                                     within 12s; prints "served=K refused=R".
                                     Refused = EOF/reset before any reply.
  idle-close HOST PORT IDLE        -- connect to a tunnel port, get one echo,
                                     then stay silent; expect EOF within
                                     IDLE+10s of the echo (idle timeout).
"""
import socket
import sys
import threading
import time


def silent_close(host, port, deadline):
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(deadline + 5)
    start = time.monotonic()
    try:
        data = s.recv(1)
    except socket.timeout:
        print(f"FAIL: silent conn still open after {deadline + 5:.0f}s")
        return 1
    elapsed = time.monotonic() - start
    if data != b"":
        print(f"FAIL: silent conn got data instead of EOF: {data!r}")
        return 1
    if elapsed > deadline + 3:
        print(f"FAIL: silent conn closed after {elapsed:.1f}s, deadline {deadline}s")
        return 1
    print(f"silent conn closed after {elapsed:.1f}s (deadline {deadline}s)")
    return 0


def slow_byte(host, port, deadline):
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(deadline + 5)
    start = time.monotonic()
    try:
        while True:
            s.sendall(b"\x16")  # one TLS-handshake byte at a time
            data = s.recv(1)
            if data == b"":
                break
            time.sleep(0.4)
    except socket.timeout:
        print(f"FAIL: slow-byte conn still open after {deadline + 5:.0f}s")
        return 1
    except (ConnectionResetError, BrokenPipeError):
        pass
    elapsed = time.monotonic() - start
    if elapsed > deadline + 3:
        print(f"FAIL: slow-byte conn closed after {elapsed:.1f}s, deadline {deadline}s")
        return 1
    print(f"slow-byte conn closed after {elapsed:.1f}s (deadline {deadline}s)")
    return 0


def oversized_first(host, port):
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(5)
    # Login type byte 'A', 5000-byte body declared, no body sent.
    s.sendall(b"A" + (5000).to_bytes(4, "little"))
    start = time.monotonic()
    try:
        data = s.recv(1)
    except socket.timeout:
        print("FAIL: oversized-first conn still open after 5s")
        return 1
    elapsed = time.monotonic() - start
    if data != b"":
        print(f"FAIL: oversized-first conn got data: {data!r}")
        return 1
    if elapsed > 3:
        print(f"FAIL: oversized-first conn closed after {elapsed:.1f}s, want < 3s")
        return 1
    print(f"oversized-first conn closed after {elapsed:.1f}s")
    return 0


def flood_cap(host, port, cap):
    held = []
    try:
        for _ in range(cap):
            s = socket.create_connection((host, port), timeout=5)
            s.settimeout(3)
            held.append(s)
        extra = socket.create_connection((host, port), timeout=5)
        extra.settimeout(3)
        try:
            data = extra.recv(1)
        except socket.timeout:
            print(f"FAIL: conn #{cap + 1} above the cap was not refused within 2s")
            return 1
        if data != b"":
            print(f"FAIL: conn #{cap + 1} got data instead of EOF: {data!r}")
            return 1
        print(f"conn #{cap + 1} above cap {cap} refused immediately; {cap} held conns still open")
        return 0
    finally:
        for s in held:
            s.close()


def visitor_flood(host, port, n):
    served = 0
    refused = 0
    lock = threading.Lock()

    def one(i):
        nonlocal served, refused
        try:
            s = socket.create_connection((host, port), timeout=12)
            s.settimeout(12)
            s.sendall(b"hello-e2e\n")
            data = s.recv(64)
            with lock:
                if data:
                    served += 1
                else:
                    refused += 1
            s.close()
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            with lock:
                refused += 1

    threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"visitor flood: served={served} refused={refused} total={n}")
    return 0


def idle_close(host, port, idle):
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(idle + 15)
    s.sendall(b"hello-e2e\n")
    try:
        data = s.recv(64)
    except socket.timeout:
        print("FAIL: idle-close conn got no echo")
        return 1
    if not data:
        print("FAIL: idle-close conn closed before the echo")
        return 1
    # The echo is the last byte; the joined stream must be cut idle
    # seconds later (watchdog ticks every 1s, so up to 1s late).
    start = time.monotonic()
    try:
        data = s.recv(1)
    except socket.timeout:
        print(f"FAIL: idle-close conn still open {idle + 15:.0f}s after the echo")
        return 1
    elapsed = time.monotonic() - start
    if data != b"":
        print(f"FAIL: idle-close conn got data instead of EOF: {data!r}")
        return 1
    if elapsed < idle - 1:
        print(f"FAIL: idle-close conn cut after {elapsed:.1f}s, idle is {idle}s")
        return 1
    if elapsed > idle + 10:
        print(f"FAIL: idle-close conn cut after {elapsed:.1f}s, idle is {idle}s")
        return 1
    print(f"idle-close conn cut after {elapsed:.1f}s idle (idle {idle}s)")
    return 0


def main():
    cmd = sys.argv[1]
    if cmd == "silent-close":
        return silent_close(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
    if cmd == "slow-byte":
        return slow_byte(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
    if cmd == "oversized-first":
        return oversized_first(sys.argv[2], int(sys.argv[3]))
    if cmd == "flood-cap":
        return flood_cap(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    if cmd == "visitor-flood":
        return visitor_flood(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    if cmd == "idle-close":
        return idle_close(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
    print(f"unknown subcommand: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
