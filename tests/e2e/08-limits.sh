#!/usr/bin/env bash
# E2E - 08: pre-login resource limits (#13)
# Test-level [limits] values are deliberately small so the script finishes
# in seconds: pre-login deadline 2s, idle timeout 5s, caps 10 global / 5
# per-IP, 4 waiting visitors, pool 2 + burst 2.
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

SERVER_PORT=49537
NO_MUX_PORT=49539
FD_SERVER_PORT=49538
CLIENT_ECHO_LOCAL=49610
CLIENT_ECHO_REMOTE=49611

cat >"$RUN_DIR/server-limits.toml" <<EOF
listen = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "e2e-test-token"

[limits]
preLoginTimeoutSecs = 2
idleTimeoutSecs = 5
firstMessageMaxBytes = 4096
preLoginMaxConns = 10
preLoginMaxConnsPerIp = 5
maxWaitingVisitorsPerTunnel = 4
maxOutstandingDataConns = 2
poolIdleTtlSecs = 300
EOF

cat >"$RUN_DIR/client-limits.toml" <<EOF
server = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "e2e-test-token"

[transport]
poolCount = 2

# #12: test server uses an ephemeral self-signed cert; no CA/TOFU.
[transport.tls]
insecureSkipVerify = true

[[tunnels]]
name        = "tcp-limits"
protocol    = "tcp"
service     = "127.0.0.1:$CLIENT_ECHO_LOCAL"
remotePort  = $CLIENT_ECHO_REMOTE
EOF

start_bg "$LOG_DIR/server-limits.log" \
  env RUST_LOG=orbien_server=debug "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-limits.toml"
wait_tcp 127.0.0.1 $SERVER_PORT

# A second instance with yamux off, so a raw Login frame can be probed
# directly: with tcpMux on, the first bytes on the wire are a yamux
# session, not a control message (the same read_msg_limited_timeout
# guards the first message on yamux streams, covered by unit tests).
cat >"$RUN_DIR/server-limits-nomux.toml" <<EOF
listen = "127.0.0.1:$NO_MUX_PORT"

[auth]
type  = "token"
token = "e2e-test-token"

[transport]
tcpMux = false

[limits]
preLoginTimeoutSecs = 2
firstMessageMaxBytes = 4096
EOF
start_bg "$LOG_DIR/server-limits-nomux.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-limits-nomux.toml"
wait_tcp 127.0.0.1 $NO_MUX_PORT

echo "--- silent connection closed at the pre-login deadline ---"
python3 "$script_dir/limits_check.py" silent-close 127.0.0.1 $SERVER_PORT 2

echo "--- slow-byte TLS handshake closed at the same deadline ---"
python3 "$script_dir/limits_check.py" slow-byte 127.0.0.1 $SERVER_PORT 2

echo "--- oversized first message rejected without waiting for the body ---"
python3 "$script_dir/limits_check.py" oversized-first 127.0.0.1 $NO_MUX_PORT

echo "--- pre-login flood capped per IP; slots free again after the deadline ---"
python3 "$script_dir/limits_check.py" flood-cap 127.0.0.1 $SERVER_PORT 5
# The 5 held conns are closed by flood-cap's cleanup; the deadline frees
# any stragglers. A real client must still be able to log in afterwards.
sleep 3

start_bg "$LOG_DIR/limits-upstream.log" \
  python3 "$script_dir/tcp_echo.py" 127.0.0.1 $CLIENT_ECHO_LOCAL
wait_tcp 127.0.0.1 $CLIENT_ECHO_LOCAL

start_bg "$LOG_DIR/client-limits.log" \
  "$BIN_DIR/orbien" -c "$RUN_DIR/client-limits.toml"
wait_tcp 127.0.0.1 $CLIENT_ECHO_REMOTE 30
python3 "$script_dir/tcp_check.py" 127.0.0.1 $CLIENT_ECHO_REMOTE
echo "--- normal login still works after the flood ---"

echo "--- visitor flood: excess visitors refused, tunnel keeps serving ---"
python3 "$script_dir/limits_check.py" visitor-flood 127.0.0.1 $CLIENT_ECHO_REMOTE 20
# The flood must have hit the waiting-visitors cap at least once, and the
# tunnel must still answer afterwards.
grep -E "waiting visitors|waiting_visitors" "$LOG_DIR/server-limits.log" >/dev/null \
  || { echo "FAIL: no waiting-visitors rejection logged during flood" >&2; exit 1; }
python3 "$script_dir/tcp_check.py" 127.0.0.1 $CLIENT_ECHO_REMOTE
echo "--- visitor flood capped, tunnel still serving ---"

# An idle joined TCP connection is cut at idleTimeoutSecs (5s here);
# the tunnel must keep serving afterwards.
echo "--- idle joined connection cut at the idle timeout ---"
python3 "$script_dir/limits_check.py" idle-close 127.0.0.1 $CLIENT_ECHO_REMOTE 5
python3 "$script_dir/tcp_check.py" 127.0.0.1 $CLIENT_ECHO_REMOTE
echo "--- idle timeout enforced, tunnel still serving ---"

# --- fd exhaustion on a separate instance: accept errors must not kill it ---
# The instance also runs an HTTP gateway, so the test proves a failing
# accept on the control listener does not stop the other listener.
FD_HTTP_PORT=49540
cat >"$RUN_DIR/server-limits-fd.toml" <<EOF
listen = "127.0.0.1:$FD_SERVER_PORT"
httpGwPort = $FD_HTTP_PORT

[auth]
type  = "token"
token = "e2e-test-token"

[limits]
preLoginTimeoutSecs = 30
# Caps raised so the flood can actually exhaust the 64 fds: with the
# default per-IP cap of 32 the gate would refuse connections before
# EMFILE is ever reached (which is the gate doing its job).
preLoginMaxConns = 500
preLoginMaxConnsPerIp = 500
EOF

# ulimit -n 64 applies to the server only (subshell).
( ulimit -n 64; exec "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-limits-fd.toml" \
  >>"$LOG_DIR/server-limits-fd.log" 2>&1 & echo $! >"$RUN_DIR/server-limits-fd.pid" )
FD_PID="$(cat "$RUN_DIR/server-limits-fd.pid")"
pids+=("$FD_PID")
wait_tcp 127.0.0.1 $FD_SERVER_PORT

# Hold ~100 idle conns: enough to exhaust a 64-fd process on accept, while
# the server must stay alive and keep accepting once they close.
python3 - "$FD_SERVER_PORT" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
held = []
for _ in range(100):
    try:
        held.append(socket.create_connection(("127.0.0.1", port), timeout=5))
    except OSError:
        break
time.sleep(3)
# Server must still be alive (checked by the caller via kill -0).
for s in held:
    s.close()
time.sleep(2)
# And accept must work again after the fds free up.
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.settimeout(3)
try:
    s.recv(1)
    print("FAIL: fresh conn after recovery got data", file=sys.stderr)
    sys.exit(1)
except socket.timeout:
    pass  # still open at 3s: accept recovered; pre-login deadline is 30s here
print("fd exhaustion: server survived, accept recovered")
PYEOF
kill -0 "$FD_PID" || { echo "FAIL: server died under fd exhaustion" >&2; exit 1; }
# The other listener must have survived too: the HTTP gateway answers
# (404 for an unknown host) once fds free up again.
python3 - "$FD_HTTP_PORT" <<'PYEOF'
import http.client, sys
conn = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
conn.request("GET", "/", headers={"Host": "nobody.example.com"})
resp = conn.getresponse()
resp.read()
assert resp.status == 404, f"gateway status {resp.status}, want 404"
print("gateway survived fd exhaustion (404 as expected)")
PYEOF
echo "--- fd exhaustion survived, accept recovered ---"

echo "=== LIMITS E2E PASS ==="
