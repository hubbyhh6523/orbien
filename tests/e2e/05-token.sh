#!/usr/bin/env bash
# E2E - 05: Token authentication
# Case 1: wrong token  -> rejected
# Case 2: empty token  -> rejected
# Case 3: correct token -> accepted, TCP data flows
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

SERVER_PORT=49531
ECHO_LOCAL=49610
ECHO_REMOTE=49611
TOKEN="e2e-accept-token"

cat >"$RUN_DIR/server-token.toml" <<EOF
listen = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "$TOKEN"
EOF

cat >"$RUN_DIR/client-token-ok.toml" <<EOF
server = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "$TOKEN"

# #12: test server uses an ephemeral self-signed cert; no CA/TOFU.
[transport.tls]
insecureSkipVerify = true

[[tunnels]]
name       = "tok-tcp"
protocol   = "tcp"
service    = "127.0.0.1:$ECHO_LOCAL"
remotePort = $ECHO_REMOTE
EOF

cat >"$RUN_DIR/client-token-wrong.toml" <<EOF
server = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "wrong-token"

# #12: test server uses an ephemeral self-signed cert; no CA/TOFU.
# (Kept so the rejection comes from the server, not the client guard.)
[transport.tls]
insecureSkipVerify = true

[[tunnels]]
name       = "tok-wrong"
protocol   = "tcp"
service    = "127.0.0.1:$ECHO_LOCAL"
remotePort = 49699
EOF

cat >"$RUN_DIR/client-token-empty.toml" <<EOF
server = "127.0.0.1:$SERVER_PORT"

# #12: test server uses an ephemeral self-signed cert; no CA/TOFU.
# (Kept so the rejection comes from the server, not the client guard.)
[transport.tls]
insecureSkipVerify = true

[[tunnels]]
name       = "tok-empty"
protocol   = "tcp"
service    = "127.0.0.1:$ECHO_LOCAL"
remotePort = 49698
EOF

start_bg "$LOG_DIR/server-token.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-token.toml"
wait_tcp 127.0.0.1 $SERVER_PORT

# --- Case 1: wrong token ---
set +e
timeout 12 "$BIN_DIR/orbien" \
  -c "$RUN_DIR/client-token-wrong.toml" \
  >>"$LOG_DIR/client-token-wrong.log" 2>&1
wrong_rc=$?
set -e
[[ $wrong_rc -ne 0 ]] || { echo "FAIL: wrong token unexpectedly succeeded"; exit 1; }
echo "Case 1 PASS: wrong token rejected (rc=$wrong_rc)"

# --- Case 2: empty token ---
set +e
timeout 12 "$BIN_DIR/orbien" \
  -c "$RUN_DIR/client-token-empty.toml" \
  >>"$LOG_DIR/client-token-empty.log" 2>&1
empty_rc=$?
set -e
[[ $empty_rc -ne 0 ]] || { echo "FAIL: empty token unexpectedly succeeded"; exit 1; }
echo "Case 2 PASS: empty token rejected (rc=$empty_rc)"

# --- Case 3: correct token ---
start_bg "$LOG_DIR/tok-upstream.log" \
  python3 "$script_dir/tcp_echo.py" 127.0.0.1 $ECHO_LOCAL
wait_tcp 127.0.0.1 $ECHO_LOCAL

start_bg "$LOG_DIR/client-token-ok.log" \
  "$BIN_DIR/orbien" -c "$RUN_DIR/client-token-ok.toml"
wait_tcp 127.0.0.1 $ECHO_REMOTE 20

python3 "$script_dir/tcp_check.py" 127.0.0.1 $ECHO_REMOTE
echo "Case 3 PASS: correct token accepted"

echo "=== TOKEN AUTH E2E PASS ==="
