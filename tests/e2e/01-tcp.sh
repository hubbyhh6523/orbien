#!/usr/bin/env bash
# E2E - 01: TCP tunnel
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

SERVER_PORT=49527
CLIENT_ECHO_LOCAL=49600
CLIENT_ECHO_REMOTE=49601

cat >"$RUN_DIR/server-tcp.toml" <<EOF
listen = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "$E2E_TOKEN"
EOF

cat >"$RUN_DIR/client-tcp.toml" <<EOF
server = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "$E2E_TOKEN"

# #12: test server uses an ephemeral self-signed cert; no CA/TOFU.
[transport.tls]
insecureSkipVerify = true

[[tunnels]]
name        = "tcp-e2e"
protocol    = "tcp"
service     = "127.0.0.1:$CLIENT_ECHO_LOCAL"
remotePort  = $CLIENT_ECHO_REMOTE
EOF

start_bg "$LOG_DIR/server-tcp.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-tcp.toml"
wait_tcp 127.0.0.1 $SERVER_PORT

start_bg "$LOG_DIR/tcp-upstream.log" \
  python3 "$script_dir/tcp_echo.py" 127.0.0.1 $CLIENT_ECHO_LOCAL
wait_tcp 127.0.0.1 $CLIENT_ECHO_LOCAL

start_bg "$LOG_DIR/client-tcp.log" \
  "$BIN_DIR/orbien" -c "$RUN_DIR/client-tcp.toml"

# Wait for tunnel remote port to open
wait_tcp 127.0.0.1 $CLIENT_ECHO_REMOTE 30

python3 "$script_dir/tcp_check.py" 127.0.0.1 $CLIENT_ECHO_REMOTE
echo "=== TCP E2E PASS ==="
