#!/usr/bin/env bash
# E2E - 04: UDP tunnel
# udpPacketSize=8192 must be set on BOTH server and client to avoid the
# default 1500-byte read-buffer truncating 4 KB payloads.
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

SERVER_PORT=49530
UDP_UPSTREAM=49900
UDP_REMOTE=49901

cat >"$RUN_DIR/server-udp.toml" <<EOF
listen        = "127.0.0.1:$SERVER_PORT"
udpPacketSize = 8192

[auth]
type  = "token"
token = "$E2E_TOKEN"
EOF

cat >"$RUN_DIR/client-udp.toml" <<EOF
server        = "127.0.0.1:$SERVER_PORT"
udpPacketSize = 8192

[auth]
type  = "token"
token = "$E2E_TOKEN"

# #12: test server uses an ephemeral self-signed cert; no CA/TOFU.
[transport.tls]
insecureSkipVerify = true

[[tunnels]]
name       = "udp-e2e"
protocol   = "udp"
service    = "127.0.0.1:$UDP_UPSTREAM"
remotePort = $UDP_REMOTE
EOF

start_bg "$LOG_DIR/server-udp.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-udp.toml"
wait_tcp 127.0.0.1 $SERVER_PORT

start_bg "$LOG_DIR/udp-upstream.log" \
  python3 "$script_dir/udp_echo.py" $UDP_UPSTREAM

start_bg "$LOG_DIR/client-udp.log" \
  "$BIN_DIR/orbien" -c "$RUN_DIR/client-udp.toml"

# UDP proxy has no TCP port to probe; wait for control connection instead
wait_tcp 127.0.0.1 $SERVER_PORT 5
sleep 1

python3 "$script_dir/udp_check.py" 127.0.0.1 $UDP_REMOTE
echo "=== UDP E2E PASS ==="
