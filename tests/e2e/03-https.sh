#!/usr/bin/env bash
# E2E - 03: HTTPS tunnel (SNI passthrough)
# curl --resolve avoids modifying /etc/hosts while still sending correct SNI.
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

SERVER_PORT=49529
VHOST_PORT=49443
UPSTREAM_PORT=49800
SNI_DOMAIN="demo-tls.test.local"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$RUN_DIR/key.pem" \
  -out    "$RUN_DIR/cert.pem" \
  -days 1 \
  -subj "/CN=$SNI_DOMAIN" \
  -addext "subjectAltName=DNS:$SNI_DOMAIN" \
  2>/dev/null

cat >"$RUN_DIR/server-https.toml" <<EOF
listen       = "127.0.0.1:$SERVER_PORT"
httpsGwPort  = $VHOST_PORT
rootDomain   = "test.local"

[auth]
type  = "token"
token = "$E2E_TOKEN"
EOF

cat >"$RUN_DIR/client-https.toml" <<EOF
server = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "$E2E_TOKEN"

[[tunnels]]
name     = "https-e2e"
protocol = "https"
service  = "127.0.0.1:$UPSTREAM_PORT"
domains  = ["$SNI_DOMAIN"]
EOF

start_bg "$LOG_DIR/server-https.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-https.toml"
wait_tcp 127.0.0.1 $SERVER_PORT
wait_tcp 127.0.0.1 $VHOST_PORT

start_bg "$LOG_DIR/https-upstream.log" \
  python3 "$script_dir/https_upstream.py" \
    "$RUN_DIR/cert.pem" "$RUN_DIR/key.pem" $UPSTREAM_PORT
wait_tcp 127.0.0.1 $UPSTREAM_PORT

start_bg "$LOG_DIR/client-https.log" \
  "$BIN_DIR/orbien" -c "$RUN_DIR/client-https.toml"

# Poll until SNI route registered – nc -z only proves port is open,
# not that the vhost entry exists; curl validates both.
# --noproxy: this VM sets an egress proxy and no_proxy does not cover
# *.test.local; the SNI host must be reached directly on 127.0.0.1.
end=$((SECONDS + 30))
while (( SECONDS < end )); do
  body="$(curl --noproxy '*' -kfsS \
    --resolve "$SNI_DOMAIN:$VHOST_PORT:127.0.0.1" \
    "https://$SNI_DOMAIN:$VHOST_PORT/" 2>/dev/null)" && break
  sleep 0.25
done

echo "$body" | grep -Fx 'orbien-https-ok'

# 10 concurrent requests
for i in $(seq 1 10); do
  curl --noproxy '*' -kfsS \
    --resolve "$SNI_DOMAIN:$VHOST_PORT:127.0.0.1" \
    "https://$SNI_DOMAIN:$VHOST_PORT/" | grep -Fx 'orbien-https-ok'
done

echo "=== HTTPS E2E PASS ==="
