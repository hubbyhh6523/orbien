#!/usr/bin/env bash
# E2E - 02: HTTP tunnel (vhost)
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

SERVER_PORT=49528
VHOST_PORT=49780
UPSTREAM_PORT=49700

cat >"$RUN_DIR/server-http.toml" <<EOF
listen      = "127.0.0.1:$SERVER_PORT"
httpGwPort  = $VHOST_PORT
rootDomain  = "test.local"

[auth]
type  = "token"
token = "$E2E_TOKEN"
EOF

cat >"$RUN_DIR/client-http.toml" <<EOF
server = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "$E2E_TOKEN"

[[tunnels]]
name     = "http-e2e"
protocol = "http"
service  = "127.0.0.1:$UPSTREAM_PORT"
domains  = ["demo.test.local"]
EOF

start_bg "$LOG_DIR/server-http.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-http.toml"
wait_tcp 127.0.0.1 $SERVER_PORT
wait_tcp 127.0.0.1 $VHOST_PORT

start_bg "$LOG_DIR/http-upstream.log" \
  python3 "$script_dir/http_upstream.py" $UPSTREAM_PORT
wait_tcp 127.0.0.1 $UPSTREAM_PORT

start_bg "$LOG_DIR/client-http.log" \
  "$BIN_DIR/orbien" -c "$RUN_DIR/client-http.toml"

# Poll until the vhost route is registered (curl replaces fixed sleep)
end=$((SECONDS + 30))
while (( SECONDS < end )); do
  body="$(curl -fsS -H 'Host: demo.test.local' \
    http://127.0.0.1:$VHOST_PORT/ 2>/dev/null)" && break
  sleep 0.25
done

echo "$body" | grep -Fx 'orbien-http-ok'
echo "$body" | grep -Fx 'host=demo.test.local'

# Unknown host must return 4xx/5xx
status="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Host: unknown.notexist' \
  http://127.0.0.1:$VHOST_PORT/ || true)"
case "$status" in
  4*|5*) ;;
  *) echo "FAIL: unknown host returned $status"; exit 1 ;;
esac

echo "=== HTTP E2E PASS ==="
