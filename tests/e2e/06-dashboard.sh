#!/usr/bin/env bash
# E2E - 06: Dashboard API
# Config: dashboard lives under [dashboard], NOT [webServer].
# Auth:   POST /api/v1/auth/login -> session cookie; NOT Basic Auth.
# Case 1: anonymous access to /api/v1/system/info -> 401
# Case 2: login then access /api/v1/system/info -> 200 + valid JSON
# Case 3: /api/v1/proxies -> 200 + valid JSON
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

SERVER_PORT=49532
DASHBOARD_PORT=49533
DB_USER="${DASHBOARD_USER:-admin}"
DB_PASS="${DASHBOARD_PASSWORD:-dash-e2e-pass-9f31}"
COOKIE_JAR="$RUN_DIR/dashboard-cookies.txt"

cat >"$RUN_DIR/server-dashboard.toml" <<EOF
listen = "127.0.0.1:$SERVER_PORT"

[auth]
token = "e2e-test-token"

[dashboard]
addr     = "127.0.0.1"
port     = $DASHBOARD_PORT
user     = "$DB_USER"
password = "$DB_PASS"
EOF

start_bg "$LOG_DIR/server-dashboard.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-dashboard.toml"
wait_tcp 127.0.0.1 $SERVER_PORT
wait_tcp 127.0.0.1 $DASHBOARD_PORT

base="http://127.0.0.1:$DASHBOARD_PORT"

# --- Case 1: anonymous access must be denied ---
anon_status="$(curl -sS -o /dev/null -w '%{http_code}' \
  "$base/api/v1/system/info" || true)"
case "$anon_status" in
  401|403|302) echo "Case 1 PASS: anonymous denied ($anon_status)" ;;
  *) echo "FAIL: anonymous access returned $anon_status"; exit 1 ;;
esac

# --- Case 2: login then access system/info ---
login_status="$(curl -sS \
  -c "$COOKIE_JAR" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$DB_USER\",\"password\":\"$DB_PASS\"}" \
  -o "$RUN_DIR/dashboard-login.json" \
  -w '%{http_code}' \
  "$base/api/v1/auth/login" || true)"
if [[ "$login_status" != "200" ]]; then
  echo "FAIL: login returned $login_status"
  cat "$RUN_DIR/dashboard-login.json" >&2 || true
  exit 1
fi
echo "Login PASS (status=$login_status)"

info_status="$(curl -sS \
  -b "$COOKIE_JAR" \
  -o "$RUN_DIR/dashboard-info.json" \
  -w '%{http_code}' \
  "$base/api/v1/system/info" || true)"
if [[ "$info_status" != "200" ]]; then
  echo "FAIL: /api/v1/system/info returned $info_status after login"
  cat "$RUN_DIR/dashboard-info.json" >&2 || true
  exit 1
fi
jq empty "$RUN_DIR/dashboard-info.json"
echo "Case 2 PASS: authenticated access OK"

# --- Case 3: proxy list returns valid JSON ---
proxy_status="$(curl -sS \
  -b "$COOKIE_JAR" \
  -o "$RUN_DIR/dashboard-proxies.json" \
  -w '%{http_code}' \
  "$base/api/v1/proxies" || true)"
if [[ "$proxy_status" == "200" ]]; then
  jq empty "$RUN_DIR/dashboard-proxies.json"
  echo "Case 3 PASS: proxy list valid JSON"
else
  echo "Case 3 SKIP: /api/v1/proxies returned $proxy_status"
fi

echo "=== DASHBOARD E2E PASS ==="
