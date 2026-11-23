#!/usr/bin/env bash
# E2E - 07: Token policies, route ownership, session identity (#11)
#
# Repro cases from issue #11 (all must FAIL before the fix, PASS after):
#   2: second session takes over a tunnel name
#   3: second session registers another location under a held domain
#   4: second session registers routeByHTTPUser under a held domain
#   5: full domain outside rootDomain without a policy
#   7: login claiming another client's live session id
#   8: data-connection injection with a victim session id (raw client)
#  10: failed multi-domain registration leaves a route behind
#  11: 40 domains x 40 locations must be rejected by a cap (scaled down
#      from 1000x1000 so the pre-fix run stays fast; the cap is 32/32/64)
#
# Repro 6 (policy allows only tcp, http registration must be rejected)
# cannot run before Step 2: a policy token cannot even log in on main.
# Its e2e case lands with Step 3.
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

SERVER_PORT=49532
VHOST_PORT=49781
UP_A=49701
UP_B=49702
TOKEN="e2e-token-11"

cat >"$RUN_DIR/server-11.toml" <<EOF
listen      = "127.0.0.1:$SERVER_PORT"
httpGwPort  = $VHOST_PORT
rootDomain  = "example.com"

[auth]
type  = "token"
token = "$TOKEN"

[transport]
tcpMux = false
EOF

mk_client() { # $1=config $2=tunnel-name $3=domains-toml $4=extra-toml $5=service-port
  cat >"$RUN_DIR/$1" <<EOF
server = "127.0.0.1:$SERVER_PORT"

[auth]
type  = "token"
token = "$TOKEN"

[transport]
tcpMux = false

# #12: test server uses an ephemeral self-signed cert; no CA/TOFU.
[transport.tls]
insecureSkipVerify = true

[[tunnels]]
name     = "$2"
protocol = "http"
service  = "127.0.0.1:$5"
domains  = $3
$4
EOF
}

start_bg "$LOG_DIR/server-11.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-11.toml"
wait_tcp 127.0.0.1 $SERVER_PORT
wait_tcp 127.0.0.1 $VHOST_PORT

start_bg "$LOG_DIR/up-a.log" python3 "$script_dir/http_upstream.py" $UP_A
start_bg "$LOG_DIR/up-b.log" python3 "$script_dir/http_upstream.py" $UP_B
wait_tcp 127.0.0.1 $UP_A
wait_tcp 127.0.0.1 $UP_B

# Echo upstream for repro 6b: the TCP tunnel check expects byte echo,
# which the HTTP upstreams above cannot provide.
ECHO_B=49705
start_bg "$LOG_DIR/echo-b.log" python3 "$script_dir/tcp_echo.py" 127.0.0.1 $ECHO_B
wait_tcp 127.0.0.1 $ECHO_B

# --- Client A: owns app.example.com ---
mk_client client-a.toml web '["app.example.com"]' "" $UP_A
rm -f "$RUN_DIR/client-a.toml.session_id"
start_bg "$LOG_DIR/client-a.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-a.toml"
wait_log "$LOG_DIR/client-a.log" "tunnel started" 30
A_ID="$(cat "$RUN_DIR/client-a.toml.session_id")"
[[ -n "$A_ID" ]] || { echo "FAIL: client A has no session id"; exit 1; }
echo "Client A session id: $A_ID"

# --- Repro 2: same tunnel name, second session ---
mk_client client-b1.toml web '["app.example.com"]' "" $UP_B
start_bg "$LOG_DIR/client-b1.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-b1.toml"
wait_log "$LOG_DIR/client-b1.log" "tunnel start failed" 30
echo "Repro 2 PASS: same-name takeover rejected"

# --- Repro 3: other location under the held domain ---
mk_client client-b2.toml other '["app.example.com"]' 'locations = ["/login"]' $UP_B
start_bg "$LOG_DIR/client-b2.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-b2.toml"
wait_log "$LOG_DIR/client-b2.log" "tunnel start failed" 30
echo "Repro 3 PASS: other location under held domain rejected"

# --- Repro 4: routeByHTTPUser under the held domain ---
mk_client client-b3.toml other2 '["app.example.com"]' 'routeByHTTPUser = "alice"' $UP_B
start_bg "$LOG_DIR/client-b3.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-b3.toml"
wait_log "$LOG_DIR/client-b3.log" "tunnel start failed" 30
echo "Repro 4 PASS: routeByHTTPUser under held domain rejected"

# --- Repro 5: full domain outside rootDomain, no policy ---
mk_client client-c.toml outside '["evil.com"]' "" $UP_B
start_bg "$LOG_DIR/client-c.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-c.toml"
wait_log "$LOG_DIR/client-c.log" "tunnel start failed" 30
echo "Repro 5 PASS: full domain outside rootDomain rejected"

# --- Repro 6: policy enforcement (second server with token_policies) ---
POLICY_SERVER=49533
POLICY_VHOST=49782
POLICY_TCP_REMOTE=49703
cat >"$RUN_DIR/server-11-policy.toml" <<EOF
listen      = "127.0.0.1:$POLICY_SERVER"
httpGwPort  = $POLICY_VHOST
rootDomain  = "example.com"

[auth]
type  = "token"
token = "$TOKEN"

[[auth.token_policies]]
token = "tcp-only-token"
allowed_protocols = ["tcp"]

[transport]
tcpMux = false
EOF
start_bg "$LOG_DIR/server-11-policy.log" \
  "$BIN_DIR/orbien-server" -c "$RUN_DIR/server-11-policy.toml"
wait_tcp 127.0.0.1 $POLICY_SERVER
wait_tcp 127.0.0.1 $POLICY_VHOST

mk_policy_client() { # $1=config $2=token $3=tunnel-toml
  cat >"$RUN_DIR/$1" <<EOF
server = "127.0.0.1:$POLICY_SERVER"

[auth]
type  = "token"
token = "$2"

[transport]
tcpMux = false

# #12: test server uses an ephemeral self-signed cert; no CA/TOFU.
[transport.tls]
insecureSkipVerify = true

$3
EOF
}

# 6a: policy token allows only tcp -> http registration rejected
mk_policy_client client-p1.toml "tcp-only-token" '[[tunnels]]
name     = "p-web"
protocol = "http"
service  = "127.0.0.1:'$UP_B'"
domains  = ["p.example.com"]'
start_bg "$LOG_DIR/client-p1.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-p1.toml"
wait_log "$LOG_DIR/client-p1.log" "tunnel start failed" 30
echo "Repro 6a PASS: policy token (tcp only) cannot register http"

# 6b: same policy token, tcp tunnel -> accepted, data flows
mk_policy_client client-p2.toml "tcp-only-token" "[[tunnels]]
name       = \"p-tcp\"
protocol   = \"tcp\"
service    = \"127.0.0.1:$ECHO_B\"
remotePort = $POLICY_TCP_REMOTE"
start_bg "$LOG_DIR/client-p2.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-p2.toml"
wait_tcp 127.0.0.1 $POLICY_TCP_REMOTE 30
python3 "$script_dir/tcp_check.py" 127.0.0.1 $POLICY_TCP_REMOTE
echo "Repro 6b PASS: policy token tcp tunnel accepted"

# 6c: global token is NOT listed in policies -> fail-closed, rejected
mk_policy_client client-p3.toml "$TOKEN" '[[tunnels]]
name       = "p-tcp-global"
protocol   = "tcp"
service    = "127.0.0.1:'$UP_B'"
remotePort = 49704'
start_bg "$LOG_DIR/client-p3.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-p3.toml"
wait_log "$LOG_DIR/client-p3.log" "tunnel start failed" 30
echo "Repro 6c PASS: unlisted global token denied (fail-closed)"

# --- Repro 7: login claiming A's live session id ---
mk_client client-d.toml d-web '["d.example.com"]' "" $UP_B
cp "$RUN_DIR/client-a.toml.session_id" "$RUN_DIR/client-d.toml.session_id"
start_bg "$LOG_DIR/client-d.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-d.toml"
wait_log "$LOG_DIR/client-d.log" "login ok" 30
sleep 3
D_ID="$(cat "$RUN_DIR/client-d.toml.session_id")"
A_ID_NOW="$(cat "$RUN_DIR/client-a.toml.session_id")"
[[ "$D_ID" != "$A_ID" ]] || { echo "FAIL repro 7: attacker kept victim session id"; exit 1; }
[[ "$A_ID_NOW" == "$A_ID" ]] || { echo "FAIL repro 7: victim session id changed"; exit 1; }
kill -0 $(pgrep -f "orbien -c $RUN_DIR/client-a.toml" | head -1) 2>/dev/null \
  || { echo "FAIL repro 7: victim client died"; exit 1; }
echo "Repro 7 PASS: takeover rejected, attacker got a new id ($D_ID), victim kept $A_ID"

# --- Repro 10: conflicting second domain must not leave a route ---
mk_client client-e.toml squat '["free.example.com", "app.example.com"]' "" $UP_B
start_bg "$LOG_DIR/client-e.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-e.toml"
wait_log "$LOG_DIR/client-e.log" "tunnel start failed" 30
mk_client client-f.toml free '["free.example.com"]' "" $UP_B
start_bg "$LOG_DIR/client-f.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-f.toml"
wait_log "$LOG_DIR/client-f.log" "tunnel started" 30
echo "Repro 10 PASS: failed registration left no route; free.example.com still free"

# --- A disconnects, B can register the domain; same client reconnects ---
pkill -f "orbien -c $RUN_DIR/client-a.toml" || true
sleep 2
mk_client client-h.toml web '["app.example.com"]' "" $UP_B
start_bg "$LOG_DIR/client-h.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-h.toml"
wait_log "$LOG_DIR/client-h.log" "tunnel started" 30
echo "Repro 10b PASS: after A disconnects, B can register app.example.com"
# Same client restarts with its old session id file (resume of the dead
# id is refused, it gets a new id) and re-registers its own old domain.
# Client H from 10b must go first, or it still owns the domain.
pkill -f "orbien -c $RUN_DIR/client-h.toml" || true
sleep 2
start_bg "$LOG_DIR/client-a2.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-a.toml"
wait_log "$LOG_DIR/client-a2.log" "tunnel started" 30
echo "Repro 10c PASS: reconnecting client re-registers its own domain"

# --- Repro 11 (scaled): 40 domains x 40 locations must be rejected ---
DOMAINS="$(python3 -c "print('[' + ', '.join('\"d%d.example.com\"' % i for i in range(40)) + ']')")"
LOCS="$(python3 -c "print('[' + ', '.join('\"/p%d\"' % i for i in range(40)) + ']')")"
mk_client client-g.toml big "$DOMAINS" "locations = $LOCS" $UP_B
start_bg "$LOG_DIR/client-g.log" "$BIN_DIR/orbien" -c "$RUN_DIR/client-g.toml"
wait_log "$LOG_DIR/client-g.log" "tunnel start failed" 30
echo "Repro 11 PASS: 40x40 registration rejected by cap"

# --- Repro 8: data-connection injection with the victim session id ---
# Flood the pool with forged data conns, then drive visitor traffic at
# A's tunnel. If any forged conn receives StartDataConn, traffic leaks.
python3 "$script_dir/07-data-conn-inject.py" \
  127.0.0.1 $SERVER_PORT "$TOKEN" "$A_ID" >"$LOG_DIR/inject.log" 2>&1 &
INJECT_PID=$!
sleep 1
for _ in 1 2 3; do
  curl -fsS --max-time 5 -H 'Host: app.example.com' \
    "http://127.0.0.1:$VHOST_PORT/" >/dev/null 2>&1 || true
done
wait "$INJECT_PID" || true
grep -qx "NOT-INJECTED" "$LOG_DIR/inject.log" \
  || { echo "FAIL repro 8: forged data conn received visitor traffic"; cat "$LOG_DIR/inject.log"; exit 1; }
echo "Repro 8 PASS: forged data conns never reached a visitor"

# --- Repro 9: over-long Login hostname must be rejected ---
python3 "$script_dir/07-login-limits.py" \
  127.0.0.1 $SERVER_PORT "$TOKEN" >"$LOG_DIR/login-limits.log" 2>&1
grep -qx "REJECTED" "$LOG_DIR/login-limits.log" \
  || { echo "FAIL repro 9: over-long hostname login accepted"; cat "$LOG_DIR/login-limits.log"; exit 1; }
echo "Repro 9 PASS: over-long hostname login rejected"

echo "=== TOKEN POLICY E2E PASS ==="
