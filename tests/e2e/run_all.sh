#!/usr/bin/env bash
# Run the full E2E acceptance suite in order.
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export ROOT="${GITHUB_WORKSPACE:-$(cd "$script_dir/../.." && pwd)}"
export BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
export RUN_DIR="${RUN_DIR:-$ROOT/.e2e}"
export LOG_DIR="${LOG_DIR:-$RUN_DIR/logs}"

mkdir -p "$RUN_DIR" "$LOG_DIR"

steps=(
  01-tcp.sh
  02-http.sh
  03-https.sh
  04-udp.sh
  05-token.sh
  06-dashboard.sh
  07-token-policy.sh
)

for step in "${steps[@]}"; do
  echo ""
  echo "━━━ Running $step ━━━"
  bash "$script_dir/$step"
done

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   ALL E2E ACCEPTANCE TESTS PASSED    ║"
echo "╚══════════════════════════════════════╝"
