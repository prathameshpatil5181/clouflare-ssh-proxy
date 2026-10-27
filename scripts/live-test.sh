#!/usr/bin/env bash
# Optional live test against the real Cloudflare Tunnel.
# LIVE_HOST defaults to ssh.ppcoder.xyz.
#
# CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET are OPTIONAL:
# - unset  -> the proxy connects anonymously (tunnel NOT Access-protected)
# - set    -> the Access service-token headers are included
#
# Prints PASS/FAIL per step and maps HTTP statuses to likely causes.
# Never prints the secret.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIVE_HOST="${LIVE_HOST:-ssh.ppcoder.xyz}"
ID="${CF_ACCESS_CLIENT_ID:-}"
SECRET="${CF_ACCESS_CLIENT_SECRET:-}"
PASS=0; FAIL=0

say() { echo; echo "== $1 =="; }
step_pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
step_fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

CURL_AUTH=()
AUTH_MODE="no Access token (anonymous)"
if [[ -n "$ID" && -n "$SECRET" ]]; then
    CURL_AUTH=(-H "CF-Access-Client-Id: $ID" -H "CF-Access-Client-Secret: $SECRET")
    AUTH_MODE="Access service token: $ID"
elif [[ -n "$ID" || -n "$SECRET" ]]; then
    echo "ERROR: only one of CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET is set; set both or neither."
    exit 2
fi
echo "auth mode: $AUTH_MODE"

cd "$REPO_DIR"
cargo build -q
BIN="$REPO_DIR/target/debug/cfssh-proxy"

# ---------------------------------------------------------- 1 curl upgrade
say "1) WebSocket upgrade via curl (expect 101 + SSH banner)"
hdrs=$(curl -sS -i --max-time 15 -N \
  "${CURL_AUTH[@]}" \
  -o /dev/null -D /dev/stdout \
  -w '\nSTATUS:%{http_code}\n' \
  "$LIVE_HOST" 2>/dev/null | tr -d '\r')
status=$(awk -F: '/^STATUS:/{print $2; exit}' <<<"$hdrs")
echo "TLS/HTTP upgrade status: ${status:-none (connection failed)}"

case "${status:-000}" in
    101) step_pass "curl upgrade returned 101 (Switching Protocols)" ;;
    302) step_fail "302 redirect: the Access policy is NOT Service Auth for this hostname (token not accepted). Fix the Access application policy to use Service Auth." ;;
    401|403)
        if [[ ${#CURL_AUTH[@]} -eq 0 ]]; then
            step_fail "$status with NO token sent: this hostname IS protected by Zero Trust Access. Set CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET (Service Auth policy must include the token)."
        else
            step_fail "$status from Access: the service token is missing, wrong, or not included in the Access application's Service Auth policy."
        fi ;;
    502) step_fail "502: the Tunnel cannot reach the origin. On the server: systemctl status cloudflared, and verify the origin (port 2222) is up." ;;
    *) step_fail "unexpected status ${status:-<connection failed>} — network/DNS problem reaching the Cloudflare edge" ;;
esac

# ----------------------------------------------------- 2 cfssh-proxy banner
say "2) cfssh-proxy banner (expect an SSH-2.0-... banner on stdout)"
banner=$({ ( sleep 3 ); } | timeout 15 "$BIN" --verbose "$LIVE_HOST" 2>/tmp/cfssh-live.err | head -c 64 | tr -d '\0')
if [[ "$banner" == SSH-2.0-* ]]; then
    step_pass "got SSH banner: $banner"
else
    step_fail "no SSH banner; stderr:"
    sed -n 1,15p /tmp/cfssh-live.err
fi

say "3) suggested next step (not automated — it prompts for a password)"
cat <<EOF
Run:
  ssh -v -o ProxyCommand="cfssh-proxy %h" dev@$LIVE_HOST true
(IntelliJ: enable "Use OpenSSH config and authentication agent", then use Host devbox.)
EOF

echo
echo "----- live summary -----"
echo "passed=$PASS failed=$FAIL"
(( FAIL == 0 )) || exit 1
exit 0
