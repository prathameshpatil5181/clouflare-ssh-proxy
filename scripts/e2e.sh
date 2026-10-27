#!/usr/bin/env bash
# Layer 3: real SSH end-to-end test of cfssh-proxy as an OpenSSH ProxyCommand.
#
# 1. Starts a throwaway user-mode sshd on 127.0.0.1:2223 (generated ed25519
#    host key + client key, AllowTcpForwarding yes, internal-sftp).
# 2. Starts the mock edge in tcp-bridge mode pointing at that sshd.
# 3. Runs real OpenSSH THROUGH cfssh-proxy: shell command, SFTP 50 MiB up/down
#    with SHA-256 verification, local port forwarding (-L), idle-keepalive
#    survival, and a kill-the-edge mid-session check. Cleans up with a trap.
#
# Requires: openssh server+client, cargo. Skips (with a clear message) when
# sshd cannot run in the environment.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR_E2E="$(mktemp -d "${TMPDIR:-/tmp}/cfssh-e2e.XXXXXX")"
E2E_HOME=""   # set later: sshd keys/config must live under $HOME, never /tmp
SSHD_PORT=2223
KEEPALIVE_SECS=2
IDLE_WAIT=$(( KEEPALIVE_SECS * 3 ))

SSHD_BIN="${SSHD_BIN:-/usr/sbin/sshd}"
command -v ssh >/dev/null || { echo "SKIP (layer 3): ssh client not found"; exit 2; }
if [[ ! -x "$SSHD_BIN" ]]; then
    echo "SKIP (layer 3): sshd not found at $SSHD_BIN (install openssh-server), and Docker is not available either."
    exit 2
fi

VIS=$(id -u)
if [[ "$VIS" -ne 0 ]]; then
    # User-mode sshd needs its own dir set and no privilege separation quirks;
    # OpenSSH >=9.8 split binaries need sshd-session present (standard install).
    echo "info: running sshd in user mode (non-root)"
fi

PASS=0
FAIL=0
declare -a RESULTS=()
record() { RESULTS+=("$1"); echo "== $1 =="; }

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        if [[ -n "$p" && -e "/proc/$p" ]]; then kill -9 "$p" 2>/dev/null; fi
    done
}
trap cleanup EXIT

die() { echo "FAIL (layer 3): $*" >&2; exit 1; }

# ---------------------------------------------------------------- 0. build
cd "$REPO_DIR"
cargo build -q || die "cargo build failed"
BIN="$REPO_DIR/target/debug/cfssh-proxy"
PROXY_STUB="$TMPDIR_E2E/cfssh-proxy"
printf '#!/bin/sh\nexec "%s" --insecure-ws --keepalive-secs %s --verbose "$@"\n' \
    "$BIN" "$KEEPALIVE_SECS" > "$PROXY_STUB"
chmod +x "$PROXY_STUB"
export PATH="$PROXY_STUB:$PATH"   # so ssh's -o ProxyCommand=cfssh-proxy %h resolves

# ------------------------------------------------- 1. throwaway user sshd
# NOTE: sshd's secure_filename() check refuses authorized_keys under any
# world-writable directory (including /tmp), so the keys, config and
# authorized_keys must live under $HOME. The temp dir is only for logs and
# transfer payloads.
E2E_HOME="$HOME/.cfssh-e2e.$$"
TMPDIR_E2E="$E2E_HOME/tmp"
HOST_KEY="$E2E_HOME/host_ed25519"
CLIENT_KEY="$E2E_HOME/client_ed25519"
AUTH_KEYS="$E2E_HOME/authorized_keys"
SSHD_CONFIG="$E2E_HOME/sshd_config"
mkdir -p "$E2E_HOME" "$TMPDIR_E2E/home/.ssh" "$TMPDIR_E2E/run" "$TMPDIR_E2E/logs"
chmod 700 "$E2E_HOME"
ssh-keygen -q -t ed25519 -N '' -f "$HOST_KEY"
ssh-keygen -q -t ed25519 -N '' -f "$CLIENT_KEY"
cp "$CLIENT_KEY.pub" "$AUTH_KEYS"

cat > "$SSHD_CONFIG" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $HOST_KEY
PidFile $TMPDIR_E2E/sshd.pid
AuthorizedKeysFile $AUTH_KEYS
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding yes
X11Forwarding no
Subsystem sftp internal-sftp
UsePAM no
EOF

# sshd as non-root: must chroot-readable config & keep absolute paths ok
/usr/sbin/sshd -f "$SSHD_CONFIG" -D -e > "$TMPDIR_E2E/logs/sshd.log" 2>&1 &
SSHD_PID=$!
PIDS+=("$SSHD_PID")
sleep 1
kill -0 "$SSHD_PID" 2>/dev/null || { sed -n 1,20p "$TMPDIR_E2E/logs/sshd.log"; die "user-mode sshd failed to start"; }
echo "sshd (user-mode) on 127.0.0.1:$SSHD_PORT, pid $SSHD_PID"

# ------------------------------------------- 2. mock edge in tcp-bridge mode
cargo build -q --tests 2>/dev/null || true
# Build the mock-edge runner example (a local cloudflared stand-in).
cargo build -q --example mock_edge_runner 2>/dev/null || true
MOCK_BIN="$REPO_DIR/target/debug/examples/mock_edge_runner"
if [[ ! -x "$MOCK_BIN" ]]; then
    echo "SKIP (layer 3): mock_edge_runner example missing"
    exit 2
fi
MOCK_CLIENT_ID="e2e-client-id"
MOCK_CLIENT_SECRET="e2e-secret"
"$MOCK_BIN" tcp-bridge "127.0.0.1:$SSHD_PORT" \
    --client-id "$MOCK_CLIENT_ID" --client-secret "$MOCK_CLIENT_SECRET" \
    --run-for 120 > "$TMPDIR_E2E/logs/edge.log" 2>&1 &
EDGE_PID=$!
PIDS+=("$EDGE_PID")
for _ in $(seq 1 40); do
    PORT=$(head -1 "$TMPDIR_E2E/logs/edge.log" 2>/dev/null | tr -d '[:space:]')
    [[ -n "$PORT" && "$PORT" =~ ^[0-9]+$ ]] && break
    sleep 0.25
done
[[ -n "${PORT:-}" && "$PORT" =~ ^[0-9]+$ ]] || { sed -n 1,10p "$TMPDIR_E2E/logs/edge.log"; die "mock edge did not report a port"; }
echo "mock edge on 127.0.0.1:$PORT (tcp-bridge -> sshd)"
export CF_ACCESS_CLIENT_ID="$MOCK_CLIENT_ID"
export CF_ACCESS_CLIENT_SECRET="$MOCK_CLIENT_SECRET"

SSH_BASE=(ssh -F /dev/null -o ProxyCommand="$PROXY_STUB 127.0.0.1:$PORT"
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=15 -o ServerAliveInterval=10
    -i "$CLIENT_KEY" -p "$SSHD_PORT" "$(id -un)@127.0.0.1")

run_ssh() { "${SSH_BASE[@]}" "$@"; }

# -------------------------------------------------------------- 3. the tests

# 3.1 command round trip
out=$(run_ssh 'echo ok && uname -s' 2>"$TMPDIR_E2E/logs/ssh1.err"); rc=$?
if [[ $rc -eq 0 && "$out" == *ok* ]]; then
    record "PASS 3.1 ssh command round trip: $out"
    PASS=$((PASS+1))
else
    record "FAIL 3.1 ssh command round trip rc=$rc out=$out"; FAIL=$((FAIL+1)); sed -n 1,30p "$TMPDIR_E2E/logs/ssh1.err"
fi

# 3.2 SFTP 50 MiB round trip with SHA-256
head -c $((50*1024*1024)) /dev/urandom > "$TMPDIR_E2E/binary"
sum_local=$(sha256sum "$TMPDIR_E2E/binary" | awk '{print $1}')
if run_ssh "cat > /tmp/e2e-remote.bin" < "$TMPDIR_E2E/binary" 2>/dev/null; then
    sum_remote=$(run_ssh "sha256sum /tmp/e2e-remote.bin" 2>/dev/null | awk '{print $1}')
    run_ssh "dd if=/tmp/e2e-remote.bin bs=1M count=50 status=none" 2>/dev/null > "$TMPDIR_E2E/download"
    sum_down=$(sha256sum "$TMPDIR_E2E/download" | awk '{print $1}')
    if [[ "$sum_local" == "$sum_remote" && "$sum_local" == "$sum_down" ]]; then
        record "PASS 3.2 50 MiB round trip, sha256 match"
        PASS=$((PASS+1))
    else
        record "FAIL 3.2 sha mismatch local=$sum_local remote=$sum_remote down=$sum_down"
        FAIL=$((FAIL+1))
    fi
else
    record "FAIL 3.2a SFTP-like upload (ssh cat)"; FAIL=$((FAIL+1))
fi

# 3.3 local port forwarding through the tunnel
# The remote echo server lives ~20 s and accepts several connections, so ssh's
# forwarded connection always finds it listening.
python3 - <<'EOF' > "$TMPDIR_E2E/logs/echo.log" 2>&1 &
import socket, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 2233)); srv.listen(5)
print("echo-ready", flush=True)
end = time.time() + 20
while time.time() < end:
    srv.settimeout(max(0.1, end - time.time()))
    try:
        c, _ = srv.accept()
    except socket.timeout:
        break
    try:
        data = c.recv(1024)
        c.sendall(b"pong-" + data)
        c.close()
    except OSError:
        pass
EOF
ECHO_PID=$!
PIDS+=("$ECHO_PID")
for _ in $(seq 1 20); do
    grep -q echo-ready "$TMPDIR_E2E/logs/echo.log" 2>/dev/null && break
    sleep 0.25
done
( sleep 3 && printf 'hello-fwd' ) | run_ssh -N -L 7799:127.0.0.1:2233 2>"$TMPDIR_E2E/logs/fwd.err" &
FWD_PID=$!
PIDS+=("$FWD_PID")
sleep 4
fwdout=$( (printf 'hello-fwd'; sleep 1) | timeout 5 nc 127.0.0.1 7799 2>/dev/null )
if [[ "$fwdout" == "pong-hello-fwd" ]]; then
    record "PASS 3.3 local port forwarding (-L) + TCP echo"
    PASS=$((PASS+1))
else
    record "FAIL 3.3 port forward: got '$fwdout'"; echo "--- fwd.err:"; sed -n 1,20p "$TMPDIR_E2E/logs/fwd.err"; echo "--- echo.log:"; sed -n 1,10p "$TMPDIR_E2E/logs/echo.log"
    FAIL=$((FAIL+1))
fi
kill -9 "$ECHO_PID" 2>/dev/null

# 3.4 idle session survives >= keepalive interval, then runs a command
out=$(run_ssh "sleep $IDLE_WAIT && echo alive+" 2>/dev/null); rc=$?
if [[ $rc -eq 0 && "$out" == *alive* ]]; then
    record "PASS 3.4 idle > keepalive interval, session survives"
    PASS=$((PASS+1))
else
    record "FAIL 3.4 idle keepalive rc=$rc"
    FAIL=$((FAIL+1))
fi

# 3.5 trust: learn the sshd host key through the tunnel and pin it
# (the exact flow for "my container was recreated"). Requires ssh-keyscan.
if ! command -v ssh-keyscan >/dev/null 2>&1; then
    record "SKIP 3.5 trust/untrust pin refresh (ssh-keyscan not installed)"
else
    KH="$TMPDIR_E2E/known_hosts_test"
    : > "$KH"
    EXPECT_FP=$(ssh-keygen -lf "$HOST_KEY.pub" | awk '{print $2}')
    if timeout 60 "$BIN" trust --insecure-ws "127.0.0.1:$PORT" \
        --client-host 127.0.0.1 --client-port "$SSHD_PORT" \
        --known-hosts "$KH" > "$TMPDIR_E2E/logs/trust.log" 2>&1 &&
        ssh-keygen -lf "$KH" | grep -q "$EXPECT_FP"; then
        record "PASS 3.5 trust: key fetched via tunnel matches the real sshd key"
        PASS=$((PASS+1))
    else
        record "FAIL 3.5 trust: pinned key does not match sshd"
        FAIL=$((FAIL+1))
        echo "--- trust.log:"; sed -n 1,25p "$TMPDIR_E2E/logs/trust.log"
        echo "--- pinned:"; ssh-keygen -lf "$KH" 2>&1 | head -3
        echo "--- expected:"; ssh-keygen -lf "$HOST_KEY.pub" 2>&1
    fi

    # untrust removes exactly those pins again
    if "$BIN" untrust --known-hosts "$KH" "127.0.0.1:$SSHD_PORT" \
        > "$TMPDIR_E2E/logs/untrust.log" 2>&1 &&
        ! grep -qE '^(\[?127\.0\.0\.1|\|1\|) ' "$KH"; then
        record "PASS 3.6 untrust: stale pins removed, others untouched"
        PASS=$((PASS+1))
    else
        record "FAIL 3.6 untrust";
        FAIL=$((FAIL+1))
        echo "--- untrust.log:"; sed -n 1,10p "$TMPDIR_E2E/logs/untrust.log"
        echo "--- file remaining:"; head -5 "$KH"
    fi
fi

# 3.7 kill the mock edge mid-session; ssh must exit with a clear error
run_ssh "sleep 8 && echo should-not-happen" 2>"$TMPDIR_E2E/logs/kill.err" &
KP=$!
PIDS+=("$KP")
sleep 3
kill -9 "$EDGE_PID" 2>/dev/null
sleep 25
if kill -0 "$KP" 2>/dev/null; then
    kill -9 "$KP" 2>/dev/null
    wait "$KP" 2>/dev/null
    record "FAIL 3.7 ssh hung after edge killed"; FAIL=$((FAIL+1))
else
    wait "$KP" 2>/dev/null; rcs=$?
    record "PASS 3.7 edge killed -> ssh exits promptly (rc=$rcs, message above)"
    PASS=$((PASS+1))
fi

# ------------------------------------------------------------- 4. summary
echo
echo "----- layer 3 summary -----"
for r in "${RESULTS[@]}"; do echo "$r"; done
echo

rm -rf "$E2E_HOME" "$HOME/.ssh-e2e-test" 2>/dev/null
rm -rf "$TMPDIR_E2E"
cleanup
if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
