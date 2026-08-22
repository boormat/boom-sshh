#!/usr/bin/env bash
# SSH integration test: starts sshd on a non-standard port, uses real SSH
# agent forwarding, sends boom-sshend from the remote side, verifies history.
#
# Usage: bash ssh_test.sh
#
# Requires: openssh-server installed (apt install openssh-server)
# No sudo is used — runs sshd on port 2222 as current user.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_BIN="$SCRIPT_DIR/target/release/boom-sshh"
HISTSEND_BIN="$SCRIPT_DIR/zig-out/x86_64-linux-musl/boom-sshend"
PORT=2222

# ── check prerequisites ─────────────────────────────────────────

if ! command -v sshd &>/dev/null && [ ! -x /usr/sbin/sshd ]; then
    echo "SKIP: sshd not found (install openssh-server)"
    exit 0
fi

SSHD_BIN=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)

if [ ! -x "$AGENT_BIN" ] || [ ! -x "$HISTSEND_BIN" ]; then
    echo "SKIP: binaries not built (run cargo build first)"
    exit 0
fi

# ── setup temp directory ────────────────────────────────────────

TMPDIR="$HOME/.ssh-test-$$"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"
trap 'cleanup' EXIT

cleanup() {
    [[ -n "$SSHD_PID" ]] && kill "$SSHD_PID" 2>/dev/null || true
    [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
}

SSHD_PID=""
AGENT_PID=""

# ── generate host keys ──────────────────────────────────────────

ssh-keygen -t ed25519 -f "$TMPDIR/ssh_host_ed25519_key" -N "" -q
ssh-keygen -t rsa -b 2048 -f "$TMPDIR/ssh_host_rsa_key" -N "" -q

# ── generate test user key ─────────────────────────────────────

ssh-keygen -t ed25519 -f "$TMPDIR/test_key" -N "" -q

# ── create authorized_keys ─────────────────────────────────────

mkdir -p "$TMPDIR/home/.ssh"
cp "$TMPDIR/test_key.pub" "$TMPDIR/home/.ssh/authorized_keys"
chmod 700 "$TMPDIR/home/.ssh"
chmod 600 "$TMPDIR/home/.ssh/authorized_keys"

# ── create sshd config ─────────────────────────────────────────

cat > "$TMPDIR/sshd_config" << EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $TMPDIR/ssh_host_ed25519_key
HostKey $TMPDIR/ssh_host_rsa_key
AuthorizedKeysFile $TMPDIR/home/.ssh/authorized_keys
PidFile $TMPDIR/sshd.pid
LogLevel ERROR
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
ChallengeResponseAuthentication no
UsePAM no
EOF

# ── start sshd ─────────────────────────────────────────────────

"$SSHD_BIN" -f "$TMPDIR/sshd_config" -E "$TMPDIR/sshd.log"
sleep 0.5

if ! kill -0 "$(cat "$TMPDIR/sshd.pid" 2>/dev/null)" 2>/dev/null; then
    echo "FAIL: sshd failed to start"
    cat "$TMPDIR/sshd.log" 2>/dev/null | tail -5
    exit 1
fi
SSHD_PID=$(cat "$TMPDIR/sshd.pid")
echo "sshd pid=$SSHD_PID port=$PORT"

# ── start agent ─────────────────────────────────────────────────

SOCK="$TMPDIR/agent.sock"
HISTFILE="$TMPDIR/history"
TEST_SSH_AUTH_SOCK="$SOCK" AGENT_HISTFILE="$HISTFILE" "$AGENT_BIN" 2>/dev/null &
AGENT_PID=$!
for i in $(seq 1 50); do [[ -S "$SOCK" ]] && break; sleep 0.05; done
[[ -S "$SOCK" ]] || { echo "FAIL: agent socket never appeared"; exit 1; }
echo "agent pid=$AGENT_PID sock=$SOCK"

export SSH_AUTH_SOCK="$SOCK"

# ── tests ───────────────────────────────────────────────────────

PASS=0
FAIL=0
ok() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; [[ -n "${2:-}" ]] && echo "    $2"; FAIL=$((FAIL+1)); }

echo ""
echo "=== Test 1: SSH with agent forwarding ==="
ssh -p "$PORT" \
    -i "$TMPDIR/test_key" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -A \
    127.0.0.1 \
    "PATH=$(dirname "$HISTSEND_BIN"):\$PATH boom-sshend testhost 1000 1234 '  42  ls -la'"
sleep 0.3

grep -qF "#1" "$HISTFILE"                              && ok "timestamp"    || fail "timestamp"
grep -qF "testhost 1000 1234   42  ls -la" "$HISTFILE" && ok "full payload" || fail "full payload"

echo ""
echo "=== Test 2: multiple SSH commands ==="
ssh -p "$PORT" \
    -i "$TMPDIR/test_key" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -A \
    127.0.0.1 \
    "PATH=$(dirname "$HISTSEND_BIN"):\$PATH boom-sshend remote-host 500 999 '  1  pwd'"
sleep 0.3

ssh -p "$PORT" \
    -i "$TMPDIR/test_key" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -A \
    127.0.0.1 \
    "PATH=$(dirname "$HISTSEND_BIN"):\$PATH boom-sshend remote-host 500 999 '  2  whoami'"
sleep 0.3

LINES=$(wc -l < "$HISTFILE")
[[ $LINES -ge 3 ]] && ok "accumulated ($LINES lines)" || fail "accumulated" "expected >=3 lines, got $LINES"

echo ""
echo "=== Test 3: command with special characters ==="
ssh -p "$PORT" \
    -i "$TMPDIR/test_key" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -A \
    127.0.0.1 \
    "PATH=$(dirname "$HISTSEND_BIN"):\$PATH boom-sshend sp 1000 2222 '  3  echo \"hello world\" && ls ~/\"my dir\"'"
sleep 0.3

grep -qF "echo \"hello world\"" "$HISTFILE" && ok "special chars" || fail "special chars"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
