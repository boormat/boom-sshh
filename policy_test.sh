#!/usr/bin/env bash
# Policy integration test: starts its OWN sshd + agent in a temp dir, using a
# headless recording approver (no GUI, no pop-ups) and never touches the real
# ~/.ssh. Verifies:
#   - ssh-userauth prompts once, then is cached for the TTL window (silent)
#   - git-commit signing (ssh-keygen -Y sign) is auto-allowed by default
#   - with a denying approver, ssh-userauth is refused but git-commit still works
#   - `agent --yolo` approves without consulting the approver, and refuses to
#     start when an agent is already running
#
# Usage: bash policy_test.sh

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_BIN="$SCRIPT_DIR/target/release/boom-sshh"
PORT=2223

if [ ! -x "$AGENT_BIN" ]; then
    echo "SKIP: agent not built (run 'cargo build --release' first)"
    exit 0
fi
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
    echo "SKIP: sshd not found (install openssh-server)"
    exit 0
fi
SSHD_BIN=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)

TMPDIR="$HOME/.ssh-test-policy-$$"
rm -rf "$TMPDIR"; mkdir -p "$TMPDIR"
trap cleanup EXIT
cleanup() {
    [[ -n "$SSHD_PID" ]] && kill "$SSHD_PID" 2>/dev/null || true
    [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
SSHD_PID=""; AGENT_PID=""

# ── keys (temp only) ────────────────────────────────────────────────
ssh-keygen -t ed25519 -f "$TMPDIR/ssh_host_ed25519_key" -N "" -q
ssh-keygen -t ed25519 -f "$TMPDIR/test_key" -N "" -q
mkdir -p "$TMPDIR/home/.ssh"
cp "$TMPDIR/test_key.pub" "$TMPDIR/home/.ssh/authorized_keys"
chmod 700 "$TMPDIR/home/.ssh"; chmod 600 "$TMPDIR/home/.ssh/authorized_keys"

cat > "$TMPDIR/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $TMPDIR/ssh_host_ed25519_key
AuthorizedKeysFile $TMPDIR/home/.ssh/authorized_keys
PidFile $TMPDIR/sshd.pid
LogLevel ERROR
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
UsePAM no
EOF

"$SSHD_BIN" -f "$TMPDIR/sshd_config" -E "$TMPDIR/sshd.log"
sleep 0.5
SSHD_PID=$(cat "$TMPDIR/sshd.pid" 2>/dev/null)
if ! kill -0 "$SSHD_PID" 2>/dev/null; then
    echo "FAIL: sshd failed to start"; tail -5 "$TMPDIR/sshd.log"; exit 1
fi
echo "sshd pid=$SSHD_PID port=$PORT"

# ── headless recording approver (counts calls, allows 1h) ───────────
cat > "$TMPDIR/recorder.sh" <<'EOF'
#!/bin/sh
# records each invocation; approves for 1h
N=$(cat "$APPROVER_COUNT" 2>/dev/null || echo 0)
N=$((N + 1))
echo "$N" > "$APPROVER_COUNT"
echo "allow 1h"
EOF
chmod +x "$TMPDIR/recorder.sh"

# ── headless denying approver (refuses; exercises fail-closed) ──────
cat > "$TMPDIR/denier.sh" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$TMPDIR/denier.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

start_agent() {
    # $1 = approver script path; $2 = extra flags for the agent (optional)
    SOCK="$TMPDIR/agent.sock"
    HISTFILE="$TMPDIR/history"
    AUTHLOG="$TMPDIR/auth.log"
    export APPROVER_COUNT="$TMPDIR/approver.count"
    rm -f "$APPROVER_COUNT" "$SOCK" "$AUTHLOG"
    AGENT_OUTPUT=$(BOOM_SSHH_ASKPASS="$1" TEST_SSH_AUTH_SOCK="$SOCK" AGENT_HISTFILE="$HISTFILE" AGENT_AUTHLOG="$AUTHLOG" "$AGENT_BIN" agent ${2:-} 2>/dev/null)
    eval "$AGENT_OUTPUT"
    AGENT_PID=$SSH_AGENT_PID
    for i in $(seq 1 50); do [[ -S "$SOCK" ]] && break; sleep 0.05; done
    [[ -S "$SOCK" ]] || { echo "FAIL: agent socket missing"; exit 1; }
    export SSH_AUTH_SOCK="$SOCK"
    ssh-add "$TMPDIR/test_key" >/dev/null 2>&1
}

approver_calls() { cat "$TMPDIR/approver.count" 2>/dev/null || echo 0; }

# ── Test 1: ssh-userauth prompts once, then cached ─────────────────
# Each connection triggers two request_approval calls: session-bind (per
# connection) + sign (cached after first approval). First ssh = 2 calls,
# second ssh = 1 additional call (new bind, sign cached). Total = 3.
echo ""
echo "=== Test 1: ssh-userauth prompts once, then cached ==="
start_agent "$TMPDIR/recorder.sh"
ssh -p "$PORT" -i "$TMPDIR/test_key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR 127.0.0.1 'true'
sleep 0.2
[ "$(approver_calls)" = "2" ] && ok "first connection: bind+sign prompted (2 calls)" || fail "approver calls (got $(approver_calls), want 2)"
ssh -p "$PORT" -i "$TMPDIR/test_key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR 127.0.0.1 'true'
sleep 0.2
[ "$(approver_calls)" = "3" ] && ok "second connection: sign cached (3 total = 2+1 bind)" || fail "approver calls (got $(approver_calls), want 3)"
# kill this agent so its in-memory rule doesn't leak into later tests
kill "$AGENT_PID" 2>/dev/null || true

# ── Test 2: git-commit signing auto-allowed (no approver call) ─────
echo ""
echo "=== Test 2: git-commit signing auto-allowed ==="
start_agent "$TMPDIR/recorder.sh"
printf 'tree 0123456789abcdef\nparent 0123\nauthor A <a@b.c> 0 +0000\ncommitter A <a@b.c> 0 +0000\n\nmsg\n' > "$TMPDIR/commit.txt"
ssh-keygen -Y sign -f "$TMPDIR/test_key.pub" -n git "$TMPDIR/commit.txt" >/dev/null 2>&1
[ -f "$TMPDIR/commit.txt.sig" ] && ok "git commit sign produced signature" || fail "git commit sign produced signature"
[ "$(approver_calls)" = "0" ] && ok "git sign did NOT prompt approver" || fail "approver calls (got $(approver_calls), want 0)"
kill "$AGENT_PID" 2>/dev/null || true

# ── Test 3: denying approver -> ssh denied, git still allowed ──────
echo ""
echo "=== Test 3: denying approver (fail-closed) ==="
start_agent "$TMPDIR/denier.sh"
if ssh -p "$PORT" -i "$TMPDIR/test_key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes 127.0.0.1 'true' 2>/dev/null; then
    fail "ssh-userauth should be denied"
else
    ok "ssh-userauth denied by policy"
fi
printf 'tree abcdef0123456789\nauthor A <a@b.c> 0 +0000\n\nmsg\n' > "$TMPDIR/commit2.txt"
ssh-keygen -Y sign -f "$TMPDIR/test_key.pub" -n git "$TMPDIR/commit2.txt" >/dev/null 2>&1
[ -f "$TMPDIR/commit2.txt.sig" ] && ok "git commit still allowed under deny policy" || fail "git commit under deny policy"
kill "$AGENT_PID" 2>/dev/null || true

# ── Test 4: --yolo approves without ever calling the approver ──────
# The recorder approver is configured but must never be invoked: --yolo
# short-circuits before the askpass is consulted.
echo ""
echo "=== Test 4: --yolo approves everything ==="
start_agent "$TMPDIR/recorder.sh" --yolo
if ssh -p "$PORT" -i "$TMPDIR/test_key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes 127.0.0.1 'true' 2>/dev/null; then
    ok "ssh-userauth allowed under --yolo"
else
    fail "ssh-userauth denied under --yolo"
fi
[ "$(approver_calls)" = "0" ] && ok "approver never consulted under --yolo" || fail "approver calls (got $(approver_calls), want 0)"
grep -q '"basis":"yolo"' "$AUTHLOG" && ok "auth log records basis=yolo" || fail "auth log records basis=yolo"
grep -q '"askpass_reached":false' "$AUTHLOG" && ok "auth log records askpass_reached=false" || fail "auth log records askpass_reached=false"
kill "$AGENT_PID" 2>/dev/null || true

# ── Test 5: --yolo refuses when an agent is already running ────────
echo ""
echo "=== Test 5: --yolo with a running agent fails ==="
start_agent "$TMPDIR/recorder.sh"
set +e
YOLO_OUT=$(BOOM_SSHH_ASKPASS="$TMPDIR/recorder.sh" TEST_SSH_AUTH_SOCK="$SOCK" AGENT_HISTFILE="$HISTFILE" AGENT_AUTHLOG="$AUTHLOG" "$AGENT_BIN" agent --yolo 2>"$TMPDIR/yolo.err")
YOLO_RC=$?
set -e
[ "$YOLO_RC" -ne 0 ] && ok "--yolo against a running agent exits non-zero" || fail "--yolo should exit non-zero (got $YOLO_RC)"
echo "$YOLO_OUT" | grep -q 'SSH_AUTH_SOCK=' && ok "still prints SSH_AUTH_SOCK for eval" || fail "should still print SSH_AUTH_SOCK"
grep -q 'already running' "$TMPDIR/yolo.err" && ok "explains the conflict on stderr" || fail "stderr should explain the conflict"
kill "$AGENT_PID" 2>/dev/null || true

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
