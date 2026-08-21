#!/usr/bin/env bash
# End-to-end test: build agent + client, start agent, send messages, verify history file.
#
# Usage: bash histsend_test.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_BIN="$SCRIPT_DIR/target/debug/ssh-agent-history"
HISTSEND_BIN="$SCRIPT_DIR/target/debug/histsend"
HISTFILE=$(mktemp)
SOCK=$(mktemp -u)
AGENT_PID=""

cleanup() {
    [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null || true
    rm -f "$SOCK" "$HISTFILE"
}
trap cleanup EXIT

PASS=0
FAIL=0

ok() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; [[ -n "${2:-}" ]] && echo "    $2"; FAIL=$((FAIL+1)); }

# ── build ────────────────────────────────────────────────────────

echo "Building..."
eval "$(mise activate bash)" > /dev/null 2>&1 || true
cargo build 2>/dev/null

# ── start agent ──────────────────────────────────────────────────

export SSH_AUTH_SOCK="$SOCK"
TEST_SSH_AUTH_SOCK="$SOCK" AGENT_HISTFILE="$HISTFILE" "$AGENT_BIN" 2>/dev/null &
AGENT_PID=$!
for i in $(seq 1 50); do [[ -S "$SOCK" ]] && break; sleep 0.05; done
[[ -S "$SOCK" ]] || { echo "FAIL: socket never appeared"; exit 1; }
echo "Agent pid=$AGENT_PID sock=$SOCK"

# ── tests ───────────────────────────────────────────────────────

echo ""
echo "=== Test 1: simple command ==="
"$HISTSEND_BIN" "testhost" "1000" "1234" "  42  ls -la"
sleep 0.2

grep -qF "#1" "$HISTFILE"                              && ok "timestamp"    || fail "timestamp"
grep -qF "testhost 1000 1234   42  ls -la" "$HISTFILE" && ok "full payload" || fail "full payload"

echo ""
echo "=== Test 2: special characters ==="
"$HISTSEND_BIN" "host-1.example.com" "1001" "9999" "  5  echo 'hello world' && ls"
sleep 0.2

grep -qF "echo 'hello world'" "$HISTFILE" && ok "special chars" || fail "special chars"
grep -qF "host-1.example.com" "$HISTFILE" && ok "long hostname" || fail "long hostname"

echo ""
echo "=== Test 3: entries accumulate ==="
"$HISTSEND_BIN" "h" "0" "111" "  1  pwd"
sleep 0.2

LINES=$(wc -l < "$HISTFILE")
[[ $LINES -ge 3 ]] && ok "accumulated ($LINES lines)" || fail "accumulated" "expected >=3 lines, got $LINES"

echo ""
echo "=== Test 4: file permissions ==="
PERMS=$(stat -c '%a' "$HISTFILE")
[[ "$PERMS" == "600" ]] && ok "file perms 600" || fail "file perms" "got $PERMS"

echo ""
echo "=== Test 5: log format ==="
FIRST=$(head -1 "$HISTFILE")
echo "$FIRST" | grep -qP '^#\d+ \S+ \d+ \d+ ' && ok "format: #ts host uid pid ..." || fail "format" "got: $FIRST"

echo ""
echo "=== Test 6: no args shows usage ==="
"$HISTSEND_BIN" 2>/dev/null; [[ $? -ne 0 ]] && ok "no-args exits non-zero" || fail "no-args"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
