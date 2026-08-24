#!/usr/bin/env bash
# Manual test script for GUI popups.
# Run interactively: bash gui_test.sh
#
# Tests:
# 1. Version output consistency
# 2. TUI panel (terminal)
# 3. GUI dialog (zenity/kdialog)
# 4. Details button flow

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT="$SCRIPT_DIR/target/release/boom-sshh"
SSHEND="$SCRIPT_DIR/zig-out/x86_64-linux-musl/boom-sshend"

echo "=== Version consistency ==="
echo -n "  agent version:     "; $AGENT version
echo -n "  agent --version:   "; $AGENT --version
echo -n "  sshend version:    "; $SSHEND version
echo -n "  sshend --version:  "; $SSHEND --version
echo -n "  agent -V:          "; $AGENT -V
echo -n "  sshend -V:         "; $SSHEND -V

echo ""
echo "=== TUI approval panel ==="
echo "Press a=allow, d/q/Esc=deny"
echo '{"kind":"test","timestamp":0,"summary":["TUI test","press a to allow"]}' | $AGENT askpass
echo "Result: $?"

echo ""
echo "=== GUI approval dialog ==="
echo "Click Allow, Deny, or Details in the dialog"
echo '{"kind":"test","timestamp":0,"summary":["GUI test","click Allow to pass"]}' | BOOM_SSHH_FORCE_UI=gui $AGENT askpass
echo "Result: $?"

echo ""
echo "=== Details flow ==="
echo "Click Details, review, then click Allow"
echo '{"kind":"test","timestamp":0,"summary":["Details test","click Details then Allow"]}' | BOOM_SSHH_FORCE_UI=gui $AGENT askpass
echo "Result: $?"

echo ""
echo "All GUI tests complete."
