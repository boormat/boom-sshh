#!/usr/bin/env bash
#
# remote-setup.sh — Configure a remote host's .bashrc for ssh-agent-history.
#
# Usage: remote-setup.sh [ssh-options] <host>
#
# The agent runs locally; this script configures the remote host's bash
# to send command history over the forwarded SSH_AUTH_SOCK.
#
# Requires `histsend` binary to be installed on the remote host.
# Build with: cargo build --release -p histsend
# Then copy target/release/histsend to the remote's PATH.

set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 [ssh-options] <host>" >&2
    exit 1
fi

MARKER="# ssh-agent-history begin"

# The bash config block to inject into ~/.bashrc
read -r -d '' CONFIG_BLOCK << 'BLOCK'
# ssh-agent-history begin
# Automatically added by remote-setup.sh — do not edit between markers.
# Requires `histsend` binary in PATH (build: cargo build --release -p histsend)
__ha_history_trap() {
    local _line
    _line=$(history 1)
    [[ -n "$_line" ]] && histsend "$HOSTNAME" "$UID" "$$" "$_line"
}
trap __ha_history_trap DEBUG
# ssh-agent-history end
BLOCK

echo "Configuring $* ..."
ssh "$@" bash -s -- "$MARKER" "$CONFIG_BLOCK" << 'EOF'
MARKER="$1"
BLOCK="$2"
if grep -qF "$MARKER" ~/.bashrc 2>/dev/null; then
    echo "Already configured — skipping."
else
    echo "$BLOCK" >> ~/.bashrc
    echo "Added to ~/.bashrc. Restart your shell or run: source ~/.bashrc"
fi
EOF
