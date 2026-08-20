#!/usr/bin/env bash
#
# remote-setup.sh — Configure a remote host's .bashrc for ssh-agent-history.
#
# Usage: remote-setup.sh [ssh-options] <host>
#
# The agent runs locally; this script configures the remote host's bash
# to send command history over the forwarded SSH_AUTH_SOCK.

set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 [ssh-options] <host>" >&2
    exit 1
fi

MARKER="# ssh-agent-history begin"

# The full bash config block to inject
read -r -d '' CONFIG_BLOCK << 'BLOCK'
# ssh-agent-history begin
# Automatically added by remote-setup.sh — do not edit between markers.
export AGENT_HISTFILE="${HOME}/.history_all"

__ha_to_ssh_int32() {
    local l=${1}
    printf '\\x%02X\\x%02x\\x%02X\\x%02X' \
        $((0xFF & l>>24)) $((0xFF & l>>16)) $((0xFF & l>>8)) $((0xFF & l>>0))
}

__ha_to_ssh_int8() {
    local l=${1}
    printf '\\x%02X' $((0xFF & l))
}

__ha_to_ssh_string() {
    declare -i l
    l=${#1}
    printf '%s%b' "$(__ha_to_ssh_int32 l)" "$1"
}

__ha_hist_get() {
    local _cmd
    _cmd="$(history 1)"
    _cmd=${_cmd:7}
    local msgtype="HISTORY"
    local payloadlen="$(( 4 + ${#_cmd} + 4 + ${#HOSTNAME} + 4 + ${#UID} ))"
    local totallen="$(( 1 + 4 + ${#msgtype} + 4 + payloadlen ))"
    printf %s%s%s%s%s%s%s \
        "$(__ha_to_ssh_int32 totallen)" \
        "$(__ha_to_ssh_int8 27)" \
        "$(__ha_to_ssh_string "${msgtype}")" \
        "$(__ha_to_ssh_int32 payloadlen)" \
        "$(__ha_to_ssh_string "${_cmd}")" \
        "$(__ha_to_ssh_string "${HOSTNAME}")" \
        "$(__ha_to_ssh_string "${UID}")"
}

__ha_history_trap() {
    local _cmd=$(history 1)
    local _cmdid=${_cmd:0:7}
    if [[ "$_cmdid" != "$_lastCommand" ]]; then
        _lastCommand="$_cmdid"
        printf "$(__ha_hist_get)" | nc -U "$SSH_AUTH_SOCK" > /dev/null 2>&1
    fi
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
