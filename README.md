# ssh-agent-history

An SSH agent that logs command history from remote hosts via the SSH agent protocol extension mechanism.

The agent runs locally and accepts standard SSH agent requests (key storage, signing) plus a custom `HISTORY` extension. Remote hosts send each command over the forwarded `SSH_AUTH_SOCK` using a bash `trap DEBUG` hook.

## How it works

```
┌──────────┐   SSH agent protocol    ┌──────────────┐
│ remote   │ ─────────────────────── │ ssh-agent-   │
│ bash     │   HISTORY extension     │ history      │
│ (trap)   │   over forwarded sock   │ (local)      │
└──────────┘                         └──────┬───────┘
                                            │
                                     writes to
                                            ▼
                                     ~/.history_all
```

Each history entry is written with a timestamp, hostname, and user:

```
#1700000000 myhost 1000
ls -la /etc/hosts
```

## Install

### Pre-built binaries

Download from [GitHub Releases](https://github.com/boormat/ssh-agent-history/releases).

### From source

With [mise](https://mise.jdx.dev):

```bash
git clone https://github.com/boormat/ssh-agent-history.git
cd ssh-agent-history
mise install
go build -ldflags="-s -w"
```

Or with Go already installed:

```bash
go install github.com/boormat/ssh-agent-history@latest
```

## Quick start

1. Run the agent locally:

```bash
eval $(./ssh-agent-history)
```

This prints `SSH_AUTH_SOCK=...; export SSH_AUTH_SOCK;` and starts the agent.

2. SSH to a remote host with agent forwarding:

```bash
ssh -A user@remote-host
```

3. Configure the remote host (idempotent, safe to re-run):

```bash
./remote-setup.sh user@remote-host
```

4. Commands are now logged to `~/.history_all` on your local machine.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AGENT_HISTFILE` | `~/.history_all` | Path to the history log file |

Set it before starting the agent:

```bash
AGENT_HISTFILE=~/my-agent-history eval $(./ssh-agent-history)
```

## Remote setup (manual)

If you prefer not to use `remote-setup.sh`, add this to your remote host's `~/.bashrc`:

```bash
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
```

## Testing locally

You can test without SSH by setting `TEST_SSH_AUTH_SOCK`:

```bash
export TEST_SSH_AUTH_SOCK=/tmp/test-agent.sock
./ssh-agent-history &
# agent listens on /tmp/test-agent.sock instead of a random path
```

## Building

```bash
go build -ldflags="-s -w" -o ssh-agent-history
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
