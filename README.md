# ssh-agent-history

An SSH agent that logs command history from remote hosts via the SSH agent protocol extension mechanism.

The agent runs locally and accepts standard SSH agent requests (key storage, signing) plus a custom `HISTORY` extension. Remote hosts send each command over the forwarded `SSH_AUTH_SOCK` using a small client binary.

## How it works

```
┌──────────┐   SSH agent protocol    ┌──────────────┐
│ remote   │ ─────────────────────── │ ssh-agent-   │
│ bash     │   HISTORY extension     │ history      │
│ (trap)   │   over forwarded sock   │ (Rust, local)│
└──────────┘                         └──────┬───────┘
                                            │
                                     writes to
                                            ▼
                                     ~/.history_all
```

Each history entry is written with a timestamp, hostname, uid, pid, and command:

```
#1700000000 myhost 1000 1234   42  ls -la /etc/hosts
```

## Install

### From source

With [mise](https://mise.jdx.dev):

```bash
git clone https://github.com/boormat/ssh-agent-history.git
cd ssh-agent-history
mise install
cargo build --release
```

Or with Rust already installed:

```bash
cargo build --release
```

Binaries are at:
- `target/release/ssh-agent-history` — the agent
- `target/release/histsend` — the remote client

## Quick start

1. Run the agent locally:

```bash
eval $(./target/release/ssh-agent-history)
```

This prints `SSH_AUTH_SOCK=...; export SSH_AUTH_SOCK;` and starts the agent.

2. SSH to a remote host with agent forwarding:

```bash
ssh -A user@remote-host
```

3. Copy `histsend` to the remote and configure it:

```bash
scp target/release/histsend user@remote-host:~/.local/bin/
./remote-setup.sh user@remote-host
```

4. Commands are now logged to `~/.history_all` on your local machine.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AGENT_HISTFILE` | `~/.history_all` | Path to the history log file |

Set it before starting the agent:

```bash
AGENT_HISTFILE=~/my-agent-history eval $(./target/release/ssh-agent-history)
```

## Remote setup (manual)

If you prefer not to use `remote-setup.sh`, install `histsend` on the remote host (build with `cargo build --release -p histsend`, copy binary to PATH), then add to your remote host's `~/.bashrc`:

```bash
__ha_history_trap() {
    local _line
    _line=$(history 1)
    [[ -n "$_line" ]] && histsend "$HOSTNAME" "$UID" "$$" "$_line"
}
trap __ha_history_trap DEBUG
```

## Testing locally

You can test without SSH by setting `TEST_SSH_AUTH_SOCK`:

```bash
export TEST_SSH_AUTH_SOCK=/tmp/test-agent.sock
./target/release/ssh-agent-history &
# agent listens on /tmp/test-agent.sock instead of a random path
```

## Building

```bash
# Debug build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Run tests
cargo test
```

## Project structure

```
crates/
  agent/     — ssh-agent-history: the SSH agent server
  client/    — histsend: the remote client binary
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
