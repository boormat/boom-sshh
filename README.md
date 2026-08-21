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
zig build
```

Or with Rust + Zig already installed:

```bash
zig build
```

This builds the Zig client for all platforms and the Rust agent with embedded clients.

## Quick start

1. Run the agent locally:

```bash
eval $(./target/release/ssh-agent-history)
```

This prints `SSH_AUTH_SOCK=...; export SSH_AUTH_SOCK;` and starts the agent.

2. Set up a remote host:

```bash
./target/release/ssh-agent-history --setup user@remote-host
```

This detects the remote shell, installs `histsend`, and injects the trap into `~/.bashrc` (or `~/.zshrc`, `~/.config/fish/config.fish` if they exist).

3. SSH to the remote with agent forwarding:

```bash
ssh -A user@remote-host
```

4. Commands are now logged to `~/.history_all` on your local machine.

## Commands

| Command | Description |
|---|---|
| `ssh-agent-history` | Start the agent |
| `ssh-agent-history --setup <host>` | Setup remote host |
| `ssh-agent-history --setup --dry-run <host>` | Preview setup (no changes) |
| `ssh-agent-history --help` | Show help |
| `ssh-agent-history --version` | Show version |
| `ssh-agent-history --list-clients` | List embedded client architectures |
| `ssh-agent-history --extract-client <arch> <path>` | Extract client binary |

### Setup

`--setup` detects the remote shell and architecture, then:

1. Installs `histsend` to `~/.local/bin/histsend` on the remote
2. Injects the appropriate trap into each shell config file that exists:
   - `~/.bashrc` — bash trap
   - `~/.zshrc` — zsh trap
   - `~/.config/fish/conf.d/ssh-agent-history.fish` — fish trap

```bash
# Basic setup
ssh-agent-history --setup user@remote-host

# With SSH options
ssh-agent-history --setup -p 2222 -i ~/.ssh/key user@remote-host

# Preview what would be done
ssh-agent-history --setup --dry-run user@remote-host
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AGENT_HISTFILE` | `~/.history_all` | Path to the history log file |

Set it before starting the agent:

```bash
AGENT_HISTFILE=~/my-agent-history eval $(./target/release/ssh-agent-history)
```

## Manual remote setup

If you prefer not to use `--setup`, install `histsend` on the remote host and add to the appropriate shell config:

### Bash (`~/.bashrc`)

```bash
__ha_history_trap() {
    local _line
    _line=$(history 1)
    [[ -n "$_line" ]] && histsend "$HOSTNAME" "$UID" "$$" "$_line"
}
trap __ha_history_trap DEBUG
```

### Zsh (`~/.zshrc`)

```zsh
__ha_history_trap() {
    local _line
    _line=$(fc -l -1)
    [[ -n "$_line" ]] && histsend "$HOSTNAME" "$UID" "$$" "$_line"
}
TRAPDEBUG=__ha_history_trap
```

### Fish (`~/.config/fish/conf.d/ssh-agent-history.fish`)

```fish
function __ha_history_preexec --on-event fish_preexec
    if test -n "$argv[1]"
        histsend $HOSTNAME $UID %self "$argv[1]"
    end
end
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
# Build everything (Zig client + Rust agent)
zig build

# Build just the Zig client
zig build zig

# Build just the Rust agent
cargo build --release

# Run tests
cargo test
```

## Project structure

```
build.zig                      — build orchestrator
src/zig_tool/main.zig          — Zig client (histsend)
crates/agent/
  src/main.rs                  — agent entry point
  src/agent.rs                 — Session impl with keyring + history
  src/setup.rs                 — remote setup logic
  build.rs                     — embeds prebuilt clients
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
