# boom-sshh

An SSH agent that logs command history from remote hosts via the SSH agent protocol extension mechanism.

The agent runs locally and accepts standard SSH agent requests (key storage, signing) plus a custom `HISTORY` extension. Remote hosts send each command over the forwarded `SSH_AUTH_SOCK` using a small client binary.

## Quick start

Install the agent binary with the one-line installer, which downloads `install.sh`
from the latest release and runs it:

```bash
curl -fsSL https://github.com/boormat/boom-sshh/releases/latest/download/install.sh | sh
```

Then start the agent and set up a remote host:

1. Run the agent locally:

```bash
eval $(boom-sshh)
```

2. Set up a remote host:

```bash
boom-sshh --init user@remote-host
```

3. SSH to the remote with agent forwarding:

```bash
ssh -A user@remote-host
```

4. Commands are now logged to `~/.history_all` on your local machine.

## How it works

```
┌──────────┐   SSH agent protocol    ┌──────────────┐
│ remote   │ ─────────────────────── │  boom-sshh   │
│ bash     │   HISTORY extension     │              │
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

## Commands

| Command | Description |
|---|---|
| `boom-sshh` | Start the agent |
| `boom-sshh --init <host>` | Init remote host |
| `boom-sshh --init --dry-run <host>` | Preview remote init |
| `boom-sshh --init-agent` | Init local machine |
| `boom-sshh --init-agent --dry-run` | Preview local init |
| `boom-sshh --help` | Show help |
| `boom-sshh --version` | Show version |
| `boom-sshh --list-clients` | List embedded client architectures |
| `boom-sshh --extract-client <arch> <path>` | Extract client binary |

## `--init` (remote)

Detects remote shell (bash/zsh/fish), installs `boom-sshend`, and injects the trap into shell config files.

```bash
boom-sshh --init user@remote-host
boom-sshh --init -p 2222 user@remote-host
boom-sshh --init --dry-run user@remote-host
```

## `--init-agent` (local)

Sets up the local machine:
- Launches the agent via keychain on login
- Adds the history trap to your shell config
- Checks for existing agent/keychain and warns if detected

```bash
boom-sshh --init-agent
boom-sshh --init-agent --dry-run
```

Pre-flight checks before modifying rc files:
- Warns (non-fatal) if keychain is already managing an agent
- Warns (non-fatal) if ssh-agent is running
- Warns (non-fatal) if other agent-startup lines are found in the rc file
- Skips agent launch if boom-sshh is already running
- Skips if already configured

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AGENT_HISTFILE` | `~/.history_all` | Path to the history log file |
| `BOOM_SSHH_ASKPASS` | `boom-sshh --askpass` | Approver program for session-bind / destination-constraint / sign prompts. Default `boom-sshh --askpass` auto-selects a terminal panel (when a controlling tty exists) or a native GUI dialog (`zenity` → `kdialog` → `osascript`); set to `true` to always allow. |
| `BOOM_SSHH_ASKPASS_TIMEOUT` | `60` | Approver timeout in seconds. |

```bash
AGENT_HISTFILE=~/my-agent-history eval $(boom-sshh)
```

## Manual setup

If you prefer not to use `--init`, install `boom-sshend` on the remote host and add to the appropriate shell config:

### Bash (`~/.bashrc`)

```bash
__boomssh_trap() {
    local _line
    _line=$(history 1)
    [[ -n "$_line" ]] && boom-sshend "$HOSTNAME" "$UID" "$$" "$_line"
}
trap __boomssh_trap DEBUG
```

### Zsh (`~/.zshrc`)

```zsh
__boomssh_trap() {
    local _line
    _line=$(fc -l -1)
    [[ -n "$_line" ]] && boom-sshend "$HOSTNAME" "$UID" "$$" "$_line"
}
TRAPDEBUG=__boomssh_trap
```

### Fish (`~/.config/fish/conf.d/boom-sshh.fish`)

```fish
function __boomssh_preexec --on-event fish_preexec
    if test -n "$argv[1]"
        boom-sshend $HOSTNAME $UID %self "$argv[1]"
    end
end
```

## Build and Testing

For development, install the toolchain via [mise](https://mise.jdx.dev)
(defined in `mise.toml`), then build:

```bash
mise install
zig build
```

This builds the Zig client (`boom-sshend`) for all platforms and the Rust agent
with embedded clients. Additional targets:

```bash
# Build just the Zig client
zig build zig

# Build just the Rust agent
cargo build --release

# Run tests
cargo test
```

### Testing locally

```bash
export TEST_SSH_AUTH_SOCK=/tmp/test-agent.sock
./target/release/boom-sshh &
```

## Project structure

```
build.zig                      — build orchestrator
src/zig_tool/main.zig          — Zig client (boom-sshend)
crates/boom-sshh/
  src/main.rs                  — agent entry point
  src/agent.rs                 — Session impl with keyring + history
  src/approval.rs              — askpass approval prompting
  src/init.rs                  — remote + local init logic
  build.rs                     — embeds prebuilt clients
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
