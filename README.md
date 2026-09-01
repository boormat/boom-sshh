# boom-sshh

An SSH agent that logs command history from remote hosts via the SSH agent protocol extension mechanism.

The agent runs locally and accepts standard SSH agent requests (key storage, signing) plus a custom `HISTORY` extension. Remote hosts send each command over the forwarded `SSH_AUTH_SOCK` using a small client binary.

## Quick start

This starts installs the agent, and has it started in bashrc or equivalent. It is configured to log history via the agent.

```bash
curl -fsSL https://github.com/boormat/boom-sshh/releases/latest/download/install.sh | sh
boom-sshh init-agent

source ~/.bashrc

```

Set up a remote hosts environment. It installs the boom-sshend binary and configures to send history back to ssh-agent.

```bash
boom-sshh init user@remote-host
```

Commands are now logged to `~/.history_all` on your local machine.

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
| `boom-sshh agent` | Start the agent |
| `boom-sshh init <host>` | Init remote host |
| `boom-sshh init --dry-run <host>` | Preview remote init |
| `boom-sshh init-agent` | Init local machine |
| `boom-sshh init-agent --dry-run` | Preview local init |
| `boom-sshh test-approval` | Test approval UI |
| `boom-sshh test-approval --force-tui` | Force TUI panel |
| `boom-sshh test-approval --force-gui` | Force GUI dialog |
| `boom-sshh askpass` | Prompt for approval (stdin) |
| `boom-sshh list-clients` | List embedded client architectures |
| `boom-sshh extract-client <arch> <path>` | Extract client binary |
| `boom-sshh help` | Show help |
| `boom-sshh version` | Show version |
| `boom-sshend version` | Show client version |

## `init` (remote)

Detects remote shell (bash/zsh/fish), installs `boom-sshend`, and injects the trap into shell config files.

```bash
boom-sshh init user@remote-host
boom-sshh init -p 2222 user@remote-host
boom-sshh init --dry-run user@remote-host
```

## `init-agent` (local)

Sets up the local machine:
- Installs boom-sshh agent and boom-sshend client
- Starts agent and adds history trap to your shell config
- Detects the available approval UI (zenity, kdialog, or osascript)
- Confirms setup via GUI dialog before proceeding
- Checks for existing agent and warns if detected

```bash
boom-sshh init-agent
boom-sshh init-agent --dry-run
```

Pre-flight checks before modifying rc files:
- Warns (non-fatal) if ssh-agent is already running
- Warns (non-fatal) if other agent-startup lines are found in the rc file
- Reuses existing agent if already running (no duplicate instances)

## `test-approval`

Tests the approval UI without setting up the full agent. Useful for verifying that the TUI panel or GUI dialog works on your system.

```bash
boom-sshh test-approval              # auto-detect (TUI or GUI)
boom-sshh test-approval --force-tui  # force TUI panel on /dev/tty
boom-sshh test-approval --force-gui  # force GUI dialog (zenity/kdialog)
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AGENT_HISTFILE` | `~/.history_all` | Path to the history log file |
| `BOOM_SSHH_ASKPASS` | `boom-sshh askpass` | Approver program for sign prompts (`session-bind` is auto-recorded, never prompted). Executes the given command; prints `allow`, `allow 5m` / `allow 1h` / `allow 12h` / `allow session`, or `deny` to stdout. |
| `BOOM_SSHH_ASKPASS_TIMEOUT` | `60` | Approver timeout in seconds. |

```bash
AGENT_HISTFILE=~/my-agent-history eval $(boom-sshh agent)
```

## Manual setup

If you prefer not to use `init`, install `boom-sshend` on the remote host and add to the appropriate shell config.
boom-sshend auto-detects hostname, uid, pid — the trap only passes the command.

### Bash (`~/.bashrc`)

```bash
eval "$(boom-sshh agent)"
trap 'boom-sshend "$(history 1)"' DEBUG
```

### Zsh (`~/.zshrc`)

```zsh
eval "$(boom-sshh agent)"
TRAPDEBUG='boom-sshend "$(fc -l -1)"'
```

### Fish (`~/.config/fish/conf.d/boom-sshh.fish`)

```fish
eval (boom-sshh agent)
function __boomssh_preexec --on-event fish_preexec
    if test -n "$argv[1]"
        boom-sshend "$argv[1]"
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
./target/release/boom-sshh agent
```

## Signing approval policy

Every signature request is checked against an **in-memory** policy (never written
to disk; reset when the agent exits). Git commit/tag signing is allowed by
default; an `ssh-userauth` signature (ssh/scp/ansible/git push-pull) requires an
explicit, time-bounded approval the first time it is seen.

When no rule matches, the agent prompts via `BOOM_SSHH_ASKPASS` (the default
`boom-sshh askpass` shows a GUI dialog with zenity/kdialog when available, or a
TUI panel on `/dev/tty`). The response can carry a duration:

| Response            | Meaning                                            |
|---|---|
| `allow session`     | Allow, valid until the agent exits (default)      |
| `allow 5m`          | Allow for 5 minutes                                |
| `allow 1h`          | Allow for 1 hour                                   |
| `allow 12h`         | Allow for 12 hours                                 |
| `deny`              | Deny                                               |

The stored rule is keyed on the key fingerprint, operation class
(`git-commit` / `git-tag` / `ssh-userauth`), and destination host (from
`session-bind`). So approving `ssh-userauth` to a host for `1h` makes subsequent
connections to that host in the next hour silent — which is what lets an ansible
run over many hosts proceed after a single approval.

If no approver can be reached (e.g. a headless session with no GUI), the request
**fails closed** (denied) rather than prompting — set `BOOM_SSHH_ASKPASS=true`
only as a deliberate "always allow" security-off switch.

Security notes:
- Policy lives only in the agent process; there is no on-disk policy file to
  tamper with, and a restart returns to "prompt everything".
- The TTL bounds how long a delegation lasts (e.g. grant an AI agent limited
  access for a short window).
- The agent socket is the trust boundary; policy restricts by key/op/host. It
  does **not** inspect the calling process (`/proc`), so a rule for a host is
  usable by any local process that can reach the socket during its TTL.

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
