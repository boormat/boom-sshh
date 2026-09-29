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

Commands are now logged to `~/.boom-sshh/history.log` on your local machine (JSONL).

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
                                       ~/.boom-sshh/history.log
```

Each history entry is written with a timestamp, hostname, uid, pid, and command:

```
#1700000000 myhost 1000 1234   42  ls -la /etc/hosts
```

## Commands

| Command | Description |
|---|---|
| `boom-sshh agent` | Start the agent |
| `boom-sshh agent --yolo` | Start the agent and approve every request |
| `boom-sshh init <host>` | Init remote host |
| `boom-sshh init --dry-run <host>` | Preview remote init |
| `boom-sshh init-agent` | Init local machine |
| `boom-sshh init-agent --dry-run` | Preview local init |
| `boom-sshh test-approval` | Test approval UI (GUI) |
| `boom-sshh askpass` | Prompt for approval (stdin) |
| `boom-sshh list-clients` | List embedded client architectures |
| `boom-sshh extract-client <arch> <path>` | Extract client binary |
| `boom-sshh help` | Show help |
| `boom-sshh version` | Show version |
| `boom-sshend version` | Show client version |

## Always-approve (`--yolo`)

`boom-sshh agent --yolo` starts the agent with approvals switched off: no approver
is spawned (no GUI, no askpass) and every sign request is allowed. It takes
precedence over `BOOM_SSHH_ASKPASS`, including one set to a custom program.

```bash
eval "$(boom-sshh agent --yolo)"
```

`--yolo` only applies at startup. If an agent is already running, the new
invocation still prints the existing socket and pid (so `eval` in a fresh shell
keeps working) but fails with an error on stderr — kill the running agent and
start it again to change the mode:

```bash
kill "$(cat ~/.boom-sshh/agent.pid)"
eval "$(boom-sshh agent --yolo)"
```

Approval decisions are logged either way; in `--yolo` mode
`~/.boom-sshh/auth.log` records `basis: "yolo"` and the history log is the only
record of what was signed.

## `init` (remote)

Detects remote shell (bash/zsh/fish) and the remote bash version, installs `boom-sshend`, and writes the appropriate hook into shell config files.

`init` replaces any boom-sshh lines already in those files rather than skipping
them, so re-running it re-decides the hook against the host's current bash — a
host upgraded to bash 5 moves from the `DEBUG` trap to `PS0`. Everything else in
the file is left as it was. The new contents are written through a sibling temp
file and moved into place, so a dropped connection cannot leave a truncated
config, and the original file mode is carried over. A file that is already
correct is reported as up to date and not rewritten at all.

```bash
boom-sshh init user@remote-host
boom-sshh init -p 2222 user@remote-host
boom-sshh init --dry-run user@remote-host
```

## `init-agent` (local)

Sets up the local machine:
- Installs boom-sshh agent and boom-sshend client
- Starts agent and adds history trap to your shell config
- Detects the available approval UI (zenity, kdialog)
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

Tests the approval UI without setting up the full agent. Useful for verifying that the GUI dialog works on your system.

```bash
boom-sshh test-approval   # show the approval dialog (zenity/kdialog)
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AGENT_HISTFILE` | `~/.boom-sshh/history.log` | Path to the history log file (JSONL) |
| `BOOM_SSHH_ASKPASS` | `boom-sshh askpass` | Approver program for sign prompts (`session-bind` is auto-recorded, never prompted). It reads a JSON request on stdin and prints a JSON envelope (`{"decision":"allow","ttl":"5m","criteria":{…}}`, `{"decision":"once"}`, `{"decision":"deny"}`); legacy tokens (`allow` / `allow 5m` / `allow session` / `deny`) are also accepted. `BOOM_SSHH_ASKPASS=true` = always allow (history-only mode). |
| `BOOM_SSHH_ASKPASS_TIMEOUT` | `60` | Approver timeout in seconds. |

```bash
AGENT_HISTFILE=~/my-agent-history eval $(boom-sshh agent)
```

## Manual setup

If you prefer not to use `init`, install `boom-sshend` on the remote host and add to the appropriate shell config.
boom-sshend auto-detects hostname, uid, pid — the hook only passes the command.

### Bash (`~/.bashrc`)

`init` reads the host's bash version and writes the hook that suits it, so the rc
file holds one unconditional line. Bash 4.4 and newer get `PS0`, which runs the
hook after each command is read and avoids the `DEBUG` trap conflicts common in
preconfigured bash 5 environments:

```bash
eval "$(boom-sshh agent)"
PS0='$(boom-sshend "$(history 1)" >/dev/null 2>&1)'"${PS0:-}"
```

Older bash gets the `DEBUG` trap, which every bash supports:

```bash
eval "$(boom-sshh agent)"
trap 'boom-sshend "$(history 1)"' DEBUG
```

Either way `init` and `init-agent` print which hook they chose (and the version
they read) before writing, so `--dry-run` shows the decision without touching the
file. When the version cannot be read — bash missing, or output that is not a
version — the `DEBUG` trap is used.

The `>/dev/null 2>&1` on the `PS0` line matters: `PS0`'s command-substitution
output is rendered into the prompt, so anything `boom-sshend` prints would appear
on the prompt line.

The same replacement logic runs locally and remotely: the config file is read,
the boom-sshh lines are removed, and the block for the chosen hook is appended.
Files written by earlier versions migrate on the next run — including fish
configs, whose preexec function is removed as a whole rather than only its first
line.

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

`boom-sshh agent --yolo` skips all of this: every request is allowed without an
approver (see [Always-approve](#always-approve---yolo)).

When no rule matches, the agent prompts via `BOOM_SSHH_ASKPASS` (the default
`boom-sshh askpass` shows a native GUI dialog via zenity/kdialog). Picking a
storing duration opens a second dialog where the exact rule criteria (key, op,
host) are shown and editable — `*` = any, `host=unbound` = only unbound signs.
The response can carry a duration:

| Response            | Meaning                                            |
|---|---|
| `allow forever`     | Allow until the agent exits (default)              |
| `allow once`        | Allow this one request only; nothing is remembered |
| `allow 5m`          | Allow for 5 minutes                                |
| `allow 1h`          | Allow for 1 hour                                   |
| `allow 12h`         | Allow for 12 hours                                 |
| `deny`              | Deny                                               |
| `allow 12h`         | Allow for 12 hours                                 |
| `deny`              | Deny                                               |

The stored rule matches the criteria you confirm — the key fingerprint,
operation class (`git-commit` / `git-tag` / `ssh-userauth`), and destination
host (from `session-bind`); any field can be widened to `*`. So approving
`ssh-userauth` to a host for `1h` makes subsequent connections to that host in
the next hour silent — which is what lets an ansible run over many hosts
proceed after a single approval.

If no GUI approver can be reached (e.g. a headless session with no
zenity/kdialog), the request **fails closed** (denied) rather than prompting —
set `BOOM_SSHH_ASKPASS=true`, or start the agent with `--yolo`, only as a
deliberate "always allow" security-off switch (history-only mode).

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
