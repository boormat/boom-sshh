# AGENTS.md

## Shell commands
- Always set the `workdir` (working directory) parameter for each Bash command instead of using `cd <dir> && <command>` patterns. This keeps every command self-contained and avoids leaking directory state between calls. Default working directory is the repo root, so most commands need no `workdir` override.

## Build & test
- Full build (Zig client + Rust agent with embedded clients): `zig build`
- Build just the Rust agent: `cargo build --release`
- Type-check the crate: `cargo check -p boom-sshh`
- Run the crate's tests: `cargo test -p boom-sshh`

## Release / install
- End-user one-line install pulls `install.sh` from the latest release and runs it:
  `curl -fsSL https://github.com/boormat/boom-sshh/releases/latest/download/install.sh | sh`
- `install.sh` downloads the binary to a local temp dir, then runs `boom-sshh init-agent` which
  extracts the embedded `boom-sshend` client, copies the agent binary into place, and sets up
  a shell trap for automatic agent startup.

## Notes
- Client binary is `boom-sshend` (the per-command sender); agent binary is `boom-sshh`.
- The Zig source for the client lives in `src/zig_tool/main.zig`; it is compiled for each target and embedded into the Rust agent by `crates/boom-sshh/build.rs`.
- CLI uses subcommands: `boom-sshh agent`, `boom-sshh init`, `boom-sshh init-agent`, `boom-sshh test-approval`, `boom-sshh askpass`, etc. Running with no arguments prints an error.
- `boom-sshh agent --yolo` approves every request without an approver and takes precedence over `BOOM_SSHH_ASKPASS`. It only applies at startup: if an agent is already running, the invocation still prints the existing socket/pid on stdout (so `eval` keeps working) but reports the conflict on stderr and exits non-zero, so the flag is never silently ignored.
- Bash rc injection: `init`/`init-agent` read the host's bash version (`bash -c 'echo ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}'`, locally and over ssh) and write either the `PS0` hook (bash ≥ 4.4) or a `DEBUG` trap (older, or unreadable version) — one unconditional line, no runtime version test in the rc file. The chosen hook and probed version are printed, including under `--dry-run`. The hook's stdout/stderr are redirected on the `PS0` path because `PS0` substitution output is rendered into the prompt. zsh/fish hooks are unchanged.
- Both paths replace rather than skip: `with_block_replaced` (in `init.rs`) reads the config, strips every boom-sshh line, and appends the block for the chosen hook — the single place that decides a configured file's contents, shared by `init-agent` (local file) and `init` (file read and written over the muxed ssh connection, via a sibling temp file plus `mv`, skipping the write when already up to date). Remote runs therefore re-decide the hook from the host's current bash version, and a file that will not read aborts instead of being overwritten.
- Approvals (sign; destination-constraint if implemented) are delegated to `BOOM_SSHH_ASKPASS`. The default `boom-sshh askpass` shows a native GUI dialog (zenity/kdialog) with a single Deny button and Approve 5m/1h/12h/forever/once; picking a storing duration opens a second dialog where the rule criteria (key/op/host, `*` = any) are shown and editable. It prints a JSON envelope (`{"decision":"allow","ttl":…,"criteria":…}` / `{"decision":"once"}` / `{"decision":"deny"}`); legacy tokens are accepted from custom askpass scripts. No GUI helper → fail-closed; `BOOM_SSHH_ASKPASS=true` = history-only always-allow.
- `session-bind@openssh.com` is recorded automatically (never prompted) per PROTOCOL.agent; the recorded binding supplies the destination host fingerprint shown in sign prompts and scopes sign approvals by host. `restrict-destination-v00@openssh.com` is not advertised until it is actually enforced.
