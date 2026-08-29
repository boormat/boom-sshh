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
- Approvals (session-bind / destination-constraint / sign) are delegated to `BOOM_SSHH_ASKPASS`. The default `boom-sshh askpass` auto-selects a terminal panel when a controlling tty exists, otherwise a native GUI dialog (zenity/kdialog/osascript); both show Allow / Deny and a Details drill-down. Exit code 0 = allow, non-zero = deny.
