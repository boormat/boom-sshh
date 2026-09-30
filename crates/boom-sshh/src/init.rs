use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

struct RemoteInfo {
    arch: String,
    client_installed: bool,
    bashrc: bool,
    zshrc: bool,
    fish_config: bool,
    /// `MAJOR.MINOR` from the host's bash, or `None` when it could not be read.
    bash_version: Option<String>,
}

/// The command-capture mechanism to write into a shell config.
///
/// Chosen at init time from the target shell and, for bash, the version of bash
/// on that host, so the rc file gets one unconditional line instead of testing
/// `BASH_VERSINFO` on every shell start.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Hook {
    /// bash >= 4.4: `PS0` runs after each command is read.
    BashPs0,
    /// Older bash: the `DEBUG` trap, which every bash supports.
    BashDebugTrap,
    /// zsh: `TRAPDEBUG`.
    Zsh,
    /// fish: `fish_preexec`.
    Fish,
}

impl Hook {
    fn label(self) -> &'static str {
        match self {
            Hook::BashPs0 => "bash PS0 (bash >= 4.4)",
            Hook::BashDebugTrap => "bash DEBUG trap (bash < 4.4 or unknown)",
            Hook::Zsh => "zsh TRAPDEBUG",
            Hook::Fish => "fish fish_preexec",
        }
    }

    /// Shell whose rc file this hook belongs to. Also selects the stripping
    /// rules, since the fish block is the only multi-line one.
    fn shell(self) -> &'static str {
        match self {
            Hook::BashPs0 | Hook::BashDebugTrap => "bash",
            Hook::Zsh => "zsh",
            Hook::Fish => "fish",
        }
    }
}

/// `PS0` was added in bash 4.4. An unreadable version falls back to the `DEBUG`
/// trap, which works on every bash.
fn bash_supports_ps0(version: Option<&str>) -> bool {
    match version.and_then(parse_major_minor) {
        Some((major, minor)) => major > 4 || (major == 4 && minor >= 4),
        None => false,
    }
}

/// Parse `5.2` or `5.2.15` into `(major, minor)`. Anything else — including the
/// bare `.` that `bash -c` prints when `BASH_VERSINFO` is unset — is rejected.
fn parse_major_minor(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// The hook for a shell. Bash depends on the version probed on that host; every
/// other shell has a single form.
fn hook_for(shell: &str, bash_version: Option<&str>) -> Hook {
    match shell {
        "bash" if bash_supports_ps0(bash_version) => Hook::BashPs0,
        "bash" => Hook::BashDebugTrap,
        "zsh" => Hook::Zsh,
        _ => Hook::Fish,
    }
}

/// Agent flags we know how to keep when rewriting an existing startup line.
const KEEPABLE_AGENT_FLAGS: [&str; 1] = ["--yolo"];

/// Agent flags already present on a startup line, filtered to the ones we
/// understand.
///
/// Lets `init`/`init-agent` rewrite the block without discarding a mode the user
/// chose, such as `agent --yolo`. Unknown flags are dropped rather than carried
/// forward: a flag the CLI no longer accepts would break every new shell.
fn kept_agent_flags(contents: &str) -> Vec<String> {
    for line in contents.lines() {
        if line.contains("boom-sshh agent") && line.contains("eval") {
            if let Some(rest) = line.split("boom-sshh agent").nth(1) {
                return rest
                    .split(|c: char| c.is_whitespace() || matches!(c, ')' | '"' | '\''))
                    .filter(|token| KEEPABLE_AGENT_FLAGS.contains(token))
                    .map(str::to_string)
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Build the shell snippet that starts the agent and sends each command via `boom-sshend`.
/// boom-sshend auto-detects hostname, uid, pid — the hook only passes the command.
/// Deduplication is handled by the agent (not the shell).
fn build_trap_block(hook: Hook, agent_flags: &[String]) -> String {
    let flags = match agent_flags.is_empty() {
        true => String::new(),
        false => format!(" {}", agent_flags.join(" ")),
    };

    let startup = match hook {
        Hook::Fish => format!("eval (boom-sshh agent{flags})\n"),
        _ => format!("eval \"$(boom-sshh agent{flags})\"\n"),
    };

    // The `>/dev/null 2>&1` on the PS0 substitution is load-bearing: PS0's
    // substitution output is rendered into the prompt, and boom-sshend prints an
    // error string when it cannot reach the agent.
    let capture = match hook {
        Hook::BashPs0 => "PS0='$(boom-sshend \"$(history 1)\" >/dev/null 2>&1)'\"${PS0:-}\"\n",
        Hook::BashDebugTrap => "trap 'boom-sshend \"$(history 1)\"' DEBUG\n",
        Hook::Zsh => "TRAPDEBUG='boom-sshend \"$(fc -l -1)\"'\n",
        Hook::Fish => "function __boomssh_preexec --on-event fish_preexec\n    if test -n \"$argv[1]\"\n        boom-sshend \"$argv[1]\"\n    end\nend\n",
    };

    format!("{startup}{capture}")
}

/// Replace any boom-sshh lines in `contents` with the block for `hook`, and
/// return the new file contents.
///
/// The one place that decides what a configured rc file looks like, so the local
/// and remote paths cannot drift apart again. Appending is idempotent: editing a
/// file that is already up to date returns it unchanged.
fn with_block_replaced(contents: &str, shell: &str, hook: Hook) -> String {
    let mut out = remove_existing_traps(contents, shell);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&build_trap_block(hook, &kept_agent_flags(contents)));
    out
}

/// Remote command that replaces `path` with `contents`.
///
/// Written through a sibling temp file so a dropped connection cannot leave the
/// config truncated, with `cp -p` carrying the original mode onto the
/// replacement. The heredoc delimiter is quoted, so nothing in `contents` — the
/// `$(boom-sshend …)` and `${PS0:-}` of the hook included — is expanded by the
/// remote shell.
fn write_block_command(path: &str, contents: &str) -> String {
    let tmp = format!("{path}.boomsshh.tmp");
    format!(
        "[ -f {path} ] && cp -p {path} {tmp}; cat > {tmp} << 'HISTEOF'\n{contents}HISTEOF\nmv {tmp} {path}"
    )
}

/// Remove all existing boom-ssh lines from config contents.
/// Handles both the current PS0 hook and the legacy DEBUG trap.
fn remove_existing_traps(contents: &str, shell: &str) -> String {
    let mut result = String::new();
    // Set while inside the fish preexec function, counting nested `if`s, so the
    // whole function (body and closing `end`s) is removed as one unit.
    let mut fish_depth: Option<usize> = None;

    for line in contents.lines() {
        if shell == "fish" {
            if let Some(depth) = fish_depth {
                let trimmed = line.trim();
                if trimmed == "end" {
                    fish_depth = if depth == 0 { None } else { Some(depth - 1) };
                } else if trimmed.starts_with("if ") {
                    fish_depth = Some(depth + 1);
                }
                continue;
            }
        }
        // Skip agent startup line
        if line.contains("boom-sshh agent") && line.contains("eval") {
            continue;
        }
        // Skip command-capture lines: DEBUG trap, PS0 hook, zsh TRAPDEBUG.
        if line.contains("boom-sshend")
            && (line.contains("trap") || line.contains("TRAPDEBUG") || line.contains("PS0"))
        {
            continue;
        }
        // Start of the fish preexec function.
        if shell == "fish" && line.contains("function __boomssh_preexec") {
            fish_depth = Some(0);
            continue;
        }

        result.push_str(line);
        result.push('\n');
    }

    result
}

/// Token present in every injected block; used to detect an already-configured shell.
const CONFIG_SENTINEL: &str = "boom-sshend";

// ── init (remote) ─────────────────────────────────────────────

pub fn run_init(args: &[String], dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("usage: boom-sshh init [--dry-run] <ssh-args...> <host>");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  boom-sshh init user@remote-host");
        eprintln!("  boom-sshh init -p 2222 user@remote-host");
        eprintln!("  boom-sshh init --dry-run user@remote-host");
        std::process::exit(1);
    }

    // Filter out our own flags, pass rest to SSH
    let filtered: Vec<&str> = args
        .iter()
        .filter(|a| *a != "--dry-run" && *a != "-d")
        .map(|s| s.as_str())
        .collect();

    let host = filtered.last().ok_or("no host specified")?;
    let ssh_args = &filtered[..filtered.len() - 1];

    // Per-host control socket for connection multiplexing. Reusing one master
    // connection means a single authentication instead of one per ssh/scp call.
    let mut control_path = std::env::temp_dir();
    control_path.push(format!("boom-sshh-init-{}.sock", sanitize_host(host)));
    let control_path = control_path.to_string_lossy().into_owned();

    // Pre-flight: ensure an agent is reachable and holds a key, so ssh never
    // needs to fall back to an interactive password prompt.
    ensure_agent_ready()?;

    println!("detecting remote {host}...");
    let info = detect_remote(&ssh_args, host, &control_path)?;

    // Map arch to client name
    let client_arch = match info.arch.as_str() {
        "x86_64" | "x86-64" => "x86_64-linux",
        "aarch64" | "arm64" => "aarch64-linux",
        other => {
            eprintln!("error: unsupported remote architecture: {other}");
            eprintln!("supported: x86_64, aarch64");
            std::process::exit(1);
        }
    };

    println!("remote arch: {}", info.arch);
    println!("client: {client_arch}");

    // Determine which config files to inject into, and which capture hook each
    // one needs. For bash that depends on the version we probed on the host.
    let mut configs: Vec<(&str, Hook)> = Vec::new();
    if info.bashrc {
        let hook = hook_for("bash", info.bash_version.as_deref());
        let bash_ver = info.bash_version.as_deref().unwrap_or("unknown");
        println!("bash:     {bash_ver} -> {}", hook.label());
        configs.push(("~/.bashrc", hook));
    }
    if info.zshrc {
        configs.push(("~/.zshrc", Hook::Zsh));
    }
    if info.fish_config {
        configs.push((
            "~/.config/fish/conf.d/boom-sshh.fish",
            Hook::Fish,
        ));
    }

    if configs.is_empty() {
        eprintln!("error: no supported shell config found on remote");
        eprintln!("checked: ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish");
        std::process::exit(1);
    }

    // init always copies (overwrites) boom-sshend to the remote, so reflect that
    // in both real and dry-run output.
    if dry_run {
        if info.client_installed {
            println!("boom-sshend: would copy to remote (overwriting existing)");
        } else {
            println!("boom-sshend: would copy to remote (new)");
        }
    } else if info.client_installed {
        println!("boom-sshend: already installed (will be overwritten)");
    } else {
        println!("boom-sshend: not installed");
    }

    // Work out the new contents of each rc file now, by reading it over the same
    // muxed connection. Doing it up front lets --dry-run report what a real run
    // would do, and lets a file that is already correct be left untouched.
    struct ConfigPlan<'a> {
        path: &'a str,
        hook: Hook,
        /// Whether the file existed; a missing one is created.
        exists: bool,
        /// New file contents: existing boom-sshh lines swapped for this hook.
        updated: String,
        /// `false` when the remote file already matches `updated`.
        needs_write: bool,
    }

    let mut plans: Vec<ConfigPlan> = Vec::new();
    for (path, hook) in &configs {
        let exists = ssh_exec(ssh_args, host, &format!("test -f {path}"), &control_path).is_ok();
        // A file that exists but will not read is fatal: building new contents
        // from an empty buffer would throw away the user's config.
        let current = if exists {
            match ssh_exec(ssh_args, host, &format!("cat {path}"), &control_path) {
                Ok(contents) => contents,
                Err(e) => {
                    eprintln!("error: cannot read {path} on {host}: {e}");
                    close_mux(&control_path, ssh_args, host);
                    std::process::exit(1);
                }
            }
        } else {
            String::new()
        };
        let updated = with_block_replaced(&current, hook.shell(), *hook);
        plans.push(ConfigPlan {
            path,
            hook: *hook,
            exists,
            needs_write: !(exists && updated == current),
            updated,
        });
    }

    for p in &plans {
        let action = match (p.needs_write, p.exists) {
            (false, _) => "already up to date".to_string(),
            (true, true) if dry_run => "would replace boom-sshh block".to_string(),
            (true, true) => "will replace boom-sshh block".to_string(),
            (true, false) if dry_run => "would create with boom-sshh block".to_string(),
            (true, false) => "will create with boom-sshh block".to_string(),
        };
        println!("{:<44} {} ({})", p.path, action, p.hook.label());
    }

    if dry_run {
        println!();
        println!("(dry run — no changes made)");
        close_mux(&control_path, ssh_args, host);
        return Ok(());
    }

    // Extract client to temp file
    let tmp_dir = std::env::temp_dir().join("boom-sshh-init");
    fs::create_dir_all(&tmp_dir)?;
    let client_path = tmp_dir.join("boom-sshend");

    let client_bytes = match client_arch {
        "x86_64-linux" => super::CLIENT_X86_64_LINUX,
        "aarch64-linux" => super::CLIENT_AARCH64_LINUX,
        "x86_64-macos" => super::CLIENT_X86_64_MACOS,
        "aarch64-macos" => super::CLIENT_AARCH64_MACOS,
        _ => unreachable!(),
    };

    if client_bytes.is_empty() {
        eprintln!("error: client not embedded for {client_arch}");
        std::process::exit(1);
    }

    fs::write(&client_path, client_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&client_path, fs::Permissions::from_mode(0o755))?;
    }

    println!();
    println!("installing boom-sshend...");

    // SCP to remote — convert -p PORT to -P PORT for scp
    let remote_path = format!("{host}:~/.local/bin/boom-sshend");
    let mut scp_args: Vec<String> = ssh_args.iter().map(|s| s.to_string()).collect();
    let mut i = 0;
    while i < ssh_args.len() {
        if ssh_args[i] == "-p" && i + 1 < ssh_args.len() {
            scp_args.push("-P".to_string());
            scp_args.push(ssh_args[i + 1].to_string());
            i += 2;
        } else {
            scp_args.push(ssh_args[i].to_string());
            i += 1;
        }
    }
    scp_args.extend(mux_opts(&control_path));
    scp_args.extend([
        "-O".to_string(),
        "-q".to_string(),
        client_path.to_str().unwrap().to_string(),
    ]);
    scp_args.push(remote_path);

    // First ensure directory exists
    let mut mkdir_args: Vec<String> = ssh_args.iter().map(|s| s.to_string()).collect();
    mkdir_args.extend(mux_opts(&control_path));
    mkdir_args.extend([
        "-q".to_string(),
        host.to_string(),
        "--".to_string(),
        "mkdir".to_string(),
        "-p".to_string(),
        "~/.local/bin".to_string(),
    ]);

    let status = Command::new("ssh").args(&mkdir_args).status()?;
    if !status.success() {
        eprintln!("error: failed to create ~/.local/bin on remote");
        eprintln!("       (check that your key is loaded in the agent: ssh-add -l)");
        close_mux(&control_path, ssh_args, host);
        std::process::exit(1);
    }

    // scp supports the same -o passthrough as ssh
    let status = Command::new("scp").args(&scp_args).status()?;
    if !status.success() {
        eprintln!("error: failed to copy boom-sshend to remote");
        eprintln!("       (check that your key is loaded in the agent: ssh-add -l)");
        close_mux(&control_path, ssh_args, host);
        std::process::exit(1);
    }

    // Make executable
    let mut chmod_args: Vec<String> = ssh_args.iter().map(|s| s.to_string()).collect();
    chmod_args.extend(mux_opts(&control_path));
    chmod_args.extend([
        "-q".to_string(),
        host.to_string(),
        "--".to_string(),
        "chmod".to_string(),
        "+x".to_string(),
        "~/.local/bin/boom-sshend".to_string(),
    ]);

    let status = Command::new("ssh").args(&chmod_args).status()?;
    if !status.success() {
        eprintln!("error: failed to chmod boom-sshend on remote");
        eprintln!("       (check that your key is loaded in the agent: ssh-add -l)");
        close_mux(&control_path, ssh_args, host);
        std::process::exit(1);
    }

    println!("boom-sshend installed to ~/.local/bin/boom-sshend");

    // Replace the boom-sshh lines in each rc file. Writing goes through a sibling
    // temp file so the real file is never left truncated if the connection drops,
    // and `cp -p` carries the original mode onto the replacement. A file that
    // already matches is not written at all.
    for p in &plans {
        if !p.needs_write {
            continue;
        }
        println!("updating {}...", p.path);

        let write_cmd = write_block_command(p.path, &p.updated);
        let mut write_args: Vec<String> = ssh_args.iter().map(|s| s.to_string()).collect();
        write_args.extend(mux_opts(&control_path));
        write_args.extend([
            "-t".to_string(),
            host.to_string(),
            "--".to_string(),
            "bash".to_string(),
            "-c".to_string(),
            write_cmd,
        ]);

        let status = Command::new("ssh").args(&write_args).status()?;
        if !status.success() {
            eprintln!("error: failed to update {}", p.path);
            eprintln!("       (check that your key is loaded in the agent: ssh-add -l)");
            close_mux(&control_path, ssh_args, host);
            std::process::exit(1);
        }

        println!("  {}: done ({})", p.path, p.hook.label());
    }

    // Cleanup
    let _ = fs::remove_dir_all(&tmp_dir);
    close_mux(&control_path, ssh_args, host);

    println!();
    println!("init complete! Restart your shell or run: source ~/.bashrc");
    Ok(())
}

// ── init-agent (local) ────────────────────────────────────────

pub fn run_init_agent(dry_run: bool, assume_yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    if dry_run {
        println!("=== DRY RUN — no changes will be made ===");
        println!();
    } else {
        println!("boom-sshh init-agent {}", env!("CARGO_PKG_VERSION"));
        println!();
    }

    // Detect local shell
    let shell = detect_local_shell();
    let shell_name = shell.rsplit('/').next().unwrap_or(&shell);

    // Determine which config file to modify
    let config_path = match shell_name {
        "bash" => Some(dirs_or_default().join(".bashrc")),
        "zsh" => Some(dirs_or_default().join(".zshrc")),
        "fish" => Some(dirs_or_default().join(".config/fish/conf.d/boom-sshh.fish")),
        _ => None,
    };

    let config_path = match config_path {
        Some(p) => p,
        None => {
            eprintln!("error: unsupported shell: {shell_name}");
            eprintln!("supported: bash, zsh, fish");
            std::process::exit(1);
        }
    };

    let config_display = config_path.to_str().unwrap_or("?");

    // Pick the capture hook from the shell and, for bash, the local bash version,
    // so the rc file needs no runtime version test.
    let bash_version = if shell_name == "bash" {
        detect_local_bash_version()
    } else {
        None
    };
    let hook = hook_for(shell_name, bash_version.as_deref());

    // ── Detect shell and config ──
    println!("shell:    {shell_name}");
    println!("config:   {config_display}");
    match shell_name {
        "bash" => println!(
            "bash:     {} -> {}",
            bash_version.as_deref().unwrap_or("unknown"),
            hook.label()
        ),
        _ => println!("hook:     {}", hook.label()),
    }

    // ── Pre-flight conflict checks ──
    let mut warnings: Vec<String> = Vec::new();
    let boom_running = check_boom_sshh_running();
    let ssh_auth_valid = check_ssh_auth_sock_valid();

    if boom_running {
        warnings.push("boom-sshh agent already running — startup trap will reuse it".into());
    }
    if ssh_auth_valid && !boom_running {
        warnings.push("ssh-agent detected — boom-sshh will take over as the agent".into());
    }
    if check_ssh_agent_running() {
        warnings.push("ssh-agent is already running — will be replaced by boom-sshh".into());
    }
    if config_path.exists() {
        let contents = fs::read_to_string(&config_path).unwrap_or_default();
        if contents.contains(CONFIG_SENTINEL) {
            warnings.push("already configured — will update".into());
        }
    }
    warn_config_conflicts_collect(&config_path, &mut warnings);

    if !warnings.is_empty() {
        println!();
        for w in &warnings {
            println!("warning:  {w}");
        }
    }

    // ── Detect GUI helper (used for display + the confirm dialog) ──
    println!();
    let ui_desc = match crate::approval::detect_gui_helper() {
        Some(desc) => desc,
        None => "(none)".to_string(),
    };

    if dry_run {
        println!("approval UI: {ui_desc} (would confirm with user)");
        let install_dir = preferred_install_dir();
        let agent_dest = install_dir.join("boom-sshh");
        let identical = std::env::current_exe()
            .map_or(false, |c| agent_dest.exists() && files_identical(&c, &agent_dest));
        if identical {
            println!("agent:       {agent_dest:?} (up to date — no change)");
        } else {
            let verb = if agent_dest.exists() { "replace" } else { "install" };
            println!("agent:       would {verb} {agent_dest:?}");
        }
        println!("client:      would install boom-sshend to {install_dir:?}");
        println!("config:      would inject trap into {config_display}");
        println!();
        println!("(dry run — no changes made)");
        return Ok(());
    }

    // A GUI helper is required for the confirm dialog unless the user bypasses
    // it with --yes (e.g. when the dialog can't be reached / Wayland quirks).
    if !assume_yes {
        if ui_desc == "(none)" {
            eprintln!("error: no GUI helper found (zenity or kdialog)");
            eprintln!("       install one of these, or pass --yes to install without the");
            eprintln!("       confirmation dialog (see `boom-sshh help` for manual steps).");
            std::process::exit(1);
        }
        println!("approval UI: {ui_desc}");
        if !crate::approval::confirm_setup_gui() {
            println!("setup cancelled (dialog closed or timed out — run again and choose Allow,");
            println!("            or use `boom-sshh init-agent --yes` to skip the dialog).");
            return Ok(());
        }
    } else {
        println!("approval UI: skipped (--yes)");
    }

    println!();
    println!("agent:     will install + add trap with startup guard");

    // ── Install ──
    println!();
    println!("installing:");
    let install_dir = install_local_client()?;

    // Check if boom-sshh is in the install dir, copy if not
    install_agent_binary(&install_dir)?;

    // Replace the boom-sshh block with the one for the hook chosen above.
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let raw = fs::read_to_string(&config_path).unwrap_or_default();
    let contents = with_block_replaced(&raw, shell_name, hook);
    fs::write(&config_path, &contents)?;

    println!("config:    {config_display} — done");

    println!();
    println!("done! Restart your shell or run: source {config_display}");
    Ok(())
}

// ── pre-flight checks ───────────────────────────────────────────

fn check_ssh_agent_running() -> bool {
    Command::new("pgrep")
        .args(["-x", "ssh-agent"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn check_boom_sshh_running() -> bool {
    let my_pid = std::process::id();
    Command::new("pgrep")
        .args(["-x", "boom-sshh"])
        .output()
        .map(|o| {
            if !o.status.success() {
                return false;
            }
            // Check if any PID other than our own is running
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.trim().parse::<u32>().ok())
                .any(|pid| pid != my_pid)
        })
        .unwrap_or(false)
}

fn check_ssh_auth_sock_valid() -> bool {
    std::env::var("SSH_AUTH_SOCK")
        .map(|sock| {
            let path = std::path::Path::new(&sock);
            if !path.exists() {
                return false;
            }
            // Check if it's a socket using stat
            Command::new("test")
                .args(["-S", &sock])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Warn about other agent-launch mechanisms present in the shell config so the
/// user is aware of possible conflicts with the boom-sshh agent startup.
fn warn_config_conflicts_collect(path: &Path, warnings: &mut Vec<String>) {
    let Ok(contents) = fs::read_to_string(path) else {
        return;
    };
    for line in contents.lines() {
        // Skip lines that are part of our own config
        if line.contains("boom-sshend") || line.contains("boom-sshh") {
            continue;
        }
        for pat in ["ssh-agent", "keychain", "gpg-agent", "fish_ssh_agent", "ssh-add"] {
            if line.contains(pat) {
                warnings.push(format!("{} contains '{}' — possible conflict", path.display(), pat));
                break; // one warning per line is enough
            }
        }
    }
}

/// Pick the embedded client bytes matching the local OS/arch.
fn local_client_bytes() -> Option<&'static [u8]> {
    let os = Command::new("uname")
        .args(["-s"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let arch = Command::new("uname")
        .args(["-m"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    match (os.as_deref(), arch.as_deref()) {
        (Some("Linux"), Some("x86_64") | Some("amd64")) => Some(super::CLIENT_X86_64_LINUX),
        (Some("Linux"), Some("aarch64") | Some("arm64")) => Some(super::CLIENT_AARCH64_LINUX),
        (Some("Darwin"), Some("x86_64") | Some("amd64")) => Some(super::CLIENT_X86_64_MACOS),
        (Some("Darwin"), Some("aarch64") | Some("arm64")) => Some(super::CLIENT_AARCH64_MACOS),
        _ => None,
    }
}

/// Install the boom-sshend client locally so the injected trap can send history.
/// Mirrors the remote installer but writes to a local bin directory.
fn install_local_client() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let bytes = match local_client_bytes() {
        Some(b) if !b.is_empty() => b,
        _ => {
            eprintln!(
                "warning: no embedded boom-sshend client for this platform; skipping local client install"
            );
            // Still return the preferred install dir
            return Ok(preferred_install_dir());
        }
    };

    let install_dir = preferred_install_dir();
    // ~/.local/bin need not exist yet on a fresh machine.
    fs::create_dir_all(&install_dir)?;
    let dest = install_dir.join("boom-sshend");

    // Skip if already in place with same content
    if dest.exists() {
        if let Ok(existing) = fs::read(&dest) {
            if existing == bytes {
                println!("  boom-sshend    {dest:?} (up to date)");
                return Ok(install_dir);
            }
        }
    }

    // Write to a temp file then atomically rename into place, so we never
    // truncate a boom-sshend that happens to be executing mid-command.
    let tmp = install_dir.join(format!(".boom-sshend-install-{}.tmp", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, &dest)?;
    println!("  boom-sshend    {dest:?}");
    Ok(install_dir)
}

/// If `boom-sshh` is already on PATH, return its directory so a reinstall
/// upgrades that binary in place (rather than dropping a second copy into a
/// different dir and leaving the old one first on PATH).
fn detect_existing_install_dir() -> Option<PathBuf> {
    let out = Command::new("sh")
        .args(["-c", "command -v boom-sshh"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if p.is_empty() {
        return None;
    }
    let path = PathBuf::from(&p);
    path.is_file().then(|| path.parent().map(|parent| parent.to_path_buf())).flatten()
}

fn preferred_install_dir() -> PathBuf {
    // Prefer an already-installed location so reinstalls replace the binary in
    // the place it's actually found on PATH.
    if let Some(d) = detect_existing_install_dir() {
        return d;
    }
    // Fall back to the running exe's own */bin dir if applicable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if parent.file_name().map_or(false, |n| n == "bin") {
                return parent.to_path_buf();
            }
        }
    }
    if fs::write("/usr/local/bin/.boom-sshh-write-test", b"").is_ok() {
        let _ = fs::remove_file("/usr/local/bin/.boom-sshh-write-test");
        PathBuf::from("/usr/local/bin")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/bin")
    }
}

/// Copy the current boom-sshh binary to the install directory, overwriting any
/// existing binary that differs. We compare *contents*, not just the path: if the
/// running binary is the destination but a different build, it must be replaced.
///
/// The copy is written to a temp file and atomically renamed into place, so it
/// works even when the destination is the currently *running* agent binary
/// (directly overwriting an executing file fails with ETXTBSY "Text file busy").
fn install_agent_binary(install_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Create the destination rather than assuming a previous install made it.
    fs::create_dir_all(install_dir)?;
    let dest = install_dir.join("boom-sshh");
    let current = match std::env::current_exe() {
        Ok(c) => c,
        Err(e) => {
            println!("  boom-sshh      (skipped: cannot locate current executable: {e})");
            return Ok(());
        }
    };

    let identical = dest.exists() && files_identical(&current, &dest);
    if identical {
        println!("  boom-sshh      {dest:?} (up to date)");
        return Ok(());
    }

    let replacing = dest.exists();
    let tmp = install_dir.join(format!(".boom-sshh-install-{}.tmp", std::process::id()));
    fs::copy(&current, &tmp)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, &dest)?;
    if replacing {
        println!("  boom-sshh      {dest:?} (replaced)");
    } else {
        println!("  boom-sshh      {dest:?}");
    }
    Ok(())
}

/// True when two files exist with identical size and bytes.
fn files_identical(a: &Path, b: &Path) -> bool {
    let (a_len, b_len) = match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => (x.len(), y.len()),
        _ => return false,
    };
    if a_len != b_len {
        return false;
    }
    match (std::fs::read(a), std::fs::read(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

// ── local detection ─────────────────────────────────────────────

fn detect_local_shell() -> String {
    // Try $SHELL first
    if let Ok(shell) = std::env::var("SHELL") {
        return shell;
    }

    // Fallback to getent
    Command::new("getent")
        .args(["passwd"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            let user = std::env::var("USER").unwrap_or_default();
            s.lines()
                .find(|l| l.starts_with(&format!("{user}:")))
                .and_then(|l| l.split(':').nth(6))
                .map(String::from)
        })
        .unwrap_or_else(|| "/bin/sh".to_string())
}

/// `MAJOR.MINOR` of the local bash, or `None` when bash is missing or its output
/// is not a version. The hook for `~/.bashrc` is decided from this.
fn detect_local_bash_version() -> Option<String> {
    let out = Command::new("bash")
        .args(["-c", "echo ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let version = String::from_utf8(out.stdout).ok()?.trim().to_string();
    parse_major_minor(&version).map(|_| version)
}

// ── remote detection ────────────────────────────────────────────

fn detect_remote(
    ssh_args: &[&str],
    host: &str,
    control_path: &str,
) -> Result<RemoteInfo, Box<dyn std::error::Error>> {
    let arch = ssh_exec(ssh_args, host, "uname -m", control_path)?;
    let arch = arch.trim().to_string();

    // Ask about the path init installs to, not PATH: a non-interactive ssh
    // session has no ~/.local/bin (interactive rc files add it), so `which`
    // reports the client missing on hosts where it is installed.
    let client_installed = ssh_exec(
        ssh_args,
        host,
        "test -x ~/.local/bin/boom-sshend || command -v boom-sshend >/dev/null 2>&1",
        control_path,
    )
    .map(|_| true)
    .unwrap_or(false);

    let bashrc = ssh_exec(ssh_args, host, "test -f ~/.bashrc && echo yes || echo no", control_path)
        .map(|s| s.trim() == "yes")
        .unwrap_or(false);

    let zshrc = ssh_exec(ssh_args, host, "test -f ~/.zshrc && echo yes || echo no", control_path)
        .map(|s| s.trim() == "yes")
        .unwrap_or(false);

    let fish_config = ssh_exec(
        ssh_args,
        host,
        "test -f ~/.config/fish/config.fish && echo yes || echo no",
        control_path,
    )
    .map(|s| s.trim() == "yes")
    .unwrap_or(false);

    // The hook we write depends on the host's bash, so read its version here
    // rather than testing it from the rc file on every shell start. Single
    // quotes keep the remote login shell from expanding the array.
    let bash_version = ssh_exec(
        ssh_args,
        host,
        "bash -c 'echo ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}'",
        control_path,
    )
    .ok()
    .map(|v| v.trim().to_string())
    .filter(|v| parse_major_minor(v).is_some());

    Ok(RemoteInfo {
        arch,
        client_installed,
        bashrc,
        zshrc,
        fish_config,
        bash_version,
    })
}

fn ssh_exec(
    ssh_args: &[&str],
    host: &str,
    command: &str,
    control_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut args: Vec<String> = ssh_args.iter().map(|s| s.to_string()).collect();
    args.extend(mux_opts(control_path));
    args.extend(["-q".to_string(), host.to_string(), "--".to_string(), command.to_string()]);

    let output = Command::new("ssh").args(&args).output()?;

    if !output.status.success() {
        return Err(format!(
            "ssh command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(String::from_utf8(output.stdout)?)
}

/// SSH options that (a) reuse a single master connection for all the ssh/scp
/// calls init makes and (b) forbid interactive auth so a missing-agent key
/// fails loudly instead of prompting for a password.
fn mux_opts(control_path: &str) -> Vec<String> {
    vec![
        "-o".to_string(),
        "ControlMaster=auto".to_string(),
        "-o".to_string(),
        format!("ControlPath={control_path}"),
        "-o".to_string(),
        "ControlPersist=60".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
    ]
}

/// Close the multiplexed master connection so no control socket lingers.
/// Failures are ignored — this is best-effort cleanup.
fn close_mux(control_path: &str, ssh_args: &[&str], host: &str) {
    let mut args: Vec<String> = Vec::new();
    args.extend(ssh_args.iter().map(|s| s.to_string()));
    args.extend([
        "-o".to_string(),
        format!("ControlPath={control_path}"),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-q".to_string(),
        host.to_string(),
        "-O".to_string(),
        "exit".to_string(),
    ]);
    let _ = Command::new("ssh").args(&args).status();
}

/// Turn a host string into a filesystem-safe token for the control socket name.
fn sanitize_host(host: &str) -> String {
    host.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

/// Verify an SSH agent is reachable and holds at least one key, so that the
/// subsequent ssh/scp calls can authenticate without an interactive prompt.
fn ensure_agent_ready() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("SSH_AUTH_SOCK").is_err() {
        eprintln!("error: no SSH agent found (SSH_AUTH_SOCK is not set)");
        eprintln!("       start one with: eval $(boom-sshh agent)");
        std::process::exit(1);
    }

    let out = Command::new("ssh-add").arg("-l").output()?;
    if !out.status.success() {
        eprintln!("error: no keys loaded in the SSH agent");
        eprintln!("       add your key first: ssh-add ~/.ssh/id_rsa");
        std::process::exit(1);
    }

    Ok(())
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_agent_binary_replaces_when_different() {
        let dir = std::env::temp_dir().join(format!("bshh-install-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let dest = dir.join("boom-sshh");

        // A pre-existing, different binary must be overwritten.
        std::fs::write(&dest, b"OLD-BINARY-CONTENT").unwrap();
        install_agent_binary(&dir).unwrap();
        let after = std::fs::read(&dest).unwrap();
        assert_ne!(after, b"OLD-BINARY-CONTENT", "binary should have been replaced");
        assert!(
            files_identical(&std::env::current_exe().unwrap(), &dest),
            "dest should now match the running executable"
        );

        // A second run with identical content must be a no-op (up to date),
        // not a second copy.
        install_agent_binary(&dir).unwrap();
        assert!(files_identical(&std::env::current_exe().unwrap(), &dest));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_install_agent_binary_creates_missing_install_dir() {
        // A fresh machine has no ~/.local/bin; the install must create it rather
        // than failing with a raw NotFound from the first write.
        let root = std::env::temp_dir().join(format!("bshh-install-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("nested").join("bin");
        assert!(!dir.exists());

        install_agent_binary(&dir).unwrap();
        assert!(dir.join("boom-sshh").is_file(), "binary should have been installed");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_preferred_install_dir_reuses_exes_bin() {
        // If the running exe lives in a */bin dir, reinstalls stay in place.
        let exe = std::env::current_exe().unwrap();
        if let Some(parent) = exe.parent() {
            if parent.file_name().map_or(false, |n| n == "bin") {
                assert_eq!(preferred_install_dir(), parent, "should reuse the exe's bin dir");
            }
        }
    }

    #[test]
    fn test_bash_ps0_block_has_no_runtime_version_test() {
        let block = build_trap_block(Hook::BashPs0, &[]);

        assert!(
            block.contains("PS0='$(boom-sshend \"$(history 1)\" >/dev/null 2>&1)'\"${PS0:-}\""),
            "needs the PS0 hook (appending, with output redirected):\n{block}"
        );
        assert!(
            !block.contains("BASH_VERSINFO"),
            "the version is decided at init time, not in the rc file:\n{block}"
        );
        assert!(!block.contains("trap "), "no DEBUG trap on the PS0 path:\n{block}");
        assert_eq!(block.lines().count(), 2, "bash block should be exactly two lines:\n{block}");
    }

    #[test]
    fn test_bash_debug_trap_block_for_old_bash() {
        let block = build_trap_block(Hook::BashDebugTrap, &[]);

        assert_eq!(
            block,
            "eval \"$(boom-sshh agent)\"\ntrap 'boom-sshend \"$(history 1)\"' DEBUG\n"
        );
    }

    #[test]
    fn test_zsh_and_fish_blocks_unchanged() {
        assert_eq!(
            build_trap_block(Hook::Zsh, &[]),
            "eval \"$(boom-sshh agent)\"\nTRAPDEBUG='boom-sshend \"$(fc -l -1)\"'\n"
        );
        assert_eq!(
            build_trap_block(Hook::Fish, &[]),
            "eval (boom-sshh agent)\nfunction __boomssh_preexec --on-event fish_preexec\n    if test -n \"$argv[1]\"\n        boom-sshend \"$argv[1]\"\n    end\nend\n"
        );
    }

    #[test]
    fn test_write_block_command_is_quoted_and_atomic() {
        let contents = "PS0='$(boom-sshend \"$(history 1)\" >/dev/null 2>&1)'\"${PS0:-}\"\n";
        let cmd = write_block_command("~/.bashrc", contents);

        // Replace through a sibling temp file, preserving mode; the real config is
        // never truncated in place.
        assert!(cmd.contains("[ -f ~/.bashrc ] && cp -p ~/.bashrc ~/.bashrc.boomsshh.tmp"), "{cmd}");
        assert!(cmd.contains("mv ~/.bashrc.boomsshh.tmp ~/.bashrc"), "{cmd}");
        // Quoted delimiter: the hook's `$(…)` and `${…}` must reach the rc file
        // exactly as written, and the delimiter must be a whole line of its own.
        assert!(cmd.contains("<< 'HISTEOF'"), "{cmd}");
        assert!(cmd.contains(contents), "contents must be verbatim:\n{cmd}");
        assert_eq!(cmd.lines().filter(|l| *l == "HISTEOF").count(), 1, "{cmd}");
    }

    #[test]
    fn test_kept_agent_flags() {
        assert_eq!(kept_agent_flags("eval \"$(boom-sshh agent --yolo)\"\n"), vec!["--yolo"]);
        assert_eq!(kept_agent_flags("eval (boom-sshh agent --yolo)\n"), vec!["--yolo"]);
        assert_eq!(kept_agent_flags("eval \"$(boom-sshh agent)\"\n"), Vec::<String>::new());
        // A flag the CLI might not accept any more is dropped, not carried on.
        assert_eq!(
            kept_agent_flags("eval \"$(boom-sshh agent --something-else)\"\n"),
            Vec::<String>::new()
        );
        // Only our own startup line counts, and a bare mention is not one.
        assert_eq!(kept_agent_flags("# boom-sshh agent --yolo\n"), Vec::<String>::new());
        assert_eq!(kept_agent_flags(""), Vec::<String>::new());
    }

    #[test]
    fn test_with_block_replaced_keeps_the_mode_flag() {
        let rc = "alias ll='ls -l'\neval \"$(boom-sshh agent --yolo)\"\n";
        let updated = with_block_replaced(rc, "bash", Hook::BashPs0);
        assert!(
            updated.contains("eval \"$(boom-sshh agent --yolo)\""),
            "rewriting must not silently turn approvals back on:\n{updated}"
        );
        // ...and it survives repeated rewrites.
        assert_eq!(with_block_replaced(&updated, "bash", Hook::BashPs0), updated);

        // A plain startup line stays plain.
        let plain = with_block_replaced("eval \"$(boom-sshh agent)\"\n", "bash", Hook::BashPs0);
        assert!(plain.contains("eval \"$(boom-sshh agent)\"\n"), "{plain}");
        assert!(!plain.contains("--yolo"), "{plain}");
    }

    #[test]
    fn test_hook_shell_names() {
        assert_eq!(Hook::BashPs0.shell(), "bash");
        assert_eq!(Hook::BashDebugTrap.shell(), "bash");
        assert_eq!(Hook::Zsh.shell(), "zsh");
        assert_eq!(Hook::Fish.shell(), "fish");
    }

    #[test]
    fn test_with_block_replaced_is_idempotent() {
        // The remote path relies on this: re-running init must not accumulate
        // blocks, and an unchanged file must compare equal so it is not rewritten.
        for hook in [Hook::BashPs0, Hook::BashDebugTrap, Hook::Zsh, Hook::Fish] {
            let rc = "export PATH=$PATH:$HOME/.local/bin\nalias ll='ls -l'\n";
            let once = with_block_replaced(rc, hook.shell(), hook);
            let twice = with_block_replaced(&once, hook.shell(), hook);
            assert_eq!(once, twice, "{hook:?} accumulated a block:\n{twice}");
            assert_eq!(
                once.lines().filter(|l| l.contains("boom-sshend")).count(),
                1,
                "{hook:?} should leave exactly one hook line:\n{once}"
            );
            assert!(once.starts_with(rc), "{hook:?} must keep user lines:\n{once}");
        }
    }

    #[test]
    fn test_with_block_replaced_swaps_hook_both_ways() {
        // A host whose bash was upgraded must end up on PS0 alone...
        let legacy = with_block_replaced("", "bash", Hook::BashDebugTrap);
        let upgraded = with_block_replaced(&legacy, "bash", Hook::BashPs0);
        assert!(upgraded.contains("PS0="), "{upgraded}");
        assert!(
            !upgraded.contains("trap 'boom-sshend"),
            "the old trap must be gone, not duplicated:\n{upgraded}"
        );

        // ...and one that reads as older, or whose version we cannot read, goes
        // back to the trap rather than keeping PS0.
        let downgraded = with_block_replaced(&upgraded, "bash", Hook::BashDebugTrap);
        assert_eq!(downgraded.matches("trap 'boom-sshend").count(), 1, "{downgraded}");
        assert!(!downgraded.contains("PS0="), "{downgraded}");
    }

    #[test]
    fn test_with_block_replaced_migrates_unmarked_fish() {
        // Fish configs written before this change have no marker and no single
        // line we could match: the whole function has to be removed.
        let legacy = concat!(
            "set -gx EDITOR vim\n",
            "eval (boom-sshh agent)\n",
            "function __boomssh_preexec --on-event fish_preexec\n",
            "    if test -n \"$argv[1]\"\n",
            "        boom-sshend \"$argv[1]\"\n",
            "    end\n",
            "end\n",
        );
        let updated = with_block_replaced(legacy, "fish", Hook::Fish);
        assert_eq!(updated.matches("function __boomssh_preexec").count(), 1, "{updated}");
        assert_eq!(updated.matches("boom-sshend").count(), 1, "{updated}");
        assert!(updated.starts_with("set -gx EDITOR vim\n"), "user lines lost:\n{updated}");
    }

    #[test]
    fn test_bash_supports_ps0() {
        for (version, expected) in [
            (None, false),          // bash missing or version unreadable
            (Some("."), false),     // BASH_VERSINFO unset produced just a dot
            (Some(""), false),
            (Some("nonsense"), false),
            (Some("3.2"), false),
            (Some("4.3"), false),
            (Some("4.4"), true),    // first release with PS0
            (Some("4.9"), true),
            (Some("5.0"), true),
            (Some("5.2"), true),
            (Some("5.2.15"), true), // patch level is ignored
            (Some("6.1"), true),
        ] {
            assert_eq!(
                bash_supports_ps0(version),
                expected,
                "bash_supports_ps0({version:?}) should be {expected}"
            );
        }
    }

    #[test]
    fn test_hook_choice_per_shell() {
        assert_eq!(hook_for("bash", Some("5.2")), Hook::BashPs0);
        assert_eq!(hook_for("bash", Some("4.4")), Hook::BashPs0);
        assert_eq!(hook_for("bash", Some("4.3")), Hook::BashDebugTrap);
        assert_eq!(hook_for("bash", Some("3.2")), Hook::BashDebugTrap);
        // Version unreadable: the DEBUG trap works on every bash.
        assert_eq!(hook_for("bash", None), Hook::BashDebugTrap);
        assert_eq!(hook_for("zsh", None), Hook::Zsh);
        assert_eq!(hook_for("fish", None), Hook::Fish);
    }

    #[test]
    fn test_bash_hook_lines_are_valid_bash() {
        // Skip where bash is unavailable rather than failing on the host.
        if Command::new("bash").arg("-c").arg(":").output().is_err() {
            return;
        }
        for hook in [Hook::BashPs0, Hook::BashDebugTrap] {
            let file = std::env::temp_dir().join(format!("bshh-hook-{hook:?}.sh"));
            std::fs::write(&file, build_trap_block(hook, &[])).unwrap();
            let out = Command::new("bash").arg("-n").arg(&file).output().unwrap();
            assert!(
                out.status.success(),
                "{hook:?} hook does not parse: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let _ = std::fs::remove_file(&file);
        }
    }

    #[test]
    fn test_remove_existing_traps_strips_legacy_and_ps0() {
        // One rc holding every form we have written: the 0.3.x DEBUG trap, the
        // 0.4.0 version-guarded PS0 line, and the current bare PS0 line.
        let rc = concat!(
            "export PATH=$PATH:$HOME/.local/bin\n",
            "eval \"$(boom-sshh agent)\"\n",
            "trap 'boom-sshend \"$(history 1)\"' DEBUG\n",
            "if [ -n \"${BASH_VERSINFO:-}\" ]; then PS0='$(boom-sshend \"$(history 1)\")'\"${PS0:-}\"; fi\n",
            "PS0='$(boom-sshend \"$(history 1)\" >/dev/null 2>&1)'\"${PS0:-}\"\n",
            "alias ll='ls -l'\n",
        );
        let cleaned = remove_existing_traps(rc, "bash");
        assert_eq!(cleaned, "export PATH=$PATH:$HOME/.local/bin\nalias ll='ls -l'\n");

        // Injecting the current block and cleaning again must return the same
        // file (init-agent removes the old block before appending the new one).
        let injected = format!("{cleaned}{}", build_trap_block(Hook::BashPs0, &[]));
        assert_eq!(
            injected.lines().filter(|l| l.contains("boom-sshend")).count(),
            1,
            "one hook line per file:\n{injected}"
        );
        assert_eq!(
            remove_existing_traps(&injected, "bash"),
            cleaned,
            "re-injection should be idempotent"
        );
    }

    #[test]
    fn test_remove_existing_traps_fish_function() {
        let rc = "eval (boom-sshh agent)\nfunction __boomssh_preexec --on-event fish_preexec\n    if test -n \"$argv[1]\"\n        boom-sshend \"$argv[1]\"\n    end\nend\n";
        assert_eq!(remove_existing_traps(rc, "fish"), "");

        // Same idempotency property as bash: re-injecting leaves nothing behind.
        let injected = build_trap_block(Hook::Fish, &[]);
        assert_eq!(
            injected.lines().filter(|l| l.contains("boom-sshend")).count(),
            1,
            "one hook line per file:\n{injected}"
        );
        assert_eq!(remove_existing_traps(&injected, "fish"), "");
    }
}
