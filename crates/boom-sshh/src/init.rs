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
}

/// Build the shell snippet that starts the agent and sends each command via `boom-sshend`.
/// boom-sshend auto-detects hostname, uid, pid — trap only passes the command.
/// Deduplication is handled by the agent (not the shell).
fn build_trap_block(shell: &str) -> String {
    let mut block = String::new();

    // Agent startup — reuse existing or start new (agent handles detection)
    match shell {
        "fish" => block.push_str("eval (boom-sshh agent)\n"),
        _ => block.push_str("eval \"$(boom-sshh agent)\"\n"),
    }

    // Trap block — send commands to the agent
    match shell {
        "fish" => block.push_str(
            "function __boomssh_preexec --on-event fish_preexec\n    if test -n \"$argv[1]\"\n        boom-sshend \"$argv[1]\"\n    end\nend\n",
        ),
        "zsh" => block.push_str("TRAPDEBUG='boom-sshend \"$(fc -l -1)\"'\n"),
        _ => block.push_str("trap 'boom-sshend \"$(history 1)\"' DEBUG\n"),
    }
    block
}

/// Remove all existing boom-ssh lines from config contents.
/// Only needs to handle current format — no backwards compatibility.
fn remove_existing_traps(contents: &str, shell: &str) -> String {
    let mut result = String::new();

    for line in contents.lines() {
        // Skip agent startup line
        if line.contains("boom-sshh agent") && line.contains("eval") {
            continue;
        }
        // Skip trap lines
        if line.contains("boom-sshend") && (line.contains("trap") || line.contains("TRAPDEBUG")) {
            continue;
        }
        // Skip fish function
        if line.contains("function __boomssh_preexec") {
            continue;
        }
        // Skip fish end (only if it's the end of the preexec function)
        if shell == "fish" && line.trim() == "end" && result.contains("__boomssh_preexec") {
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

    // Determine which config files to inject into
    let mut configs: Vec<(&str, String)> = Vec::new();
    if info.bashrc {
        configs.push(("~/.bashrc", build_trap_block("bash")));
    }
    if info.zshrc {
        configs.push(("~/.zshrc", build_trap_block("zsh")));
    }
    if info.fish_config {
        configs.push((
            "~/.config/fish/conf.d/boom-sshh.fish",
            build_trap_block("fish"),
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

    for (path, _) in &configs {
        let already = std::fs::read_to_string(path)
            .map(|c| c.contains(CONFIG_SENTINEL))
            .unwrap_or(false);
        if dry_run {
            println!("{path}: would {}", if already { "update trap" } else { "inject trap" });
        } else {
            println!("{path}: {}", if already { "already configured" } else { "will inject trap" });
        }
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

    // Inject trap blocks
    for (path, block) in &configs {
        println!("injecting trap into {path}...");

        // Check if already configured
        let check_cmd = format!("grep -q '{CONFIG_SENTINEL}' {path} 2>/dev/null");
        let already_configured = ssh_exec(ssh_args, host, &check_cmd, &control_path).is_ok();

        if already_configured {
            println!("  {path}: already configured — skipping");
            continue;
        }

        // Append block via heredoc
        let append_cmd = format!(
            "cat >> {path} << 'HISTEOF'\n{block}\nHISTEOF"
        );
        let mut append_args: Vec<String> = ssh_args.iter().map(|s| s.to_string()).collect();
        append_args.extend(mux_opts(&control_path));
        append_args.extend([
            "-t".to_string(),
            host.to_string(),
            "--".to_string(),
            "bash".to_string(),
            "-c".to_string(),
            append_cmd,
        ]);

        let status = Command::new("ssh").args(&append_args).status()?;
        if !status.success() {
            eprintln!("error: failed to inject trap into {path}");
            eprintln!("       (check that your key is loaded in the agent: ssh-add -l)");
            close_mux(&control_path, ssh_args, host);
            std::process::exit(1);
        }

        println!("  {path}: done");
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

    // ── Detect shell and config ──
    println!("shell:    {shell_name}");
    println!("config:   {config_display}");

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

    // Build and inject the trap block
    let block = build_trap_block(shell_name);
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Remove existing trap blocks before appending new one
    let raw = fs::read_to_string(&config_path).unwrap_or_default();
    let cleaned = remove_existing_traps(&raw, shell_name);
    let mut contents = cleaned;
    if !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&block);
    contents.push('\n');
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

// ── remote detection ────────────────────────────────────────────

fn detect_remote(
    ssh_args: &[&str],
    host: &str,
    control_path: &str,
) -> Result<RemoteInfo, Box<dyn std::error::Error>> {
    let arch = ssh_exec(ssh_args, host, "uname -m", control_path)?;
    let arch = arch.trim().to_string();

    let client_installed = ssh_exec(ssh_args, host, "which boom-sshend >/dev/null 2>&1", control_path)
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

    Ok(RemoteInfo {
        arch,
        client_installed,
        bashrc,
        zshrc,
        fish_config,
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
    fn test_preferred_install_dir_reuses_exes_bin() {
        // If the running exe lives in a */bin dir, reinstalls stay in place.
        let exe = std::env::current_exe().unwrap();
        if let Some(parent) = exe.parent() {
            if parent.file_name().map_or(false, |n| n == "bin") {
                assert_eq!(preferred_install_dir(), parent, "should reuse the exe's bin dir");
            }
        }
    }
}
