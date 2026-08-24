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

/// Build the shell snippet that sends each command via `boom-sshend`.
/// `with_agent_startup` adds a guard that starts boom-sshh if not already running.
fn build_trap_block(shell: &str, with_agent_startup: bool) -> String {
    let mut block = String::new();

    // Agent startup guard — start boom-sshh if no valid agent is running
    if with_agent_startup {
        match shell {
            "fish" => {
                block.push_str("if not test -S \"$SSH_AUTH_SOCK\" 2>/dev/null\n");
                block.push_str("    or not kill -0 $SSH_AGENT_PID 2>/dev/null\n");
                block.push_str("    eval (boom-sshh agent)\n");
                block.push_str("end\n");
            }
            "zsh" => {
                block.push_str("if ! test -S \"${SSH_AUTH_SOCK:-/dev/null}\" 2>/dev/null || \\\n");
                block.push_str("   ! kill -0 \"${SSH_AGENT_PID:-0}\" 2>/dev/null; then\n");
                block.push_str("    eval \"$(boom-sshh agent)\"\n");
                block.push_str("fi\n");
            }
            _ => {
                block.push_str("if ! test -S \"${SSH_AUTH_SOCK:-/dev/null}\" 2>/dev/null || \\\n");
                block.push_str("   ! kill -0 \"${SSH_AGENT_PID:-0}\" 2>/dev/null; then\n");
                block.push_str("    eval \"$(boom-sshh agent)\"\n");
                block.push_str("fi\n");
            }
        }
    }

    // Trap block — send commands to the agent
    match shell {
        "fish" => block.push_str(
            "function __boomssh_preexec --on-event fish_preexec\n    if test -n \"$argv[1]\"\n        boom-sshend $HOSTNAME $UID %self \"$argv[1]\"\n    end\nend\n",
        ),
        "zsh" => block.push_str(
            "__boomssh_trap() {\n    local _line\n    _line=$(fc -l -1)\n    [[ -n \"$_line\" ]] && boom-sshend \"$HOSTNAME\" \"$UID\" \"$$\" \"$_line\"\n}\nTRAPDEBUG=__boomssh_trap\n",
        ),
        _ => block.push_str(
            "__boomssh_trap() {\n    local _line\n    _line=$(history 1)\n    [[ -n \"$_line\" ]] && boom-sshend \"$HOSTNAME\" \"$UID\" \"$$\" \"$_line\"\n}\ntrap __boomssh_trap DEBUG\n",
        ),
    }
    block
}

/// Remove all existing boom-ssh trap blocks, keychain eval lines, and agent startup guards.
/// This ensures deduplication — only the new block will be present after cleanup.
fn remove_existing_traps(contents: &str, shell: &str) -> String {
    let mut result = String::new();
    let mut skip = false;
    let mut skip_blank_after = false;

    for line in contents.lines() {
        // Detect start of trap block
        if !skip && (line.contains("__boomssh_trap()") || line.contains("function __boomssh_preexec")) {
            skip = true;
            continue;
        }

        // Detect start of agent startup guard (old keychain or new direct startup)
        if !skip && (line.contains("keychain") && line.contains("boom-sshh")) {
            skip = true;
            continue;
        }
        if !skip && line.contains("boom-sshh agent") && (line.contains("eval") || line.contains("test -S")) {
            skip = true;
            continue;
        }

        if skip {
            // Detect end of trap block
            let at_end = line.contains("trap __boomssh_trap DEBUG")
                || line.contains("TRAPDEBUG=__boomssh_trap")
                || (shell == "fish" && line.trim() == "end");
            // Detect end of agent startup guard (fi or end)
            let at_guard_end = line.trim() == "fi" || (shell == "fish" && line.trim() == "end");
            if at_end || at_guard_end {
                skip = false;
                skip_blank_after = true;
                continue;
            }
            continue;
        }

        // Skip blank lines immediately after a removed block
        if skip_blank_after && line.trim().is_empty() {
            continue;
        }
        skip_blank_after = false;

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

    println!("detecting remote {host}...");
    let info = detect_remote(&ssh_args, host)?;

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
        configs.push(("~/.bashrc", build_trap_block("bash", false)));
    }
    if info.zshrc {
        configs.push(("~/.zshrc", build_trap_block("zsh", false)));
    }
    if info.fish_config {
        configs.push((
            "~/.config/fish/conf.d/boom-sshh.fish",
            build_trap_block("fish", false),
        ));
    }

    if configs.is_empty() {
        eprintln!("error: no supported shell config found on remote");
        eprintln!("checked: ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish");
        std::process::exit(1);
    }

    if info.client_installed {
        println!("boom-sshend: already installed");
    } else {
        println!("boom-sshend: not installed");
    }

    for (path, _) in &configs {
        println!("{path}: will inject trap");
    }

    if dry_run {
        println!();
        println!("(dry run — no changes made)");
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
    let mut scp_args: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < ssh_args.len() {
        if ssh_args[i] == "-p" && i + 1 < ssh_args.len() {
            scp_args.push("-P");
            scp_args.push(ssh_args[i + 1]);
            i += 2;
        } else {
            scp_args.push(ssh_args[i]);
            i += 1;
        }
    }
    scp_args.extend(["-O", "-q", client_path.to_str().unwrap()]);
    scp_args.push(&remote_path);

    // First ensure directory exists
    let mut mkdir_args: Vec<&str> = Vec::new();
    mkdir_args.extend(ssh_args.iter());
    mkdir_args.extend(["-q", host, "--", "mkdir", "-p", "~/.local/bin"]);

    let status = Command::new("ssh").args(&mkdir_args).status()?;
    if !status.success() {
        eprintln!("error: failed to create ~/.local/bin on remote");
        std::process::exit(1);
    }

    let status = Command::new("scp").args(&scp_args).status()?;
    if !status.success() {
        eprintln!("error: failed to copy boom-sshend to remote");
        std::process::exit(1);
    }

    // Make executable
    let mut chmod_args: Vec<&str> = Vec::new();
    chmod_args.extend(ssh_args.iter());
    chmod_args.extend(["-q", host, "--", "chmod", "+x", "~/.local/bin/boom-sshend"]);

    let status = Command::new("ssh").args(&chmod_args).status()?;
    if !status.success() {
        eprintln!("error: failed to chmod boom-sshend on remote");
        std::process::exit(1);
    }

    println!("boom-sshend installed to ~/.local/bin/boom-sshend");

    // Inject trap blocks
    for (path, block) in &configs {
        println!("injecting trap into {path}...");

        // Check if already configured
        let check_cmd = format!("grep -q '{CONFIG_SENTINEL}' {path} 2>/dev/null");
        let already_configured = ssh_exec(ssh_args, host, &check_cmd).is_ok();

        if already_configured {
            println!("  {path}: already configured — skipping");
            continue;
        }

        // Append block via heredoc
        let append_cmd = format!(
            "cat >> {path} << 'HISTEOF'\n{block}\nHISTEOF"
        );
        let mut append_args: Vec<&str> = Vec::new();
        append_args.extend(ssh_args.iter());
        append_args.extend(["-t", host, "--", "bash", "-c", &append_cmd]);

        let status = Command::new("ssh").args(&append_args).status()?;
        if !status.success() {
            eprintln!("error: failed to inject trap into {path}");
            std::process::exit(1);
        }

        println!("  {path}: done");
    }

    // Cleanup
    let _ = fs::remove_dir_all(&tmp_dir);

    println!();
    println!("init complete! Restart your shell or run: source ~/.bashrc");
    Ok(())
}

// ── init-agent (local) ────────────────────────────────────────

pub fn run_init_agent(dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    let agent_running = check_boom_sshh_running() || check_ssh_auth_sock_valid();

    if agent_running {
        warnings.push("replacing existing agent with direct startup".into());
    }
    if check_ssh_agent_running() {
        warnings.push("ssh-agent is already running — will be replaced".into());
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

    // ── Detect GUI helper — always required for init-agent ──
    println!();
    let ui_desc = match crate::approval::detect_gui_helper() {
        Some(desc) => desc,
        None => {
            eprintln!("error: no GUI helper found (zenity, kdialog, or osascript)");
            eprintln!("       install one of these to use boom-sshh's setup dialogs");
            eprintln!("       for manual install without GUI, see: boom-sshh help");
            std::process::exit(1);
        }
    };

    if dry_run {
        println!("approval UI: {ui_desc} (would confirm with user)");
        println!("agent:       will install + add trap with startup guard");
        println!();
        println!("(dry run — no changes made)");
        return Ok(());
    }

    println!("approval UI: {ui_desc}");

    if !crate::approval::confirm_setup_gui() {
        println!("setup cancelled");
        return Ok(());
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
    let block = build_trap_block(shell_name, true);
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

    fs::write(&dest, bytes)?;
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))?;
    println!("  boom-sshend    {dest:?}");
    Ok(install_dir)
}

fn preferred_install_dir() -> PathBuf {
    if fs::write("/usr/local/bin/.boom-sshh-write-test", b"").is_ok() {
        let _ = fs::remove_file("/usr/local/bin/.boom-sshh-write-test");
        PathBuf::from("/usr/local/bin")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/bin")
    }
}

/// Copy the current boom-sshh binary to the install directory if not already there.
fn install_agent_binary(install_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let dest = install_dir.join("boom-sshh");

    // Check if already in the right place
    if let Ok(current) = std::env::current_exe() {
        if current == dest {
            println!("  boom-sshh      {dest:?} (up to date)");
            return Ok(());
        }
        // Copy current binary to install dir
        fs::copy(&current, &dest)?;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))?;
        println!("  boom-sshh      {dest:?}");
    }

    Ok(())
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
) -> Result<RemoteInfo, Box<dyn std::error::Error>> {
    let arch = ssh_exec(ssh_args, host, "uname -m")?;
    let arch = arch.trim().to_string();

    let client_installed = ssh_exec(ssh_args, host, "which boom-sshend >/dev/null 2>&1")
        .map(|_| true)
        .unwrap_or(false);

    let bashrc = ssh_exec(ssh_args, host, "test -f ~/.bashrc && echo yes || echo no")
        .map(|s| s.trim() == "yes")
        .unwrap_or(false);

    let zshrc = ssh_exec(ssh_args, host, "test -f ~/.zshrc && echo yes || echo no")
        .map(|s| s.trim() == "yes")
        .unwrap_or(false);

    let fish_config = ssh_exec(
        ssh_args,
        host,
        "test -f ~/.config/fish/config.fish && echo yes || echo no",
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
) -> Result<String, Box<dyn std::error::Error>> {
    let mut args: Vec<&str> = Vec::new();
    args.extend(ssh_args);
    args.extend(["-q", host, "--", command]);

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

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
