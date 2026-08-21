use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct RemoteInfo {
    arch: String,
    client_installed: bool,
    bashrc: bool,
    zshrc: bool,
    fish_config: bool,
}

const BASH_BLOCK: &str = r#"# boom-sshh begin
__ha_history_trap() {
    local _line
    _line=$(history 1)
    [[ -n "$_line" ]] && boom-sshsend "$HOSTNAME" "$UID" "$$" "$_line"
}
trap __ha_history_trap DEBUG
# boom-sshh end"#;

const ZSH_BLOCK: &str = r#"# boom-sshh begin
__ha_history_trap() {
    local _line
    _line=$(fc -l -1)
    [[ -n "$_line" ]] && boom-sshsend "$HOSTNAME" "$UID" "$$" "$_line"
}
TRAPDEBUG=__ha_history_trap
# boom-sshh end"#;

const FISH_BLOCK: &str = r#"# boom-sshh begin
function __ha_history_preexec --on-event fish_preexec
    if test -n "$argv[1]"
        boom-sshsend $HOSTNAME $UID %self "$argv[1]"
    end
end
# boom-sshh end"#;

// ── --init (remote) ─────────────────────────────────────────────

pub fn run_init(args: &[String], dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("usage: boom-sshh --init [--dry-run] <ssh-args...> <host>");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  boom-sshh --init user@remote-host");
        eprintln!("  boom-sshh --init -p 2222 user@remote-host");
        eprintln!("  boom-sshh --init --dry-run user@remote-host");
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
    let mut configs: Vec<(&str, &str)> = Vec::new();
    if info.bashrc {
        configs.push(("~/.bashrc", BASH_BLOCK));
    }
    if info.zshrc {
        configs.push(("~/.zshrc", ZSH_BLOCK));
    }
    if info.fish_config {
        configs.push(("~/.config/fish/conf.d/boom-sshh.fish", FISH_BLOCK));
    }

    if configs.is_empty() {
        eprintln!("error: no supported shell config found on remote");
        eprintln!("checked: ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish");
        std::process::exit(1);
    }

    if info.client_installed {
        println!("boom-sshsend: already installed");
    } else {
        println!("boom-sshsend: not installed");
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
    let client_path = tmp_dir.join("boom-sshsend");

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
    println!("installing boom-sshsend...");

    // SCP to remote — convert -p PORT to -P PORT for scp
    let remote_path = format!("{host}:~/.local/bin/boom-sshsend");
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
        eprintln!("error: failed to copy boom-sshsend to remote");
        std::process::exit(1);
    }

    // Make executable
    let mut chmod_args: Vec<&str> = Vec::new();
    chmod_args.extend(ssh_args.iter());
    chmod_args.extend(["-q", host, "--", "chmod", "+x", "~/.local/bin/boom-sshsend"]);

    let status = Command::new("ssh").args(&chmod_args).status()?;
    if !status.success() {
        eprintln!("error: failed to chmod boom-sshsend on remote");
        std::process::exit(1);
    }

    println!("boom-sshsend installed to ~/.local/bin/boom-sshsend");

    // Inject trap blocks
    for (path, block) in &configs {
        println!("injecting trap into {path}...");

        // Check if already configured
        let check_cmd = format!("grep -q 'boom-sshh begin' {path} 2>/dev/null");
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

// ── --init-agent (local) ────────────────────────────────────────

pub fn run_init_agent(dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Detect local shell
    let shell = detect_local_shell();
    let shell_name = shell.rsplit('/').next().unwrap_or(&shell);

    println!("shell: {shell_name}");

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

    // Check if already configured
    if config_path.exists() {
        let contents = fs::read_to_string(&config_path).unwrap_or_default();
        if contents.contains("boom-sshh begin") {
            let display = config_path.to_str().unwrap_or("?");
            println!("{display}: already configured — skipping");
            return Ok(());
        }
    }

    // Pre-flight checks
    if check_keychain_running() {
        eprintln!("error: keychain is already managing an agent");
        eprintln!("edit your shell config manually to switch to boom-sshh");
        std::process::exit(1);
    }

    if check_ssh_agent_running() {
        eprintln!("error: ssh-agent is already running");
        eprintln!("kill it first or edit your shell config manually");
        std::process::exit(1);
    }

    // Determine what to install
    let agent_running = check_boom_sshh_running() || check_ssh_auth_sock_valid();
    let config_display = config_path.to_str().unwrap_or("?");

    if agent_running {
        println!("boom-sshh already running");
        println!("{config_display}: will add trap only");
    } else {
        println!("{config_display}: will add agent launch + trap");
    }

    if dry_run {
        println!();
        println!("(dry run — no changes made)");
        return Ok(());
    }

    // Build the block to inject
    let block = match shell_name {
        "bash" | "zsh" => build_local_bash_block(),
        "fish" => build_local_fish_block(),
        _ => unreachable!(),
    };

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Append block
    let mut contents = fs::read_to_string(&config_path).unwrap_or_default();
    if !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&block);
    contents.push('\n');
    fs::write(&config_path, &contents)?;

    println!("{config_display}: done");

    println!();
    println!("init-agent complete! Restart your shell or run: source {config_display}");
    Ok(())
}

fn build_local_bash_block() -> String {
    let mut block = String::from("# boom-sshh begin\n");

    // Only add keychain launch if agent isn't already running
    if !check_boom_sshh_running() && !check_ssh_auth_sock_valid() {
        block.push_str("eval $(keychain --eval --agents ssh boom-sshh)\n");
    }

    block.push_str(
        r#"
__ha_history_trap() {
    local _line
    _line=$(history 1)
    [[ -n "$_line" ]] && boom-sshsend "$HOSTNAME" "$UID" "$$" "$_line"
}
trap __ha_history_trap DEBUG
"#,
    );
    block.push_str("# boom-sshh end\n");
    block
}

fn build_local_fish_block() -> String {
    let mut block = String::from("# boom-sshh begin\n");

    if !check_boom_sshh_running() && !check_ssh_auth_sock_valid() {
        block.push_str("eval (keychain --eval --agents ssh boom-sshh | source)\n");
    }

    block.push_str(
        r#"
function __ha_history_preexec --on-event fish_preexec
    if test -n "$argv[1]"
        boom-sshsend $HOSTNAME $UID %self "$argv[1]"
    end
end
"#,
    );
    block.push_str("# boom-sshh end\n");
    block
}

// ── pre-flight checks ───────────────────────────────────────────

fn check_keychain_running() -> bool {
    // Check if keychain is managing any agent
    Command::new("keychain")
        .args(["--list"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn check_ssh_agent_running() -> bool {
    Command::new("pgrep")
        .args(["-x", "ssh-agent"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn check_boom_sshh_running() -> bool {
    Command::new("pgrep")
        .args(["-x", "boom-sshh"])
        .output()
        .map(|o| o.status.success())
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

    let client_installed = ssh_exec(ssh_args, host, "which boom-sshsend >/dev/null 2>&1")
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
