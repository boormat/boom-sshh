use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct RemoteInfo {
    arch: String,
    histsend_installed: bool,
    bashrc: bool,
    zshrc: bool,
    fish_config: bool,
}

const BASH_BLOCK: &str = r#"# ssh-agent-history begin
__ha_history_trap() {
    local _line
    _line=$(history 1)
    [[ -n "$_line" ]] && histsend "$HOSTNAME" "$UID" "$$" "$_line"
}
trap __ha_history_trap DEBUG
# ssh-agent-history end"#;

const ZSH_BLOCK: &str = r#"# ssh-agent-history begin
__ha_history_trap() {
    local _line
    _line=$(fc -l -1)
    [[ -n "$_line" ]] && histsend "$HOSTNAME" "$UID" "$$" "$_line"
}
TRAPDEBUG=__ha_history_trap
# ssh-agent-history end"#;

const FISH_BLOCK: &str = r#"# ssh-agent-history begin
function __ha_history_preexec --on-event fish_preexec
    if test -n "$argv[1]"
        histsend $HOSTNAME $UID %self "$argv[1]"
    end
end
# ssh-agent-history end"#;

pub fn run_setup(args: &[String], dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("usage: ssh-agent-history --setup [--dry-run] <ssh-args...> <host>");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  ssh-agent-history --setup user@remote-host");
        eprintln!("  ssh-agent-history --setup -p 2222 user@remote-host");
        eprintln!("  ssh-agent-history --setup --dry-run user@remote-host");
        std::process::exit(1);
    }

    // Filter out our own flags, pass rest to SSH
    // Last argument is the host
    let filtered: Vec<&str> = args
        .iter()
        .filter(|a| *a != "--dry-run" && *a != "-d")
        .map(|s| s.as_str())
        .collect();

    let host = filtered.last().ok_or("no host specified")?;
    let ssh_args = &filtered[..filtered.len() - 1]; // everything except host

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
        configs.push(("~/.config/fish/conf.d/ssh-agent-history.fish", FISH_BLOCK));
    }

    if configs.is_empty() {
        eprintln!("error: no supported shell config found on remote");
        eprintln!("checked: ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish");
        std::process::exit(1);
    }

    // Check if histsend needs installation
    if info.histsend_installed {
        println!("histsend: already installed");
    } else {
        println!("histsend: not installed");
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
    let tmp_dir = std::env::temp_dir().join("ssh-agent-history-setup");
    fs::create_dir_all(&tmp_dir)?;
    let client_path = tmp_dir.join("histsend");

    let client_bytes = match client_arch {
        "x86_64-linux" => super::CLIENT_X86_64_LINUX,
        "aarch64-linux" => super::CLIENT_AARCH64_LINUX,
        "x86_64-macos" => super::CLIENT_X86_64_MACOS,
        "aarch64-macos" => super::CLIENT_AARCH64_MACOS,
        _ => unreachable!(),
    };

    if client_bytes.is_empty() {
        eprintln!("error: client not embedded for {client_arch}");
        eprintln!("build with: PREBUILT_CLIENTS_DIR=zig-out cargo build --release");
        std::process::exit(1);
    }

    fs::write(&client_path, client_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&client_path, fs::Permissions::from_mode(0o755))?;
    }

    println!();
    println!("installing histsend...");

    // SCP to remote — convert -p PORT to -P PORT for scp
    let remote_path = format!("{host}:~/.local/bin/histsend");
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
        eprintln!("error: failed to copy histsend to remote");
        std::process::exit(1);
    }

    // Make executable
    let mut chmod_args: Vec<&str> = Vec::new();
    chmod_args.extend(ssh_args.iter());
    chmod_args.extend(["-q", host, "--", "chmod", "+x", "~/.local/bin/histsend"]);

    let status = Command::new("ssh").args(&chmod_args).status()?;
    if !status.success() {
        eprintln!("error: failed to chmod histsend on remote");
        std::process::exit(1);
    }

    println!("histsend installed to ~/.local/bin/histsend");

    // Inject trap blocks
    for (path, block) in &configs {
        println!("injecting trap into {path}...");

        // Check if already configured
        let check_cmd = format!("grep -q 'ssh-agent-history begin' {path} 2>/dev/null");
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
    println!("setup complete! Restart your shell or run: source ~/.bashrc");
    Ok(())
}

fn detect_remote(
    ssh_args: &[&str],
    host: &str,
) -> Result<RemoteInfo, Box<dyn std::error::Error>> {
    // Detect architecture
    let arch = ssh_exec(ssh_args, host, "uname -m")?;
    let arch = arch.trim().to_string();

    // Check if histsend is installed
    let histsend_installed = ssh_exec(ssh_args, host, "which histsend >/dev/null 2>&1")
        .map(|_| true)
        .unwrap_or(false);

    // Check which config files exist
    let bashrc = ssh_exec(
        ssh_args,
        host,
        "test -f ~/.bashrc && echo yes || echo no",
    )
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
        histsend_installed,
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
