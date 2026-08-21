mod agent;
mod setup;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ssh_agent_lib::agent::listen;

use crate::agent::HistoryAgent;

// Embedded client binaries (built by build.rs from zig-out/)
// Each is a prebuilt boom-sshsend binary for a specific architecture
const CLIENT_X86_64_LINUX: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/boom-sshsend-x86_64-linux"));
const CLIENT_AARCH64_LINUX: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/boom-sshsend-aarch64-linux"));
const CLIENT_X86_64_MACOS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/boom-sshsend-x86_64-macos"));
const CLIENT_AARCH64_MACOS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/boom-sshsend-aarch64-macos"));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some("--version") | Some("-V") => {
            println!("boom-sshh {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--extract-client") => extract_client(&args[2..]),
        Some("--list-clients") => Ok(list_clients()),
        Some("--setup") => setup::run_setup(&args[2..], false),
        Some("--dry-run") | Some("-d") => {
            let rest: Vec<String> = args[2..].iter().filter(|a| !a.starts_with('-')).cloned().collect();
            setup::run_setup(&rest, true)
        }
        Some(other) => {
            eprintln!("error: unknown argument '{other}'");
            eprintln!();
            print_help();
            std::process::exit(1);
        }
        None => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_agent())
        }
    }
}

fn print_help() {
    println!("boom-sshh — SSH agent with HISTORY extension for logging remote commands");
    println!();
    println!("Usage:");
    println!("  boom-sshh                                     Start the agent");
    println!("  boom-sshh --setup <host>                      Setup remote host");
    println!("  boom-sshh --setup --dry-run <host>            Preview setup (no changes)");
    println!("  boom-sshh --help                              Show this help");
    println!("  boom-sshh --version                           Show version");
    println!("  boom-sshh --list-clients                      List embedded clients");
    println!("  boom-sshh --extract-client <arch> <path>      Extract client binary");
    println!();
    println!("Setup detects remote shell (bash/zsh/fish), installs boom-sshsend,");
    println!("and injects the appropriate trap into shell config files.");
    println!();
    println!("Environment variables:");
    println!("  SSH_AUTH_SOCK          Agent socket path (set automatically)");
    println!("  SSH_AGENT_PID          Agent PID (set automatically)");
    println!("  AGENT_HISTFILE         History file path (default: ~/.history_all)");
    println!("  TEST_SSH_AUTH_SOCK     Override socket path (for testing)");
    println!();
    println!("Examples:");
    println!("  eval $(boom-sshh)");
    println!("  boom-sshh --setup user@remote-host");
    println!("  boom-sshh --setup -p 2222 user@remote-host");
    println!("  boom-sshh --setup --dry-run user@remote-host");
}

fn extract_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() < 2 {
        eprintln!("usage: boom-sshh --extract-client <arch> <path>");
        eprintln!();
        eprintln!("Available architectures:");
        list_clients();
        std::process::exit(1);
    }

    let arch = &args[0];
    let path = &args[1];

    let client_bytes = match arch.as_str() {
        "x86_64-linux" => CLIENT_X86_64_LINUX,
        "aarch64-linux" => CLIENT_AARCH64_LINUX,
        "x86_64-macos" => CLIENT_X86_64_MACOS,
        "aarch64-macos" => CLIENT_AARCH64_MACOS,
        _ => {
            eprintln!("unknown architecture: {arch}");
            eprintln!("available: x86_64-linux, aarch64-linux, x86_64-macos, aarch64-macos");
            std::process::exit(1);
        }
    };

    if client_bytes.is_empty() {
        eprintln!("client not embedded for architecture: {arch}");
        eprintln!("build with: PREBUILT_CLIENTS_DIR=zig-out cargo build --release");
        std::process::exit(1);
    }

    // Ensure parent directory exists
    if let Some(parent) = PathBuf::from(path).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut f = fs::File::create(path)?;
    f.write_all(client_bytes)?;
    f.sync_all()?;

    // Make executable
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;

    println!("extracted {arch} client to {path} ({} bytes)", client_bytes.len());
    Ok(())
}

fn list_clients() {
    let clients = [
        ("x86_64-linux", CLIENT_X86_64_LINUX),
        ("aarch64-linux", CLIENT_AARCH64_LINUX),
        ("x86_64-macos", CLIENT_X86_64_MACOS),
        ("aarch64-macos", CLIENT_AARCH64_MACOS),
    ];

    for (arch, data) in &clients {
        if data.is_empty() {
            println!("  {arch:20} (not embedded)");
        } else {
            println!("  {arch:20} ({} bytes)", data.len());
        }
    }
}

async fn run_agent() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let pid = std::process::id();

    // Determine socket path
    let socket_path = if let Ok(test_sock) = std::env::var("TEST_SSH_AUTH_SOCK") {
        let _ = fs::remove_file(&test_sock);
        test_sock
    } else {
        let tmp_dir = std::env::temp_dir().join(format!("boom-sshh-{pid}"));
        fs::create_dir_all(&tmp_dir)?;
        tmp_dir.join(format!("agent.{pid}")).to_str().unwrap().to_string()
    };

    // Determine history file path
    let hist_path = std::env::var("AGENT_HISTFILE").unwrap_or_else(|_| {
        dirs_or_default().join(".history_all").to_str().unwrap().to_string()
    });

    // Open history file
    let histfile = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&hist_path)?;

    // Set socket permissions
    let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600));

    let agent = HistoryAgent::new(histfile);

    // Output ssh-agent compatible env vars
    println!("SSH_AUTH_SOCK={socket_path}; export SSH_AUTH_SOCK;");
    println!("SSH_AGENT_PID={pid}; export SSH_AGENT_PID;");
    println!("echo Agent pid {pid};");

    // Remove old socket if exists
    let _ = fs::remove_file(&socket_path);

    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    listen(listener, agent).await?;

    Ok(())
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
