mod agent;
mod approval;
mod init;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ssh_agent_lib::agent::listen;

use crate::agent::HistoryAgent;

// Embedded client binaries (built by build.rs from zig-out/)
// Each is a prebuilt boom-sshend binary for a specific architecture
const CLIENT_X86_64_LINUX: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/boom-sshend-x86_64-linux"));
const CLIENT_AARCH64_LINUX: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/boom-sshend-aarch64-linux"));
const CLIENT_X86_64_MACOS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/boom-sshend-x86_64-macos"));
const CLIENT_AARCH64_MACOS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/boom-sshend-aarch64-macos"));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some("version") | Some("--version") | Some("-V") => {
            println!("boom-sshh {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("extract-client") => extract_client(&args[2..]),
        Some("list-clients") => Ok(list_clients()),
        Some("init") => {
            if args[2..].iter().any(|a| a == "--help" || a == "-h") {
                print_init_help();
                return Ok(());
            }
            // Reject unknown long flags (single-dash args are SSH flags, pass through)
            for arg in &args[2..] {
                if arg.starts_with("--") && arg != "--dry-run" {
                    eprintln!("error: unknown flag '{arg}'");
                    eprintln!();
                    print_init_help();
                    std::process::exit(1);
                }
            }
            let rest: Vec<String> = args[2..].iter().filter(|a| a.as_str() != "--dry-run" && a.as_str() != "-d").cloned().collect();
            let dry_run = args[2..].iter().any(|a| a == "--dry-run" || a == "-d");
            init::run_init(&rest, dry_run)
        }
        Some("init-agent") => {
            if args[2..].iter().any(|a| a == "--help" || a == "-h") {
                print_init_agent_help();
                return Ok(());
            }
            // Reject unknown flags
            for arg in &args[2..] {
                if arg.starts_with('-') && arg != "--dry-run" && arg != "-d" {
                    eprintln!("error: unknown flag '{arg}'");
                    eprintln!();
                    print_init_agent_help();
                    std::process::exit(1);
                }
            }
            let dry_run = args[2..].iter().any(|a| a == "--dry-run" || a == "-d");
            init::run_init_agent(dry_run)
        }
        Some("agent") => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_agent())
        }
        Some("askpass") => match approval::run_askpass() {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("boom-sshh askpass: {e}");
                std::process::exit(1);
            }
        },
        Some("test-approval") => {
            if args[2..].iter().any(|a| a == "--help" || a == "-h") {
                println!("boom-sshh test-approval — test the approval UI");
                println!();
                println!("Usage:");
                println!("  boom-sshh test-approval              Auto-detect (TUI or GUI)");
                println!("  boom-sshh test-approval --force-tui  Force TUI panel");
                println!("  boom-sshh test-approval --force-gui  Force GUI dialog");
                return Ok(());
            }
            for arg in &args[2..] {
                if arg.starts_with('-') && arg != "--force-tui" && arg != "--force-gui" {
                    eprintln!("error: unknown flag '{arg}'");
                    eprintln!();
                    eprintln!("usage: boom-sshh test-approval [--force-tui | --force-gui]");
                    std::process::exit(1);
                }
            }
            let force_ui = if args[2..].iter().any(|a| a == "--force-tui") {
                Some("tui")
            } else if args[2..].iter().any(|a| a == "--force-gui") {
                Some("gui")
            } else {
                None
            };
            match approval::run_approval_test(force_ui) {
                Ok(()) => Ok(()),
                Err(e) => {
                    eprintln!("boom-sshh test-approval: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(other) => {
            eprintln!("error: unknown subcommand '{other}'");
            eprintln!();
            print_help();
            std::process::exit(1);
        }
        None => {
            eprintln!("error: no subcommand provided");
            eprintln!();
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!("boom-sshh — SSH agent with HISTORY extension for logging remote commands");
    println!();
    println!("Usage:");
    println!("  boom-sshh agent                              Start the agent");
    println!("  boom-sshh init <host>                        Init remote host");
    println!("  boom-sshh init --dry-run <host>              Preview remote init");
    println!("  boom-sshh init-agent                         Init local machine");
    println!("  boom-sshh init-agent --dry-run               Preview local init");
    println!("  boom-sshh test-approval                      Test approval UI");
    println!("  boom-sshh test-approval --force-tui          Force TUI panel");
    println!("  boom-sshh test-approval --force-gui          Force GUI dialog");
    println!("  boom-sshh askpass                            Prompt for approval (stdin)");
    println!("  boom-sshh list-clients                       List embedded clients");
    println!("  boom-sshh extract-client <arch> <path>       Extract client binary");
    println!("  boom-sshh help                               Show this help");
    println!("  boom-sshh version                            Show version");
    println!();
    println!("init detects remote shell (bash/zsh/fish), installs boom-sshend,");
    println!("and injects the appropriate trap into shell config files.");
    println!();
    println!("init-agent sets up the local machine: launches agent via startup guard");
    println!("and adds the history trap to your shell config.");
    println!("It also tests the approval UI to verify it works.");
    println!();
    println!("Environment variables:");
    println!("  SSH_AUTH_SOCK          Agent socket path (set automatically)");
    println!("  SSH_AGENT_PID          Agent PID (set automatically)");
    println!("  AGENT_HISTFILE         History file path (default: ~/.history_all)");
    println!("  TEST_SSH_AUTH_SOCK     Override socket path (for testing)");
    println!("  BOOM_SSHH_ASKPASS      Approver program (default: 'boom-sshh askpass').");
    println!("                          Executes the given command; exit 0 = allow.");
    println!("  BOOM_SSHH_ASKPASS_TIMEOUT  Approver timeout in seconds (default: 60).");
    println!();
    println!("Examples:");
    println!("  eval $(boom-sshh agent)");
    println!("  boom-sshh init user@remote-host");
    println!("  boom-sshh init -p 2222 user@remote-host");
    println!("  boom-sshh init --dry-run user@remote-host");
    println!("  boom-sshh init-agent");
    println!("  boom-sshh test-approval --force-gui");
}

fn print_init_help() {
    println!("boom-sshh init — init a remote host for command logging");
    println!();
    println!("Usage:");
    println!("  boom-sshh init <host>                  Init remote host");
    println!("  boom-sshh init --dry-run <host>        Preview remote init");
    println!("  boom-sshh init -p <port> <host>        Init via custom SSH port");
    println!();
    println!("Detects remote shell (bash/zsh/fish), installs boom-sshend,");
    println!("and injects the history trap into shell config files.");
    println!();
    println!("Any extra arguments are passed through to SSH (e.g. -p, -i, -l).");
}

fn print_init_agent_help() {
    println!("boom-sshh init-agent — set up the local machine for command logging");
    println!();
    println!("Usage:");
    println!("  boom-sshh init-agent                 Init local machine");
    println!("  boom-sshh init-agent --dry-run       Preview local init");
    println!();
    println!("This command:");
    println!("  1. Detects your shell and config file");
    println!("  2. Requires a GUI helper (zenity/kdialog/osascript) for confirmation");
    println!("  3. Asks for confirmation via GUI dialog");
    println!("  4. Installs boom-sshend locally");
    println!("  5. Adds agent startup and history trap to your shell config");
    println!("  6. Tests the approval UI to verify it works");
    println!();
    println!("A GUI helper is required. Install zenity, kdialog, or osascript.");
}

fn extract_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() < 2 {
        eprintln!("usage: boom-sshh extract-client <arch> <path>");
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
    let listener_agent = agent::ListeningAgent::new(agent);

    // Output ssh-agent compatible env vars
    println!("SSH_AUTH_SOCK={socket_path}; export SSH_AUTH_SOCK;");
    println!("SSH_AGENT_PID={pid}; export SSH_AGENT_PID;");
    println!("echo Agent pid {pid};");

    // Remove old socket if exists
    let _ = fs::remove_file(&socket_path);

    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    listen(listener, listener_agent).await?;

    Ok(())
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
