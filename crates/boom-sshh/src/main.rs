mod agent;
mod approval;
mod init;

use crate::agent::{policy_snapshot_path, ApprovedRule};
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
        Some("agent") => run_agent_daemon(),
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
        Some("policy") => run_policy(&args[2..]),
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
    println!("  boom-sshh policy list                        Show remembered accepts");
    println!("  boom-sshh policy clear                       Forget remembered accepts");
    println!("  boom-sshh askpass                            Prompt for approval (stdin)");
    println!("  boom-sshh list-clients                       List embedded clients");
    println!("  boom-sshh extract-client <arch> <path>       Extract client binary");
    println!("  boom-sshh help                               Show this help");
    println!("  boom-sshh version                            Show version");
    println!();
    println!("init detects remote shell (bash/zsh/fish), installs boom-sshend,");
    println!("and injects the appropriate trap into shell config files.");
    println!();
    println!("init-agent sets up the local machine: installs agent + client,");
    println!("starts agent, and adds the history trap to your shell config.");
    println!();
    println!("Environment variables:");
    println!("  SSH_AUTH_SOCK          Agent socket path (set automatically)");
    println!("  SSH_AGENT_PID          Agent PID (set automatically)");
    println!("  AGENT_HISTFILE         History file path (default: ~/.history_all)");
    println!("  AGENT_AUTHLOG          Auth log path (default: ~/.boom-sshh/auth.log)");
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

/// `boom-sshh policy list|clear` — inspect and forget remembered accepts.
///
/// Only user-accepted rules are ever remembered (denies are never stored), so
/// `clear` simply tells the running agent (via SIGUSR1) to drop them.
fn run_policy(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "list" => {
            let path = policy_snapshot_path();
            let rules: Vec<ApprovedRule> = match std::fs::read_to_string(&path) {
                Ok(s) if !s.trim().is_empty() => {
                    serde_json::from_str(&s).unwrap_or_default()
                }
                _ => Vec::new(),
            };
            if rules.is_empty() {
                println!("no remembered accepts (everything will prompt).");
                return Ok(());
            }
            println!("remembered accepts:");
            for r in &rules {
                let exp = r
                    .expires_in_secs
                    .map(|s| format!("{s}s"))
                    .unwrap_or_else(|| "session".to_string());
                println!(
                    "  {}  op={:<10} host={:<10} key={}  expires={}",
                    r.id, r.op, r.host, r.key_fp, exp
                );
            }
            println!();
            println!("(run `boom-sshh policy clear` to forget all of these)");
        }
        "clear" => {
            // Signal every running agent (there may be several — one per shell
            // session) to drop its user-remembered accepts, then truncate the
            // on-disk snapshot so `policy list` is consistent immediately.
            let out = std::process::Command::new("pgrep")
                .args(["-x", "boom-sshh"])
                .output();
            let self_pid = std::process::id();
            if let Ok(o) = out {
                for line in String::from_utf8_lossy(&o.stdout).lines() {
                    if let Ok(pid) = line.trim().parse::<u32>() {
                        if pid == self_pid {
                            continue;
                        }
                        let _ = std::process::Command::new("kill").args(["-USR1", &pid.to_string()]).status();
                    }
                }
            }
            let _ = std::fs::write(policy_snapshot_path(), "[]");
            println!("cleared remembered accepts (built-in defaults remain).");
        }
        "--help" | "-h" | "" => {
            println!("boom-sshh policy — inspect/forget remembered accepts");
            println!();
            println!("Usage:");
            println!("  boom-sshh policy list     Show remembered accepts");
            println!("  boom-sshh policy clear    Forget all remembered accepts");
            println!();
            println!("Denies are never stored. Accepts are remembered until they expire");
            println!("or until you clear them. Built-in defaults (git commit/tag) remain.");
        }
        other => {
            eprintln!("error: unknown policy command '{other}'");
            eprintln!("usage: boom-sshh policy [list|clear]");
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Daemonize the agent: fork, parent exits, child runs the listener.
fn run_agent_daemon() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Singleton discovery: ensure multiple shells share ONE agent instead of
    // each spawning their own. We first honour any inherited SSH_AUTH_SOCK/
    // SSH_AGENT_PID (the common case when a shell is a child of one that already
    // started the agent), then fall back to a stable socket + pid file under
    // ~/.boom-sshh so a fresh terminal can still find and reuse the agent even
    // when those env vars weren't inherited.
    let agent_dir = dirs_or_default().join(".boom-sshh");
    let _ = fs::create_dir_all(&agent_dir);
    let fixed_sock = agent_dir.join("agent.sock");
    let pid_path = agent_dir.join("agent.pid");

    // Fast path: inherited env vars point at a live agent.
    if let (Ok(sock), Ok(pid_str)) = (
        std::env::var("SSH_AUTH_SOCK"),
        std::env::var("SSH_AGENT_PID"),
    ) {
        if let Ok(pid) = pid_str.parse::<u32>() {
            if std::path::Path::new(&sock).exists() && unsafe { libc::kill(pid as i32, 0) } == 0 {
                println!("SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;");
                println!("SSH_AGENT_PID={pid}; export SSH_AGENT_PID;");
                println!("echo Agent pid {pid};");
                return Ok(());
            }
        }
    }

    // Singleton path: reuse the fixed socket if its recorded pid is alive.
    if let Ok(pid_s) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_s.trim().parse::<u32>() {
            if fixed_sock.exists() && unsafe { libc::kill(pid as i32, 0) } == 0 {
                let sock = fixed_sock.to_string_lossy().into_owned();
                println!("SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;");
                println!("SSH_AGENT_PID={pid}; export SSH_AGENT_PID;");
                println!("echo Agent pid {pid};");
                return Ok(());
            }
        }
    }
    // Stale socket/pid file from a dead agent — clean up before binding.
    let _ = fs::remove_file(&fixed_sock);
    let _ = fs::remove_file(&pid_path);

    // Determine socket path (fixed singleton location, or TEST_SSH_AUTH_SOCK).
    let socket_path = if let Ok(test_sock) = std::env::var("TEST_SSH_AUTH_SOCK") {
        let _ = fs::remove_file(&test_sock);
        test_sock
    } else {
        fixed_sock.to_string_lossy().into_owned()
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

    // Open the separate auth log (~/.boom-sshh/auth.log unless AGENT_AUTHLOG set).
    let auth_dir = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join(".boom-sshh");
    let _ = std::fs::create_dir_all(&auth_dir);
    let auth_path = std::env::var("AGENT_AUTHLOG")
        .unwrap_or_else(|_| auth_dir.join("auth.log").to_string_lossy().into_owned());
    let authfile = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&auth_path)?;

    // Remove old socket if exists
    let _ = fs::remove_file(&socket_path);

    // Bind socket synchronously before fork
    let std_listener = std::os::unix::net::UnixListener::bind(&socket_path)?;

    // Set socket permissions
    let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600));

    // Fork — parent prints env vars and exits, child daemonizes
    let child_pid = unsafe { libc::fork() };
    if child_pid > 0 {
        // Parent: print env vars and exit
        println!("SSH_AUTH_SOCK={socket_path}; export SSH_AUTH_SOCK;");
        println!("SSH_AGENT_PID={child_pid}; export SSH_AGENT_PID;");
        println!("echo Agent pid {child_pid};");
        std::process::exit(0);
    }

    // Child: detach from terminal
    unsafe {
        libc::setsid();
        libc::close(libc::STDIN_FILENO);
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
    }
    // Record our pid so future shells can discover and reuse this singleton.
    // (fork() returns 0 in the child, so use the real pid here.)
    let _ = fs::write(&pid_path, std::process::id().to_string());

    // Create fresh tokio runtime in child
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_agent_listener(std_listener, histfile, authfile))?;

    Ok(())
}

async fn run_agent_listener(
    std_listener: std::os::unix::net::UnixListener,
    histfile: std::fs::File,
    authfile: std::fs::File,
) -> Result<(), Box<dyn std::error::Error>> {
    std_listener.set_nonblocking(true)?;
    let tokio_listener = tokio::net::UnixListener::from_std(std_listener)?;

    let mut agent = HistoryAgent::new(histfile);
    agent.set_authfile(authfile);

    // `boom-sshh policy clear` sends SIGUSR1: drop all user-remembered accepts
    // (built-in defaults stay), then rewrite the snapshot. Denies are never
    // stored, so there is nothing to clear for them.
    let policy_arc = agent.policy.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = match signal(SignalKind::from_raw(libc::SIGUSR1 as i32)) {
            Ok(s) => s,
            Err(_) => return,
        };
        loop {
            sig.recv().await;
            policy_arc.lock().unwrap().retain(|r| r.builtin);
            agent::write_policy_snapshot(&policy_arc);
        }
    });

    let listener_agent = agent::ListeningAgent::new(agent);

    listen(tokio_listener, listener_agent).await?;

    Ok(())
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
