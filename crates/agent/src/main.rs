mod agent;

use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ssh_agent_lib::agent::listen;

use crate::agent::HistoryAgent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let pid = std::process::id();

    // Determine socket path
    let socket_path = if let Ok(test_sock) = std::env::var("TEST_SSH_AUTH_SOCK") {
        let _ = fs::remove_file(&test_sock);
        test_sock
    } else {
        let tmp_dir = std::env::temp_dir().join(format!("ssh-agent-history-{pid}"));
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
