//! Interactive approval via an external "askpass" program.
//!
//! The agent is a headless daemon, so approval prompts are delegated to an
//! external program configured through `BOOM_SSHH_ASKPASS`:
//!
//! * unset / empty  -> default to re-invoking `boom-sshh --askpass`, which
//!   prompts on the controlling terminal (`/dev/tty`).
//! * `true` (or `1`, `yes`) -> security-off workaround: always allow, never prompt.
//! * `<program> [args...]` -> spawn that program; it reads a JSON
//!   [`ApprovalRequest`] on stdin and must print `allow` or `deny` to stdout.
//!
//! If the approver cannot be reached (spawn failure, timeout, non-zero exit)
//! the request is denied (fail-closed). The timeout is `BOOM_SSHH_ASKPASS_TIMEOUT`
//! seconds (default 60).

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// A single approval request sent to the askpass program.
#[derive(Serialize, Deserialize, Clone)]
pub struct ApprovalRequest {
    /// One of: `"session-bind"`, `"dest-constraint"`, `"sign"`.
    pub kind: String,
    /// Unix epoch seconds when the request was raised.
    pub timestamp: u64,
    /// Human-readable facts shown to the user.
    pub summary: Vec<String>,
}

/// Ask the configured approver whether a request should be allowed.
///
/// Returns `true` to allow, `false` to deny.
pub async fn request_approval(req: &ApprovalRequest) -> bool {
    // Security-off workaround: explicit "true" always allows.
    if let Ok(v) = std::env::var("BOOM_SSHH_ASKPASS") {
        let t = v.trim();
        if t == "true" || t == "1" || t.eq_ignore_ascii_case("yes") {
            return true;
        }
    }

    let timeout = std::env::var("BOOM_SSHH_ASKPASS_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    let mut cmd = match std::env::var("BOOM_SSHH_ASKPASS") {
        Ok(p) if !p.trim().is_empty() => {
            let mut parts = p.split_whitespace();
            let mut c = Command::new(parts.next().unwrap());
            for a in parts {
                c.arg(a);
            }
            c
        }
        _ => match std::env::current_exe() {
            Ok(exe) => {
                let mut c = Command::new(exe);
                c.arg("--askpass");
                c
            }
            Err(_) => return false,
        },
    };

    let json = match serde_json::to_string(req) {
        Ok(j) => j,
        Err(_) => return false,
    };

    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return false,
    };

    {
        let mut stdin = match child.stdin.take() {
            Some(s) => s,
            None => return false,
        };
        if stdin.write_all(json.as_bytes()).await.is_err() {
            return false;
        }
        let _ = stdin.shutdown().await;
        drop(stdin);
    }

    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout),
        child.wait_with_output(),
    )
    .await
    {
        Ok(Ok(out)) if out.status.success() => {
            let line = String::from_utf8_lossy(&out.stdout);
            let first = line.split_whitespace().next().unwrap_or("");
            matches!(first, "allow" | "yes" | "y" | "true")
        }
        _ => false,
    }
}

/// Entry point for `boom-sshh --askpass`.
///
/// Reads a JSON [`ApprovalRequest`] from stdin, prompts on the controlling
/// terminal (`/dev/tty`), and prints `allow` or `deny` to stdout. When no
/// controlling terminal is available the request is denied (fail-closed).
pub fn run_askpass() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let req: ApprovalRequest = serde_json::from_str(&input)?;

    let decision = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => prompt_tty(&req, tty)?,
        Err(_) => {
            eprintln!("boom-sshh --askpass: no controlling terminal; denying request");
            false
        }
    };

    let mut out = std::io::stdout();
    writeln!(out, "{}", if decision { "allow" } else { "deny" })?;
    Ok(())
}

fn prompt_tty(req: &ApprovalRequest, mut tty: std::fs::File) -> std::io::Result<bool> {
    use std::io::{Read, Write};
    writeln!(tty, "boom-sshh approval request: {}", req.kind)?;
    for line in &req.summary {
        writeln!(tty, "  {line}")?;
    }
    write!(tty, "Allow? [y/N] ")?;
    tty.flush()?;
    let mut buf = [0u8; 1];
    let n = tty.read(&mut buf)?;
    if n == 0 {
        return Ok(false);
    }
    let c = buf[0] as char;
    Ok(c == 'y' || c == 'Y')
}
