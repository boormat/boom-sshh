//! Interactive approval via an external "askpass" program.
//!
//! The agent is a headless daemon, so approval prompts are delegated to an
//! external program configured through `BOOM_SSHH_ASKPASS`:
//!
//! * unset / empty  -> default to re-invoking `boom-sshh askpass`, which
//!   prompts on the controlling terminal (`/dev/tty`).
//! * `<program> [args...]` -> spawn that program; it reads a JSON
//!   [`ApprovalRequest`] on stdin and must print `allow` or `deny` to stdout.
//!   Exit 0 = allow, non-zero = deny (unless stdout explicitly says "deny").
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
    /// Fingerprint of the key being asked about.
    pub key_fp: String,
    /// Operation class: `git-commit`, `git-tag`, `ssh-userauth`, `unknown`.
    pub op: String,
    /// Human-readable hostname (when known), e.g. from a HISTORY line.
    pub host_label: Option<String>,
    /// Destination host key fingerprint (when bound), from session-bind.
    pub host_fp: Option<String>,
    /// Recent commands on this session (display context only).
    pub recent: Vec<String>,
}

/// The outcome of an approval request.
#[derive(Clone, Copy)]
pub struct ApprovalDecision {
    pub allow: bool,
    /// How long an allow decision stays valid. `None` = until the agent exits
    /// (session-scoped); `Some(d)` = expires after `d`.
    pub ttl: Option<std::time::Duration>,
}

/// The result of asking the configured approver.
///
/// `Unreachable` means the user was never actually given a choice (no usable UI,
/// spawn failure, timeout, or non-zero exit) — callers fail closed on it. It is
/// kept distinct from an explicit `Deny` so the auth log can show *why* a request
/// was rejected, and so nothing is ever remembered as "denied".
pub enum ApprovalOutcome {
    Allow { ttl: Option<std::time::Duration> },
    Deny,
    Unreachable { reason: String },
}

/// Full result returned to the agent: the outcome plus diagnostics describing
/// how the approver was reached (used only for logging/feedback).
pub struct AskpassResult {
    pub outcome: ApprovalOutcome,
    /// UI path that would/should have been used: `tui` | `gui` | `none` | `auto`.
    pub ui: &'static str,
    /// Whether an approver process was actually spawned/contacted.
    pub reached: bool,
}

/// Ask the configured approver whether a request should be allowed.
///
/// Returns an [`AskpassResult`]: an explicit `Allow`/`Deny` from a reachable
/// approver, or `Unreachable` (with a reason) when the user was never actually
/// given a choice. Callers fail closed on `Unreachable`.
pub async fn request_approval(req: &ApprovalRequest) -> AskpassResult {
    let timeout = std::env::var("BOOM_SSHH_ASKPASS_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    // `BOOM_SSHH_ASKPASS=true` is the documented "always allow" (security-off)
    // shortcut — it spawns `true`, which prints nothing, so treat it specially.
    if let Ok(p) = std::env::var("BOOM_SSHH_ASKPASS") {
        if p.trim() == "true" {
            return AskpassResult {
                outcome: ApprovalOutcome::Allow { ttl: None },
                ui: "auto",
                reached: false,
            };
        }
    }

    // Decide which UI path applies *before* spawning, so we can report it even
    // when no approver is reachable (the common "rejected without a pop-up" case).
    let ui: &'static str = if tty_usable() {
        "tui"
    } else if gui_present() {
        "gui"
    } else {
        "none"
    };

    // Custom approver: always spawn it (it may notify the user by other means).
    let custom = match std::env::var("BOOM_SSHH_ASKPASS") {
        Ok(p) if !p.trim().is_empty() => Some(p),
        _ => None,
    };

    let mut cmd = match &custom {
        Some(p) => {
            let mut parts = p.split_whitespace();
            let mut c = Command::new(parts.next().unwrap());
            for a in parts {
                c.arg(a);
            }
            c
        }
        None => {
            // Default approver: if there is no usable UI at all, don't even
            // bother spawning — report it as unreachable for clear diagnostics.
            if ui == "none" {
                return AskpassResult {
                    outcome: ApprovalOutcome::Unreachable {
                        reason: "no tty and no GUI helper".into(),
                    },
                    ui,
                    reached: false,
                };
            }
            match std::env::current_exe() {
                Ok(exe) => {
                    let mut c = Command::new(exe);
                    c.arg("askpass");
                    c
                }
                Err(_) => {
                    return AskpassResult {
                        outcome: ApprovalOutcome::Unreachable {
                            reason: "agent exe not found".into(),
                        },
                        ui,
                        reached: false,
                    }
                }
            }
        }
    };

    let json = match serde_json::to_string(req) {
        Ok(j) => j,
        Err(_) => {
            return AskpassResult {
                outcome: ApprovalOutcome::Unreachable {
                    reason: "request serialization failed".into(),
                },
                ui,
                reached: false,
            }
        }
    };

    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            return AskpassResult {
                outcome: ApprovalOutcome::Unreachable {
                    reason: "approver spawn failed".into(),
                },
                ui,
                reached: false,
            }
        }
    };

    {
        let mut stdin = match child.stdin.take() {
            Some(s) => s,
            None => {
                return AskpassResult {
                    outcome: ApprovalOutcome::Unreachable {
                        reason: "approver stdin unavailable".into(),
                    },
                    ui,
                    reached: false,
                }
            }
        };
        if stdin.write_all(json.as_bytes()).await.is_err() {
            return AskpassResult {
                outcome: ApprovalOutcome::Unreachable {
                    reason: "approver stdin write failed".into(),
                },
                ui,
                reached: false,
            };
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
        Ok(Ok(out)) if out.status.success() => match parse_approval_response(&out.stdout) {
            Some(d) if d.allow => AskpassResult {
                outcome: ApprovalOutcome::Allow { ttl: d.ttl },
                ui,
                reached: true,
            },
            Some(_) => AskpassResult {
                outcome: ApprovalOutcome::Deny,
                ui,
                reached: true,
            },
            None => AskpassResult {
                outcome: ApprovalOutcome::Unreachable {
                    reason: "unparseable approver output".into(),
                },
                ui,
                reached: true,
            },
        },
        Ok(Ok(_)) => AskpassResult {
            outcome: ApprovalOutcome::Unreachable {
                reason: "approver exited non-zero".into(),
            },
            ui,
            reached: true,
        },
        Ok(Err(_)) => AskpassResult {
            outcome: ApprovalOutcome::Unreachable {
                reason: "approver io error".into(),
            },
            ui,
            reached: true,
        },
        Err(_) => AskpassResult {
            outcome: ApprovalOutcome::Unreachable {
                reason: "timeout".into(),
            },
            ui,
            reached: true,
        },
    }
}

/// Parse an approver's stdout into a decision.
///
/// Accepted tokens (first whitespace-delimited word onward):
/// `allow` / `allow session`              → allow, session-scoped
/// `allow 5m` `allow 1h` `allow 12h`      → allow for the given duration
/// `allow <n>s|m|h`                       → allow for N seconds/minutes/hours
/// `deny` / `deny session` / `no` / `n` / `false` → deny
pub fn parse_approval_response(stdout: &[u8]) -> Option<ApprovalDecision> {
    let line = String::from_utf8_lossy(stdout);
    let mut parts = line.split_whitespace();
    let verb = parts.next().unwrap_or("");
    match verb {
        "allow" => {
            let ttl = parse_duration(parts.next().unwrap_or("session"));
            Some(ApprovalDecision { allow: true, ttl })
        }
        "deny" | "no" | "n" | "false" => Some(ApprovalDecision {
            allow: false,
            ttl: None,
        }),
        _ => None,
    }
}

/// Parse a duration token like `session`, `5m`, `1h`, `12h`, `3600s`.
fn parse_duration(tok: &str) -> Option<std::time::Duration> {
    if tok == "session" {
        return None;
    }
    let (num, unit) = tok.split_at(tok.find(|c: char| !c.is_ascii_digit()).unwrap_or(tok.len()));
    let n: u64 = num.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "" => n, // bare number treated as seconds
        _ => return None,
    };
    Some(std::time::Duration::from_secs(secs))
}

/// Entry point for `boom-sshh askpass`.
///
/// Reads a JSON [`ApprovalRequest`] from stdin, then shows an interactive prompt:
/// a terminal panel when a controlling terminal (`/dev/tty`) is available, or a
/// native GUI dialog (zenity/kdialog/osascript) otherwise. Prints the decision
/// token (`allow`/`allow 5m`/`deny`, …) to stdout. With no usable UI the request
/// is denied (fail-closed).
pub fn run_askpass() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let req: ApprovalRequest = serde_json::from_str(&input)?;

    let decision = if tty_usable() {
        prompt_tui(&req)
    } else {
        prompt_gui(&req)
    };

    let mut out = std::io::stdout();
    use std::io::Write;
    writeln!(out, "{}", decision_token(&decision))?;
    Ok(())
}

/// Render an [`ApprovalDecision`] as the token the agent parses.
pub fn decision_token(d: &ApprovalDecision) -> String {
    if !d.allow {
        return "deny".to_string();
    }
    match d.ttl {
        None => "allow session".to_string(),
        Some(t) => {
            let s = t.as_secs();
            let unit = if s % 3600 == 0 {
                format!("{}h", s / 3600)
            } else if s % 60 == 0 {
                format!("{}m", s / 60)
            } else {
                format!("{s}s")
            };
            format!("allow {unit}")
        }
    }
}

/// Run a test approval request through the askpass UI.
///
/// Used by `test-approval` and `init-agent` to verify the approval UI works.
/// `force_ui` can be `Some("tui")` or `Some("gui")` to override auto-detection.
pub fn run_approval_test(force_ui: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ui) = force_ui {
        std::env::set_var("BOOM_SSHH_FORCE_UI", ui);
    }

    let req = ApprovalRequest {
        kind: "test".into(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        summary: vec![
            "Test approval prompt".into(),
            "boom-sshh verification".into(),
        ],
        key_fp: String::new(),
        op: "test".into(),
        host_label: None,
        host_fp: None,
        recent: Vec::new(),
    };

    let decision = if tty_usable() {
        prompt_tui(&req)
    } else {
        prompt_gui(&req)
    };

    let mut out = std::io::stdout();
    use std::io::Write;
    writeln!(out, "{}", decision_token(&decision))?;
    Ok(())
}

/// Detect which GUI helper is available for setup dialogs.
///
/// Only checks for native GUI tools (zenity/kdialog/osascript), not the TUI.
/// Used by init-agent which requires a GUI for confirmation dialogs.
pub fn detect_gui_helper() -> Option<String> {
    if command_present("zenity") {
        return Some("zenity (GUI)".into());
    }
    if command_present("kdialog") {
        return Some("kdialog (GUI)".into());
    }
    if command_present("osascript") {
        return Some("osascript (GUI)".into());
    }
    None
}

/// Show a confirmation dialog asking the user whether to proceed with boom-sshh setup.
///
/// Uses the same zenity/kdialog/osascript flow as the approval UI.
/// Returns `true` if the user allows, `false` if deny or timeout.
pub fn confirm_setup_gui() -> bool {
    let text = "\
Set up boom-sshh?

This will:
• Install boom-sshend to ~/.local/bin/
• Add agent startup to your shell config
• Add history trap to your shell config

[Allow] to proceed, [Deny] to cancel.";

    if command_present("zenity") {
        let out = std::process::Command::new("zenity")
            .args([
                "--question",
                "--title",
                "boom-sshh setup",
                "--ok-label",
                "Allow",
                "--cancel-label",
                "Deny",
                "--text",
                text,
                "--timeout",
                "60",
            ])
            .output();
        return match out {
            Ok(o) => o.status.success(),
            Err(_) => false,
        };
    }
    if command_present("kdialog") {
        let out = std::process::Command::new("kdialog")
            .args([
                "--title",
                "boom-sshh setup",
                "--yesno",
                text,
                "60",
            ])
            .output();
        return match out {
            Ok(o) => o.status.success(),
            Err(_) => false,
        };
    }
    if command_present("osascript") {
        let script = format!(
            "display dialog \"boom-sshh setup\n\nThis will install boom-sshend, add agent startup, and add history trap to your shell config.\" buttons {{\"Deny\", \"Allow\"}} default button \"Allow\""
        );
        let out = std::process::Command::new("osascript")
            .args(["-e", &script])
            .output();
        return match out {
            Ok(o) => o.status.success(),
            Err(_) => false,
        };
    }
    false
}

/// True when a usable controlling terminal exists (so a TUI panel can be drawn).
fn tty_usable() -> bool {
    if let Ok(v) = std::env::var("BOOM_SSHH_FORCE_UI") {
        return v == "tui";
    }
    match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => termion::is_tty(&tty),
        Err(_) => false,
    }
}

/// Render an interactive approval panel on `/dev/tty`.
///
/// `a` allows (session-scoped); `d`/`q`/Esc deny. Output is the `allow`/`deny`
/// token; duration presets live in the GUI approver.
fn prompt_tui(req: &ApprovalRequest) -> ApprovalDecision {
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};
    use termion::input::TermRead;
    use termion::screen::IntoAlternateScreen;

    let tty = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(t) => t,
        Err(_) => return ApprovalDecision { allow: false, ttl: None },
    };
    let raw = match termion::raw::IntoRawMode::into_raw_mode(tty) {
        Ok(r) => r,
        Err(_) => return ApprovalDecision { allow: false, ttl: None },
    };
    let alt = match raw.into_alternate_screen() {
        Ok(a) => a,
        Err(_) => return ApprovalDecision { allow: false, ttl: None },
    };
    let backend = ratatui::backend::TermionBackend::new(alt);
    let mut terminal = match ratatui::Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => return ApprovalDecision { allow: false, ttl: None },
    };

    // Read keystrokes on a separate fd/thread so the countdown can tick.
    let reader = match std::fs::File::open("/dev/tty") {
        Ok(r) => r,
        Err(_) => return ApprovalDecision { allow: false, ttl: None },
    };
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let events = reader.events();
        for ev in events {
            if let Ok(termion::event::Event::Key(k)) = ev {
                let _ = tx.send(k);
            }
        }
    });

    let timeout = std::env::var("BOOM_SSHH_ASKPASS_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    let start = Instant::now();
    let mut decision = ApprovalDecision { allow: false, ttl: None };
    let mut done = false;

    let _ = terminal.clear();
    while !done {
        let elapsed = start.elapsed().as_secs_f64();
        let remaining = (timeout as f64 - elapsed).max(0.0);
        let pct = if timeout > 0 {
            (elapsed / timeout as f64).min(1.0)
        } else {
            1.0
        };

        let _ = terminal.draw(|f| {
            let area = centered_rect(60, 70, f.area());
            let block = ratatui::widgets::Block::default()
                .title(format!(" boom-sshh: {} ", req.kind))
                .borders(ratatui::widgets::Borders::ALL)
                .border_style(ratatui::style::Style::default().fg(ratatui::style::Color::Yellow));
            let inner = block.inner(area);
            let _ = f.render_widget(block, area);

            let chunks = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .margin(1)
                .constraints([
                    ratatui::layout::Constraint::Min(3),
                    ratatui::layout::Constraint::Length(3),
                    ratatui::layout::Constraint::Length(1),
                ])
                .split(inner);

            let mut lines = Vec::new();
            lines.push(ratatui::text::Line::from(format!(
                "{} request — respond within {:.0}s",
                req.kind, remaining
            )));
            for s in &req.summary {
                lines.push(ratatui::text::Line::from(format!("  {s}")));
            }
            let _ = f.render_widget(
                ratatui::widgets::Paragraph::new(lines)
                    .wrap(ratatui::widgets::Wrap { trim: true }),
                chunks[0],
            );

            let _ = f.render_widget(
                ratatui::widgets::Gauge::default()
                    .ratio(pct)
                    .label(format!("{:.0}s", remaining)),
                chunks[1],
            );

            let _ = f.render_widget(
                ratatui::widgets::Paragraph::new("a=allow  d/q/Esc=deny"),
                chunks[2],
            );
        });

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(termion::event::Key::Char('a')) => {
                decision = ApprovalDecision { allow: true, ttl: None };
                done = true;
            }
            Ok(termion::event::Key::Char('d'))
            | Ok(termion::event::Key::Char('q'))
            | Ok(termion::event::Key::Esc) => {
                decision = ApprovalDecision { allow: false, ttl: None };
                done = true;
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if remaining <= 0.0 {
                    decision = ApprovalDecision { allow: false, ttl: None };
                    done = true;
                }
            }
            Err(_) => {
                decision = ApprovalDecision { allow: false, ttl: None };
                done = true;
            }
        }
    }

    let _ = terminal.clear();
    decision
}

/// Convert a button/label token into a decision (used by zenity extra buttons).
fn label_to_decision(label: &str) -> ApprovalDecision {
    let mut p = label.split_whitespace();
    match p.next() {
        Some("allow") => ApprovalDecision {
            allow: true,
            ttl: parse_duration(p.next().unwrap_or("session")),
        },
        _ => ApprovalDecision {
            allow: false,
            ttl: None,
        },
    }
}

/// Pop a native GUI dialog when no terminal is available.
///
/// Prefers zenity (duration presets + Details); otherwise kdialog / osascript.
/// If no GUI tool is present the request is denied (fail-closed).
fn prompt_gui(req: &ApprovalRequest) -> ApprovalDecision {
    let timeout = std::env::var("BOOM_SSHH_ASKPASS_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    let gist = req
        .summary
        .iter()
        .take(4)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    let mut text = format!("{} request\n\n{}", req.kind, gist);
    if !req.recent.is_empty() {
        let recent = req
            .recent
            .iter()
            .map(|c| format!("  $ {c}"))
            .collect::<Vec<_>>()
            .join("\n");
        text.push_str(&format!("\n\nRecent on this session:\n{recent}"));
    }

    // Write the full request to a private temp file for the "Details" view.
    let detail_path = std::env::temp_dir().join(format!("boom-sshh-req-{}.json", std::process::id()));
    let mut wrote_detail = false;
    if let Ok(json) = serde_json::to_string_pretty(req) {
        if std::fs::write(&detail_path, json).is_ok() {
            wrote_detail = true;
            let _ = std::fs::set_permissions(
                &detail_path,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            );
        }
    }

    let decision = if command_present("zenity") {
        zenity_approve(&text, timeout, &detail_path, wrote_detail)
    } else if command_present("kdialog") {
        kdialog_approve(&text, timeout)
    } else if command_present("osascript") {
        osascript_approve(&text)
    } else {
        ApprovalDecision {
            allow: false,
            ttl: None,
        }
    };

    if wrote_detail {
        let _ = std::fs::remove_file(&detail_path);
    }
    decision
}

/// zenity: question dialog with duration presets. "Details" re-opens the full
/// request in a text box and asks again. OK/Cancel = Deny.
fn zenity_approve(text: &str, timeout: u64, detail_path: &std::path::Path, has_detail: bool) -> ApprovalDecision {
    loop {
        let mut args: Vec<String> = vec![
            "--question".into(),
            "--title".into(),
            "boom-sshh".into(),
            "--ok-label".into(),
            "Deny".into(),
            "--cancel-label".into(),
            "Deny".into(),
            "--text".into(),
            text.into(),
            "--timeout".into(),
            timeout.to_string(),
        ];
        for b in ["Allow 5m", "Allow 1h", "Allow 12h", "Allow session"] {
            args.push("--extra-button".into());
            args.push(b.to_string());
        }
        if has_detail {
            args.push("--extra-button".into());
            args.push("Details".into());
        }
        match std::process::Command::new("zenity").args(&args).output().ok() {
            Some(o) if o.status.success() => {
                let label = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if label == "Details" {
                    let _ = std::process::Command::new("zenity")
                        .args([
                            "--text-info",
                            "--title",
                            "boom-sshh request",
                            "--width",
                            "700",
                            "--height",
                            "500",
                            "--filename",
                        ])
                        .arg(detail_path)
                        .status();
                    continue;
                }
                return label_to_decision(&label);
            }
            _ => return ApprovalDecision {
                allow: false,
                ttl: None,
            },
        }
    }
}

/// kdialog: menu with duration presets.
fn kdialog_approve(text: &str, timeout: u64) -> ApprovalDecision {
    let out = std::process::Command::new("kdialog")
        .args([
            "--title",
            "boom-sshh",
            "--menu",
            text,
            "5m",
            "Allow 5m",
            "1h",
            "Allow 1h",
            "12h",
            "Allow 12h",
            "session",
            "Allow session",
            "deny",
            "Deny",
            &timeout.to_string(),
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let tag = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match tag.as_str() {
                "5m" => ApprovalDecision {
                    allow: true,
                    ttl: Some(std::time::Duration::from_secs(300)),
                },
                "1h" => ApprovalDecision {
                    allow: true,
                    ttl: Some(std::time::Duration::from_secs(3600)),
                },
                "12h" => ApprovalDecision {
                    allow: true,
                    ttl: Some(std::time::Duration::from_secs(43200)),
                },
                "session" => ApprovalDecision {
                    allow: true,
                    ttl: None,
                },
                _ => ApprovalDecision {
                    allow: false,
                    ttl: None,
                },
            }
        }
        _ => ApprovalDecision {
            allow: false,
            ttl: None,
        },
    }
}

/// osascript: simple Allow/Deny (session-scoped allow).
fn osascript_approve(text: &str) -> ApprovalDecision {
    let script = format!(
        "display dialog \"boom-sshh request: {}\" buttons {{\"Deny\", \"Allow\"}} default button \"Allow\"",
        text.replace('"', "'")
    );
    let out = std::process::Command::new("osascript").args(["-e", &script]).output();
    match out {
        Ok(o) if o.status.success() => ApprovalDecision {
            allow: true,
            ttl: None,
        },
        _ => ApprovalDecision {
            allow: false,
            ttl: None,
        },
    }
}

/// True if `name` resolves on PATH.
fn command_present(name: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// True when a native GUI approver helper is available (zenity/kdialog/osascript).
fn gui_present() -> bool {
    command_present("zenity") || command_present("kdialog") || command_present("osascript")
}

/// Centre a rectangle inside `area` at the given percentage of its size.
fn centered_rect(percent_x: u16, percent_y: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let width = area.width * percent_x / 100;
    let height = area.height * percent_y / 100;
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    ratatui::layout::Rect {
        x,
        y,
        width,
        height,
    }
}
