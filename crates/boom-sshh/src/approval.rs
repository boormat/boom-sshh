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
}

/// Ask the configured approver whether a request should be allowed.
///
/// Returns `true` to allow, `false` to deny.
pub async fn request_approval(req: &ApprovalRequest) -> bool {
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
                c.arg("askpass");
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
            !matches!(first, "deny" | "no" | "n" | "false")
        }
        _ => false,
    }
}

/// Entry point for `boom-sshh askpass`.
///
/// Reads a JSON [`ApprovalRequest`] from stdin, then shows an interactive prompt:
/// a terminal panel when a controlling terminal (`/dev/tty`) is available, or a
/// native GUI dialog (zenity/kdialog/osascript) otherwise. Prints `allow` or
/// `deny` to stdout. With no usable UI the request is denied (fail-closed).
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
    writeln!(out, "{}", if decision { "allow" } else { "deny" })?;
    Ok(())
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
    };

    let decision = if tty_usable() {
        prompt_tui(&req)
    } else {
        prompt_gui(&req)
    };

    let mut out = std::io::stdout();
    use std::io::Write;
    writeln!(out, "{}", if decision { "allow" } else { "deny" })?;
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
fn prompt_tui(req: &ApprovalRequest) -> bool {
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};
    use termion::input::TermRead;
    use termion::screen::IntoAlternateScreen;

    let tty = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(t) => t,
        Err(_) => return false,
    };
    let raw = match termion::raw::IntoRawMode::into_raw_mode(tty) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let alt = match raw.into_alternate_screen() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let backend = ratatui::backend::TermionBackend::new(alt);
    let mut terminal = match ratatui::Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => return false,
    };

    // Read keystrokes on a separate fd/thread so the countdown can tick.
    let reader = match std::fs::File::open("/dev/tty") {
        Ok(r) => r,
        Err(_) => return false,
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
    let mut decision = false;
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
                decision = true;
                done = true;
            }
            Ok(termion::event::Key::Char('d'))
            | Ok(termion::event::Key::Char('q'))
            | Ok(termion::event::Key::Esc) => {
                decision = false;
                done = true;
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if remaining <= 0.0 {
                    decision = false;
                    done = true;
                }
            }
            Err(_) => {
                decision = false;
                done = true;
            }
        }
    }

    let _ = terminal.clear();
    decision
}

/// Pop a native GUI dialog when no terminal is available.
///
/// Prefers zenity (which supports a "Details" drill-down); otherwise kdialog /
/// osascript. If no GUI tool is present the request is denied (fail-closed).
fn prompt_gui(req: &ApprovalRequest) -> bool {
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
    let text = format!("{} request\n\n{}", req.kind, gist);

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
    } else {
        gui_approver_cmd(&text, timeout)
            .map(|(prog, args)| std::process::Command::new(prog).args(args).status())
            .and_then(|r| r.ok())
            .map(|s| s.success())
            .unwrap_or(false)
    };

    if wrote_detail {
        let _ = std::fs::remove_file(&detail_path);
    }
    decision
}

/// zenity loop: shows the question dialog; if the user clicks "Details" it
/// opens a scrollable text box with the full request and asks again.
fn zenity_approve(text: &str, timeout: u64, detail_path: &std::path::Path, has_detail: bool) -> bool {
    loop {
        let mut args: Vec<String> = vec![
            "--question".into(),
            "--title".into(),
            "boom-sshh".into(),
            "--ok-label".into(),
            "Allow".into(),
            "--cancel-label".into(),
            "Deny".into(),
            "--text".into(),
            text.into(),
            "--timeout".into(),
            timeout.to_string(),
        ];
        if has_detail {
            args.push("--extra-button".into());
            args.push("Details".into());
        }
        let out = std::process::Command::new("zenity").args(&args).output().ok();
        match out {
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
                return true;
            }
            _ => return false,
        }
    }
}

/// Choose the GUI approver program + args (kdialog / osascript).
fn gui_approver_cmd(text: &str, timeout: u64) -> Option<(String, Vec<String>)> {
    if command_present("kdialog") {
        return Some((
            "kdialog".into(),
            vec![
                "--title".into(),
                "boom-sshh".into(),
                "--yesno".into(),
                text.into(),
                timeout.to_string(),
            ],
        ));
    }
    if command_present("osascript") {
        let detail_arg = format!(
            "display dialog \"boom-sshh request\" buttons {{\"Deny\", \"Allow\"}} default button \"Allow\""
        );
        return Some(("osascript".into(), vec!["-e".into(), detail_arg]));
    }
    None
}

/// True if `name` resolves on PATH.
fn command_present(name: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
