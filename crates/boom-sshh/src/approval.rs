//! Interactive approval via an external "askpass" program.
//!
//! The agent is a headless daemon, so approval prompts are delegated to an
//! external program configured through `BOOM_SSHH_ASKPASS`:
//!
//! * unset / empty  -> default to re-invoking `boom-sshh askpass`, which shows
//!   a native GUI dialog (zenity/kdialog).
//! * `<program> [args...]` -> spawn that program; it reads a JSON
//!   [`ApprovalRequest`] on stdin and must print either a legacy token
//!   (`allow` / `allow 5m` / `deny`) or a JSON envelope (see
//!   [`parse_approval_response`]) to stdout.
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
#[derive(Clone)]
pub struct ApprovalDecision {
    pub allow: bool,
    /// How long an allow decision stays valid. `None` = until the agent exits
    /// (session-scoped); `Some(d)` = expires after `d`.
    pub ttl: Option<std::time::Duration>,
    /// `true` = allow this one request only; no rule is remembered.
    pub once: bool,
    /// What a stored rule should match; `None` = match the request itself.
    pub criteria: Option<AllowCriteria>,
}

/// What a stored auto-approval rule matches. All fields default to the request's
/// own values when omitted; `None`/`Any` mean "any".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowCriteria {
    /// Key fingerprint, or `None`/`*` for any key.
    pub key_fp: Option<String>,
    /// Operation class (`ssh-userauth`, `git-commit`, …), or `None`/`*` for any.
    pub op: Option<String>,
    pub host: HostSpec,
}

/// Host matching for a rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostSpec {
    /// `*` — any destination (bound or unbound).
    Any,
    /// Only signs with no bound destination.
    Unbound,
    /// Only signs bound to this destination host key fingerprint.
    Specific(String),
}

/// Serializes tests that mutate process-global approval env vars
/// (`BOOM_SSHH_ASKPASS`, `DISPLAY`, …) so they don't clobber each other.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The result of asking the configured approver.
///
/// `Unreachable` means the user was never actually given a choice (no usable UI,
/// spawn failure, timeout, or non-zero exit) — callers fail closed on it. It is
/// kept distinct from an explicit `Deny` so the auth log can show *why* a request
/// was rejected, and so nothing is ever remembered as "denied".
#[derive(Debug)]
pub enum ApprovalOutcome {
    /// Store an auto-approval rule. `criteria` is what the rule matches;
    /// `None` means "match this request's own key/op/host".
    Allow {
        ttl: Option<std::time::Duration>,
        criteria: Option<AllowCriteria>,
    },
    /// Allow this one request only; no rule is stored.
    AllowOnce,
    Deny,
    Unreachable { reason: String },
}

/// Full result returned to the agent: the outcome plus diagnostics describing
/// how the approver was reached (used only for logging/feedback).
pub struct AskpassResult {
    pub outcome: ApprovalOutcome,
    /// UI path that would/should have been used: `gui` | `none` | `auto`.
    pub ui: &'static str,
    /// Whether an approver process was actually spawned/contacted.
    pub reached: bool,
}

/// Ask the configured approver whether a request should be allowed.
///
/// `always_allow` comes from the agent's `--yolo` flag and short-circuits every
/// other mechanism, including an explicitly configured `BOOM_SSHH_ASKPASS`.
///
/// Returns an [`AskpassResult`]: an explicit `Allow`/`Deny` from a reachable
/// approver, or `Unreachable` (with a reason) when the user was never actually
/// given a choice. Callers fail closed on `Unreachable`.
pub async fn request_approval(req: &ApprovalRequest, always_allow: bool) -> AskpassResult {
    // `--yolo` bypasses the approver entirely (no process spawned, no UI).
    if always_allow {
        return AskpassResult {
            outcome: ApprovalOutcome::Allow {
                ttl: None,
                criteria: None,
            },
            ui: "yolo",
            reached: false,
        };
    }

    let timeout = std::env::var("BOOM_SSHH_ASKPASS_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    // `BOOM_SSHH_ASKPASS=true` is the documented "always allow" (security-off)
    // shortcut — it spawns `true`, which prints nothing, so treat it specially.
    if let Ok(p) = std::env::var("BOOM_SSHH_ASKPASS") {
        if p.trim() == "true" {
            return AskpassResult {
                outcome: ApprovalOutcome::Allow {
                    ttl: None,
                    criteria: None,
                },
                ui: "auto",
                reached: false,
            };
        }
    }

    // Decide which UI path applies *before* spawning, so we can report it even
    // when no approver is reachable (the common "rejected without a pop-up" case).
    let ui: &'static str = if gui_present() { "gui" } else { "none" };
    let display_present =
        std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

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
            // Default approver: don't spawn if there's clearly no way to show a
            // prompt. A GUI helper may be installed, but with no display (e.g. an
            // SSH session without X forwarding) it cannot appear — report that
            // directly instead of spawning something that will just fail.
            let reason = if ui == "none" {
                "no GUI helper available (install zenity/kdialog, or set BOOM_SSHH_ASKPASS=true for history-only mode)"
            } else {
                "GUI helper present but no display"
            };
            if ui == "none" || !display_present {
                let reason = format!("{reason} ({})", env_context());
                return AskpassResult {
                    outcome: ApprovalOutcome::Unreachable { reason },
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
        .stderr(std::process::Stdio::piped());

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
            Some(d) if d.allow && d.once => AskpassResult {
                outcome: ApprovalOutcome::AllowOnce,
                ui,
                reached: true,
            },
            Some(d) if d.allow => AskpassResult {
                outcome: ApprovalOutcome::Allow {
                    ttl: d.ttl,
                    criteria: d.criteria,
                },
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
        Ok(Ok(out)) => AskpassResult {
            outcome: ApprovalOutcome::Unreachable {
                reason: format!(
                    "approver exited non-zero ({}): {}",
                    env_context(),
                    stderr_snippet(&out.stderr)
                ),
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
/// The askpass prints a JSON envelope; legacy plain tokens are also accepted
/// (for custom `BOOM_SSHH_ASKPASS` scripts):
///
/// * `{"decision":"deny"}`
/// * `{"decision":"once"}`                        → allow once, no rule
/// * `{"decision":"allow","ttl":"5m"|"1h"|"12h"|"forever","criteria":{…}}`
/// * legacy: `allow` / `allow 5m` / `allow session` / `deny` / `no` / `n` / `false`
///
/// `criteria` is `{"key":…,"op":…,"host":…}` where `key`/`op` are a value or
/// `"*"`, and `host` is a value, `"*"`, or `"unbound"`. When `criteria` is
/// omitted the rule matches the request itself.
pub fn parse_approval_response(stdout: &[u8]) -> Option<ApprovalDecision> {
    let line = String::from_utf8_lossy(stdout);
    let trimmed = line.trim();
    if trimmed.starts_with('{') {
        return parse_envelope(trimmed);
    }
    let mut parts = line.split_whitespace();
    let verb = parts.next().unwrap_or("");
    match verb {
        "allow" => {
            let word = parts.next().unwrap_or("forever");
            if word == "once" {
                Some(ApprovalDecision {
                    allow: true,
                    ttl: None,
                    once: true,
                    criteria: None,
                })
            } else {
                Some(ApprovalDecision {
                    allow: true,
                    ttl: parse_duration(word),
                    once: false,
                    criteria: None,
                })
            }
        }
        "deny" | "no" | "n" | "false" => Some(ApprovalDecision {
            allow: false,
            ttl: None,
            once: false,
            criteria: None,
        }),
        _ => None,
    }
}

/// JSON envelope emitted by the built-in askpass.
#[derive(Deserialize)]
struct Envelope {
    decision: String,
    ttl: Option<String>,
    criteria: Option<CriteriaEnvelope>,
}

#[derive(Deserialize)]
struct CriteriaEnvelope {
    key: Option<String>,
    op: Option<String>,
    host: Option<String>,
}

fn parse_envelope(s: &str) -> Option<ApprovalDecision> {
    let env: Envelope = serde_json::from_str(s).ok()?;
    match env.decision.as_str() {
        "deny" => Some(ApprovalDecision {
            allow: false,
            ttl: None,
            once: false,
            criteria: None,
        }),
        "once" => Some(ApprovalDecision {
            allow: true,
            ttl: None,
            once: true,
            criteria: None,
        }),
        "allow" => {
            let ttl = env.ttl.as_deref().and_then(parse_duration);
            let criteria = env.criteria.map(|c| AllowCriteria {
                key_fp: c.key.filter(|v| v != "*"),
                op: c.op.filter(|v| v != "*"),
                host: match c.host.as_deref() {
                    None | Some("") | Some("*") => HostSpec::Any,
                    Some("unbound") => HostSpec::Unbound,
                    Some(fp) => HostSpec::Specific(fp.to_string()),
                },
            });
            Some(ApprovalDecision {
                allow: true,
                ttl,
                once: false,
                criteria,
            })
        }
        _ => None,
    }
}

/// Parse a duration token like `forever`/`session`, `5m`, `1h`, `12h`, `3600s`.
fn parse_duration(tok: &str) -> Option<std::time::Duration> {
    if tok == "session" || tok == "forever" {
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
/// Reads a JSON [`ApprovalRequest`] from stdin, shows a native GUI dialog
/// (zenity/kdialog), and prints the decision as a JSON envelope to stdout. With
/// no usable GUI the request is denied (fail-closed).
pub fn run_askpass() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let req: ApprovalRequest = serde_json::from_str(&input)?;

    let decision = prompt_gui(&req);

    let mut out = std::io::stdout();
    use std::io::Write;
    writeln!(out, "{}", decision_token(&decision))?;
    Ok(())
}

/// Render an [`ApprovalDecision`] as the JSON envelope the agent parses.
pub fn decision_token(d: &ApprovalDecision) -> String {
    if !d.allow {
        return r#"{"decision":"deny"}"#.to_string();
    }
    if d.once {
        return r#"{"decision":"once"}"#.to_string();
    }
    let ttl = match d.ttl {
        None => "forever".to_string(),
        Some(t) => {
            let s = t.as_secs();
            if s % 3600 == 0 {
                format!("{}h", s / 3600)
            } else if s % 60 == 0 {
                format!("{}m", s / 60)
            } else {
                format!("{s}s")
            }
        }
    };
    let criteria = d.criteria.as_ref().map(|c| serde_json::json!({
        "key": c.key_fp.clone().unwrap_or_else(|| "*".into()),
        "op": c.op.clone().unwrap_or_else(|| "*".into()),
        "host": match &c.host {
            HostSpec::Any => "*".to_string(),
            HostSpec::Unbound => "unbound".to_string(),
            HostSpec::Specific(fp) => fp.clone(),
        },
    }));
    let mut obj = serde_json::Map::new();
    obj.insert("decision".into(), "allow".into());
    obj.insert("ttl".into(), ttl.into());
    if let Some(c) = criteria {
        obj.insert("criteria".into(), c);
    }
    serde_json::Value::Object(obj).to_string()
}

/// Run a test approval request through the askpass UI.
///
/// Used by `test-approval` to verify the approval UI works (GUI only).
pub fn run_approval_test() -> Result<(), Box<dyn std::error::Error>> {
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

    let decision = prompt_gui(&req);

    let mut out = std::io::stdout();
    use std::io::Write;
    writeln!(out, "{}", decision_token(&decision))?;
    Ok(())
}

/// Detect which GUI helper is available for setup dialogs.
///
/// Only checks for native GUI tools (zenity/kdialog). Used by init-agent which
/// requires a GUI for confirmation dialogs.
pub fn detect_gui_helper() -> Option<String> {
    if command_present("zenity") {
        return Some("zenity (GUI)".into());
    }
    if command_present("kdialog") {
        return Some("kdialog (GUI)".into());
    }
    None
}

/// Show a confirmation dialog asking the user whether to proceed with boom-sshh setup.
///
/// Uses the same zenity/kdialog flow as the approval UI.
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
    false
}

/// Convert a button/label token into a decision (used by zenity extra buttons).
fn label_to_decision(label: &str) -> ApprovalDecision {
    let mut p = label.split_whitespace();
    match p.next() {
        Some(v) if v.eq_ignore_ascii_case("allow") || v.eq_ignore_ascii_case("approve") => {
            let word = p.next().unwrap_or("forever");
            if word.eq_ignore_ascii_case("once") {
                ApprovalDecision {
                    allow: true,
                    ttl: None,
                    once: true,
                    criteria: None,
                }
            } else {
                ApprovalDecision {
                    allow: true,
                    ttl: parse_duration(word),
                    once: false,
                    criteria: None,
                }
            }
        }
        _ => ApprovalDecision {
            allow: false,
            ttl: None,
            once: false,
            criteria: None,
        },
    }
}

/// Pop a native GUI approval dialog. Prefers zenity; falls back to kdialog.
/// If no GUI tool is present the request is denied (fail-closed).
fn prompt_gui(req: &ApprovalRequest) -> ApprovalDecision {
    let timeout = std::env::var("BOOM_SSHH_ASKPASS_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    let mut text = format!("{} request\n\n{}", req.kind, req.summary.join("\n"));
    if !req.recent.is_empty() {
        let recent = req
            .recent
            .iter()
            .map(|c| format!("  $ {c}"))
            .collect::<Vec<_>>()
            .join("\n");
        text.push_str(&format!("\n\nRecent on this session:\n{recent}"));
    }
    if let Ok(json) = serde_json::to_string_pretty(req) {
        text.push_str(&format!("\n\nDetails:\n{json}"));
    }
    text.push_str(&format!(
        "\n\nAuto-approve will match: {}",
        criteria_line(req)
    ));

    if command_present("zenity") {
        zenity_approve(&text, timeout, req)
    } else if command_present("kdialog") {
        kdialog_approve(&text, timeout, req)
    } else {
        ApprovalDecision {
            allow: false,
            ttl: None,
            once: false,
            criteria: None,
        }
    }
}

/// The editable criteria line for a request (`key=… op=… host=…`).
fn criteria_line(req: &ApprovalRequest) -> String {
    let key = if req.key_fp.is_empty() {
        "*".to_string()
    } else {
        req.key_fp.clone()
    };
    let op = if req.op.is_empty() {
        "*".to_string()
    } else {
        req.op.clone()
    };
    let host = match &req.host_fp {
        Some(fp) if !fp.is_empty() => fp.clone(),
        _ => "unbound".to_string(),
    };
    format!("key={key} op={op} host={host}")
}

/// Parse an edited criteria line back into [`AllowCriteria`]. `*` = any,
/// `host=unbound` = only unbound signs; omitted fields fall back to the request's
/// own values.
fn parse_criteria_line(line: &str, req: &ApprovalRequest) -> AllowCriteria {
    let mut key = None::<String>;
    let mut op = None::<String>;
    let mut host = None::<String>;
    for tok in line.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            let v = v.trim();
            match k {
                "key" => key = Some(v.to_string()),
                "op" => op = Some(v.to_string()),
                "host" => host = Some(v.to_string()),
                _ => {}
            }
        }
    }
    AllowCriteria {
        key_fp: match key {
            Some(v) if v == "*" => None,
            Some(v) if !v.is_empty() => Some(v),
            _ => {
                if req.key_fp.is_empty() {
                    None
                } else {
                    Some(req.key_fp.clone())
                }
            }
        },
        op: match op {
            Some(v) if v == "*" => None,
            Some(v) if !v.is_empty() => Some(v),
            _ => {
                if req.op.is_empty() {
                    None
                } else {
                    Some(req.op.clone())
                }
            }
        },
        host: match host {
            Some(v) if v == "*" => HostSpec::Any,
            Some(v) if v == "unbound" => HostSpec::Unbound,
            Some(v) if !v.is_empty() => HostSpec::Specific(v),
            _ => match &req.host_fp {
                Some(fp) if !fp.is_empty() => HostSpec::Specific(fp.clone()),
                _ => HostSpec::Unbound,
            },
        },
    }
}

/// zenity: stage 1 picks a decision, stage 2 (only for stored rules) edits the
/// criteria. A single Deny button; close/timeout = deny.
fn zenity_approve(text: &str, timeout: u64, req: &ApprovalRequest) -> ApprovalDecision {
    let default_line = criteria_line(req);
    loop {
        let mut args: Vec<String> = vec![
            "--info".into(),
            "--title".into(),
            "boom-sshh".into(),
            "--ok-label".into(),
            "Deny".into(),
            "--text".into(),
            text.into(),
            "--timeout".into(),
            timeout.to_string(),
        ];
        for b in ["Approve 5m", "Approve 1h", "Approve 12h", "Approve forever", "Approve once"] {
            args.push("--extra-button".into());
            args.push(b.to_string());
        }
        let mut decision = match std::process::Command::new("zenity").args(&args).output() {
            Ok(o) => {
                // Extra buttons print their label; exit code varies by zenity
                // version, so decide from the label. Empty stdout = Deny
                // (single Deny button, close, or timeout).
                let label = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if label.is_empty() {
                    ApprovalDecision {
                        allow: false,
                        ttl: None,
                        once: false,
                        criteria: None,
                    }
                } else {
                    label_to_decision(&label)
                }
            }
            Err(_) => ApprovalDecision {
                allow: false,
                ttl: None,
                once: false,
                criteria: None,
            },
        };

        if decision.allow && !decision.once {
            match edit_criteria_zenity(text, &default_line, req) {
                Some(c) => {
                    decision.criteria = Some(c);
                    return decision;
                }
                // Cancelled the criteria edit — let the user pick again.
                None => continue,
            }
        }
        return decision;
    }
}

/// zenity `--entry` for editing the auto-approval criteria. Returns `None` when
/// the user cancels.
fn edit_criteria_zenity(
    text: &str,
    default_line: &str,
    req: &ApprovalRequest,
) -> Option<AllowCriteria> {
    let prompt = format!(
        "{text}\n\nEditable auto-approval criteria.\nkey=VALUE op=VALUE host=VALUE\n'*' = any; host=unbound = only unbound.\nSave with the current values to accept them."
    );
    let out = std::process::Command::new("zenity")
        .args([
            "--entry",
            "--title",
            "boom-sshh",
            "--text",
            &prompt,
            "--entry-text",
            default_line,
            "--ok-label",
            "Save Approve",
            "--cancel-label",
            "Cancel",
            "--width",
            "720",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if line.is_empty() {
                None
            } else {
                Some(parse_criteria_line(&line, req))
            }
        }
        _ => None,
    }
}

/// kdialog: menu picks the decision; an input box edits criteria for stored rules.
fn kdialog_approve(text: &str, timeout: u64, req: &ApprovalRequest) -> ApprovalDecision {
    let default_line = criteria_line(req);
    loop {
        let out = std::process::Command::new("kdialog")
            .args([
                "--title",
                "boom-sshh",
                "--menu",
                text,
                "5m",
                "Approve 5m",
                "1h",
                "Approve 1h",
                "12h",
                "Approve 12h",
                "forever",
                "Approve forever",
                "once",
                "Approve once",
                "deny",
                "Deny",
                &timeout.to_string(),
            ])
            .output();
        let mut decision = match out {
            Ok(o) if o.status.success() => {
                let tag = String::from_utf8_lossy(&o.stdout).trim().to_string();
                match tag.as_str() {
                    "5m" => ApprovalDecision {
                        allow: true,
                        ttl: Some(std::time::Duration::from_secs(300)),
                        once: false,
                        criteria: None,
                    },
                    "1h" => ApprovalDecision {
                        allow: true,
                        ttl: Some(std::time::Duration::from_secs(3600)),
                        once: false,
                        criteria: None,
                    },
                    "12h" => ApprovalDecision {
                        allow: true,
                        ttl: Some(std::time::Duration::from_secs(43200)),
                        once: false,
                        criteria: None,
                    },
                    "forever" => ApprovalDecision {
                        allow: true,
                        ttl: None,
                        once: false,
                        criteria: None,
                    },
                    "once" => ApprovalDecision {
                        allow: true,
                        ttl: None,
                        once: true,
                        criteria: None,
                    },
                    _ => ApprovalDecision {
                        allow: false,
                        ttl: None,
                        once: false,
                        criteria: None,
                    },
                }
            }
            _ => ApprovalDecision {
                allow: false,
                ttl: None,
                once: false,
                criteria: None,
            },
        };

        if decision.allow && !decision.once {
            match edit_criteria_kdialog(text, &default_line, req) {
                Some(c) => {
                    decision.criteria = Some(c);
                    return decision;
                }
                None => continue,
            }
        }
        return decision;
    }
}

/// kdialog `--inputbox` for editing the auto-approval criteria. Returns `None`
/// when the user cancels.
fn edit_criteria_kdialog(
    text: &str,
    default_line: &str,
    req: &ApprovalRequest,
) -> Option<AllowCriteria> {
    let prompt = format!(
        "{text}\n\nEditable auto-approval criteria.\nkey=VALUE op=VALUE host=VALUE\n'*' = any; host=unbound = only unbound."
    );
    let out = std::process::Command::new("kdialog")
        .args(["--inputbox", &prompt, default_line])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if line.is_empty() {
                None
            } else {
                Some(parse_criteria_line(&line, req))
            }
        }
        _ => None,
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

/// True when a native GUI approver helper is available (zenity/kdialog).
fn gui_present() -> bool {
    command_present("zenity") || command_present("kdialog")
}

/// A short description of the environment a failed popup ran in, so the auth log
/// can explain *why* the prompt never appeared — e.g. an SSH session with no
/// display forwarded (`ssh-session;no-display`) versus a missing GUI helper.
fn env_context() -> String {
    let ssh =
        std::env::var("SSH_CONNECTION").is_ok() || std::env::var("SSH_TTY").is_ok();
    let display =
        std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();
    let mut s = String::from(if ssh { "ssh-session" } else { "local" });
    if display {
        s.push_str(";display-present");
    } else {
        s.push_str(";no-display");
    }
    s
}

/// First non-empty line of the approver's stderr, trimmed and capped, for inclusion
/// in the failure reason (e.g. "cannot open display:").
fn stderr_snippet(stderr: &[u8]) -> String {
    let s = String::from_utf8_lossy(stderr);
    let line = s.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
    if line.is_empty() {
        "no output".to_string()
    } else {
        line.chars().take(160).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stderr_snippet_first_line() {
        assert_eq!(stderr_snippet(b""), "no output");
        assert_eq!(
            stderr_snippet(b"cannot open display:\n"),
            "cannot open display:"
        );
        // Blank lines are skipped, and the line is capped.
        assert_eq!(
            stderr_snippet(b"\n\n  Unable to init server: DISPLAY not set  \n"),
            "Unable to init server: DISPLAY not set"
        );
        let long = format!("x{}y", "a".repeat(200));
        assert_eq!(stderr_snippet(long.as_bytes()).len(), 160);
    }

    #[test]
    fn test_env_context_shape() {
        // Just ensure it produces a recognised prefix; exact value depends on env.
        let c = env_context();
        assert!(c == "local;display-present"
            || c == "local;no-display"
            || c == "ssh-session;display-present"
            || c == "ssh-session;no-display");
    }

    #[tokio::test]
    async fn test_approval_detects_ssh_no_display() {
        // Simulate an SSH session with no forwarded display and confirm the
        // failure is reported as such rather than a silent deny.
        let _g = crate::approval::TEST_ENV_LOCK.lock().unwrap();
        let had_display = std::env::var("DISPLAY").ok();
        let had_wayland = std::env::var("WAYLAND_DISPLAY").ok();
        std::env::remove_var("DISPLAY");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::set_var("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 54321");
        std::env::remove_var("BOOM_SSHH_ASKPASS");

        let req = ApprovalRequest {
            kind: "sign".into(),
            timestamp: 1,
            summary: vec![],
            key_fp: String::new(),
            op: "ssh-userauth".into(),
            host_label: None,
            host_fp: None,
            recent: vec![],
        };
        let res = request_approval(&req, false).await;

        std::env::remove_var("SSH_CONNECTION");
        if let Some(d) = had_display {
            std::env::set_var("DISPLAY", d);
        }
        if let Some(w) = had_wayland {
            std::env::set_var("WAYLAND_DISPLAY", w);
        }

        match &res.outcome {
            ApprovalOutcome::Unreachable { reason } => {
                assert!(reason.contains("ssh-session"), "reason was: {reason}");
                assert!(reason.contains("no-display"), "reason was: {reason}");
            }
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    #[test]
    fn test_label_to_decision() {
        // "Approve" buttons (case-insensitive verb) map to durations / once / forever.
        let forever = label_to_decision("Approve forever");
        assert!(forever.allow);
        assert_eq!(forever.ttl, None);
        assert!(!forever.once);

        let once = label_to_decision("Approve once");
        assert!(once.allow);
        assert!(once.once);

        let five = label_to_decision("Approve 5m");
        assert!(five.allow);
        assert_eq!(five.ttl, Some(std::time::Duration::from_secs(300)));

        // "Allow" is still accepted (back-compat with any callers).
        let sess = label_to_decision("Allow session");
        assert!(sess.allow);
        assert_eq!(sess.ttl, None);

        // Deny verb, or anything else (incl. empty), stays a Deny.
        assert!(!label_to_decision("Deny").allow);
        assert!(!label_to_decision("").allow);
    }

    #[test]
    fn test_parse_approval_response_legacy_and_envelope() {
        // Legacy tokens still parse.
        let d = parse_approval_response(b"allow 5m").unwrap();
        assert!(d.allow);
        assert!(!d.once);
        assert_eq!(d.ttl, Some(std::time::Duration::from_secs(300)));
        assert!(d.criteria.is_none());
        assert!(parse_approval_response(b"deny").unwrap().allow == false);
        assert!(parse_approval_response(b"allow once").unwrap().once);

        // JSON envelope.
        let env = parse_approval_response(
            br#"{"decision":"allow","ttl":"1h","criteria":{"key":"k1","op":"*","host":"unbound"}}"#,
        )
        .unwrap();
        assert!(env.allow);
        assert_eq!(env.ttl, Some(std::time::Duration::from_secs(3600)));
        let c = env.criteria.unwrap();
        assert_eq!(c.key_fp.as_deref(), Some("k1"));
        assert_eq!(c.op, None); // "*"
        assert_eq!(c.host, HostSpec::Unbound);

        let once = parse_approval_response(br#"{"decision":"once"}"#).unwrap();
        assert!(once.allow);
        assert!(once.once);

        let deny = parse_approval_response(br#"{"decision":"deny"}"#).unwrap();
        assert!(!deny.allow);

        // Unparseable output.
        assert!(parse_approval_response(b"garbage").is_none());
    }

    #[test]
    fn test_decision_token_roundtrip() {
        // Envelope -> token -> parse round-trips once and stored rules.
        for d in [
            ApprovalDecision {
                allow: true,
                ttl: None,
                once: false,
                criteria: None,
            },
            ApprovalDecision {
                allow: true,
                ttl: Some(std::time::Duration::from_secs(300)),
                once: false,
                criteria: Some(AllowCriteria {
                    key_fp: None,
                    op: Some("ssh-userauth".into()),
                    host: HostSpec::Specific("h1".into()),
                }),
            },
            ApprovalDecision {
                allow: true,
                ttl: None,
                once: true,
                criteria: None,
            },
            ApprovalDecision {
                allow: false,
                ttl: None,
                once: false,
                criteria: None,
            },
        ] {
            let parsed = parse_approval_response(decision_token(&d).as_bytes()).unwrap();
            assert_eq!(parsed.allow, d.allow);
            assert_eq!(parsed.once, d.once);
            assert_eq!(parsed.ttl, d.ttl);
            assert_eq!(parsed.criteria.map(|c| c.op), d.criteria.map(|c| c.op));
        }
    }

    #[test]
    fn test_parse_criteria_line_defaults() {
        let req = ApprovalRequest {
            kind: "sign".into(),
            timestamp: 1,
            summary: vec![],
            key_fp: "kfp".into(),
            op: "ssh-userauth".into(),
            host_label: None,
            host_fp: Some("hfp".into()),
            recent: vec![],
        };
        // Editing to "*" widens; omitted fields keep the request's values.
        let c = parse_criteria_line("key=* host=*", &req);
        assert_eq!(c.key_fp, None);
        assert_eq!(c.op.as_deref(), Some("ssh-userauth"));
        assert_eq!(c.host, HostSpec::Any);
        assert_eq!(criteria_line(&req), "key=kfp op=ssh-userauth host=hfp");
    }
}
