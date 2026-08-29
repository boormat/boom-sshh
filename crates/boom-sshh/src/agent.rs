use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, Extension, Identity, KeyConstraint, PrivateCredential,
    RemoveIdentity, SignRequest,
};
use ssh_agent_lib::proto::extension::constraint::RestrictDestination;
use ssh_agent_lib::proto::extension::message::{QueryResponse, SessionBind};
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
use tokio::net::UnixListener;

use crate::approval::{request_approval, ApprovalRequest};

#[derive(Clone)]
struct StoredKey {
    pubkey: PublicKey,
    privkey: PrivateKey,
    comment: String,
    dest_constraints: Option<RestrictDestination>,
}

#[derive(Clone)]
struct LastCommand {
    command: String,
    seen: Instant,
}

#[derive(Clone)]
#[allow(dead_code)]
struct SessionBindingInfo {
    host_fp: String,
    session_id_hex: String,
    is_forwarding: bool,
    verified: bool,
}

/// Classification of what a sign request is signing, inferred from the bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
enum Op {
    GitCommit,
    GitTag,
    SshUserAuth,
    Unknown,
}

impl Op {
    fn as_str(&self) -> &'static str {
        match self {
            Op::GitCommit => "git-commit",
            Op::GitTag => "git-tag",
            Op::SshUserAuth => "ssh-userauth",
            Op::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
enum Action {
    Allow,
    Deny,
}

/// A single in-memory approval rule. `None` for a matcher field means "any".
/// `host_fp: Some(None)` matches only unbound (no destination) signs.
struct Rule {
    key_fp: Option<String>,
    op: Option<Op>,
    host_fp: Option<Option<String>>,
    action: Action,
    /// `None` = valid until the agent exits (session-scoped).
    expires_at: Option<Instant>,
}

impl Rule {
    /// Higher = more specific match (fewer `None` matchers).
    fn specificity(&self) -> usize {
        self.key_fp.is_some() as usize + self.op.is_some() as usize + self.host_fp.is_some() as usize
    }
}

/// One recently logged command on this session, tagged with the bound host so
/// sign prompts can show host-scoped context. Display only — never authorizes.
#[derive(Clone)]
struct RecentEntry {
    at: Instant,
    command: String,
    host_fp: Option<String>,
}

/// Context used to evaluate a sign request against the policy.
struct SignContext {
    key_fp: String,
    op: Op,
    host_fp: Option<String>,
}

#[derive(Clone)]
pub struct HistoryAgent {
    keys: Arc<Mutex<Vec<StoredKey>>>,
    histfile: Arc<Mutex<File>>,
    /// Set when a `session-bind@openssh.com` is accepted on this connection.
    session_binding: Option<SessionBindingInfo>,
    /// PID/UID of the process on the other end of the agent socket.
    peer: Option<(u32, u32)>,
    /// Last command per PID for dedup (24h eviction).
    last_commands: Arc<Mutex<HashMap<u32, LastCommand>>>,
    /// In-memory approval policy, shared across all sessions.
    policy: Arc<Mutex<Vec<Rule>>>,
    /// Recently logged commands for this session (display context only).
    recent: VecDeque<RecentEntry>,
    /// Hostname captured from the first HISTORY line of this session.
    host_label: Option<String>,
}

impl HistoryAgent {
    pub fn new(histfile: File) -> Self {
        // Default policy: git commit/tag signing is allowed without a prompt.
        // It is local (no remote destination) and low risk — equivalent to a
        // stock ssh-agent that holds the key. ssh-userauth signs still require
        // an explicit, time-bounded approval (stored on first use).
        let mut policy = Vec::new();
        for op in [Op::GitCommit, Op::GitTag] {
            policy.push(Rule {
                key_fp: None,
                op: Some(op),
                host_fp: None,
                action: Action::Allow,
                expires_at: None,
            });
        }

        Self {
            keys: Arc::new(Mutex::new(Vec::new())),
            histfile: Arc::new(Mutex::new(histfile)),
            session_binding: None,
            peer: None,
            last_commands: Arc::new(Mutex::new(HashMap::new())),
            policy: Arc::new(Mutex::new(policy)),
            recent: VecDeque::new(),
            host_label: None,
        }
    }

    /// Classify a sign request by inspecting the raw bytes being signed.
    ///
    /// Git commit objects start with `tree `, tag objects with `object `;
    /// OpenSSH's `ssh-keygen -Y sign` wraps the data in an SSH signature
    /// envelope (`"SSHSIG"` + namespace `"git"`); we detect that too.
    /// An ssh userauth signature contains the `"ssh-connection"` service name
    /// string somewhere in the blob. Anything else is `Unknown` (prompts)
    /// rather than being silently allowed.
    fn classify_op(data: &[u8]) -> Op {
        if data.starts_with(b"tree ") {
            Op::GitCommit
        } else if data.starts_with(b"object ") {
            Op::GitTag
        } else if data.starts_with(b"SSHSIG")
            && data.len() > 13
            && &data[6..13] == b"\x00\x00\x00\x03git"
        {
            // SSH signature envelope with namespace "git" (git commit/tag)
            Op::GitCommit
        } else if data.windows(14).any(|w| w == b"ssh-connection") {
            Op::SshUserAuth
        } else {
            Op::Unknown
        }
    }

    /// Evaluate the context against the in-memory policy. Expired rules are
    /// dropped. Returns `None` when no rule matches (caller must prompt).
    fn evaluate(&self, ctx: &SignContext) -> Option<Action> {
        let mut policy = self.policy.lock().unwrap();
        let now = Instant::now();
        policy.retain(|r| r.expires_at.map_or(true, |e| e > now));

        let mut best: Option<(usize, Action)> = None;
        for r in policy.iter() {
            if let Some(k) = &r.key_fp {
                if k != &ctx.key_fp {
                    continue;
                }
            }
            if let Some(o) = r.op {
                if o != ctx.op {
                    continue;
                }
            }
            let host_ok = match &r.host_fp {
                Some(Some(h)) => ctx.host_fp.as_ref().map_or(false, |c| c == h),
                Some(None) => ctx.host_fp.is_none(),
                None => true,
            };
            if !host_ok {
                continue;
            }
            let spec = r.specificity();
            match best {
                Some((s, _)) if s >= spec => {}
                _ => best = Some((spec, r.action)),
            }
        }
        best.map(|(_, a)| a)
    }

    fn find_key(&self, pubkey: &PublicKey) -> Option<StoredKey> {
        let keys = self.keys.lock().unwrap();
        keys.iter().find(|k| &k.pubkey == pubkey).cloned()
    }

    fn insert_key(
        &self,
        pubkey: PublicKey,
        privkey: PrivateKey,
        comment: String,
        dest_constraints: Option<RestrictDestination>,
    ) {
        let mut keys = self.keys.lock().unwrap();
        if let Some(pos) = keys.iter().position(|k| k.pubkey == pubkey) {
            keys[pos].dest_constraints = dest_constraints.clone();
        } else {
            keys.push(StoredKey {
                pubkey,
                privkey,
                comment,
                dest_constraints,
            });
        }
    }

    fn write_audit(&self, event: &str) {
        let ts = now_secs();
        let line = format!("#{ts} {event}\n");
        if let Ok(mut f) = self.histfile.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn remove_key(&self, pubkey: &PublicKey) -> bool {
        let mut keys = self.keys.lock().unwrap();
        if let Some(pos) = keys.iter().position(|k| &k.pubkey == pubkey) {
            keys.remove(pos);
            true
        } else {
            false
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fp_of_keydata(kd: &KeyData) -> String {
    kd.fingerprint(HashAlg::Sha256).to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[async_trait]
impl Session for HistoryAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let keys = self.keys.lock().unwrap();
        Ok(keys
            .iter()
            .map(|k| Identity {
                credential: k.pubkey.key_data().clone().into(),
                comment: k.comment.clone(),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let pubkey: PublicKey = request.credential.key_data().clone().into();
        let identity = self
            .find_key(&pubkey)
            .ok_or_else(|| AgentError::IO(std::io::Error::other("identity not found")))?;

        let key_fp = fp_of_keydata(pubkey.key_data());
        let peer = self
            .peer
            .map(|(p, u)| format!("{p}/{u}"))
            .unwrap_or_else(|| "?".to_string());
        let bound = self.session_binding.is_some();
        let op = Self::classify_op(&request.data);
        let host_fp = self.session_binding.as_ref().map(|b| b.host_fp.clone());
        let session_hex = self
            .session_binding
            .as_ref()
            .map(|b| b.session_id_hex.clone())
            .unwrap_or_default();
        let host_display = self
            .host_label
            .clone()
            .or_else(|| host_fp.clone())
            .unwrap_or_else(|| "?".to_string());

        let ctx = SignContext {
            key_fp: key_fp.clone(),
            op,
            host_fp: host_fp.clone(),
        };

        // Recent, host-scoped commands for display context (no authorization).
        let recent: Vec<String> = {
            let now = Instant::now();
            let mut v: Vec<String> = self
                .recent
                .iter()
                .filter(|e| host_fp.as_ref().map_or(true, |h| e.host_fp.as_ref() == Some(h)))
                .filter(|e| now.duration_since(e.at) < Duration::from_secs(30))
                .map(|e| e.command.clone())
                .collect();
            v.truncate(3);
            v
        };

        // Evaluate the in-memory policy. No match → prompt; unreachable approver
        // fails closed (deny). An explicit allow stores a time-bounded rule so
        // repeated signs in the same window are silent.
        let decision = match self.evaluate(&ctx) {
            Some(Action::Allow) => true,
            Some(Action::Deny) => false,
            None => {
                let req = ApprovalRequest {
                    kind: "sign".to_string(),
                    timestamp: now_secs(),
                    summary: vec![
                        format!("key: {key_fp}"),
                        format!("op: {}", op.as_str()),
                        format!("host: {host_display}"),
                    ],
                    key_fp: key_fp.clone(),
                    op: op.as_str().to_string(),
                    host_label: self.host_label.clone(),
                    host_fp: host_fp.clone(),
                    recent: recent.clone(),
                };
                match request_approval(&req).await {
                    Some(d) if d.allow => {
                        let rule = Rule {
                            key_fp: Some(ctx.key_fp.clone()),
                            op: Some(ctx.op),
                            host_fp: Some(ctx.host_fp.clone()),
                            action: Action::Allow,
                            expires_at: d.ttl.map(|t| Instant::now() + t),
                        };
                        self.policy.lock().unwrap().push(rule);
                        true
                    }
                    Some(_) => false,
                    None => false,
                }
            }
        };

        self.write_audit(&format!(
            "SIGN key={key_fp} peer={peer} bound={} op={} host={} session={} decision={}",
            bound as u8,
            op.as_str(),
            host_display,
            session_hex,
            if decision { "allow" } else { "deny" }
        ));

        if !decision {
            return Err(AgentError::other(std::io::Error::other(
                "signing denied by policy",
            )));
        }

        match identity.privkey.key_data() {
            KeypairData::Ed25519(key) => {
                use ed25519_dalek::{Signer, SigningKey};

                let signing_key = SigningKey::from_bytes(&key.private.to_bytes());
                let sig = signing_key.sign(&request.data);
                Ok(Signature::new(
                    ssh_key::Algorithm::Ed25519,
                    sig.to_bytes().to_vec(),
                )
                .map_err(AgentError::other)?)
            }
            KeypairData::Rsa(key) => {
                let private_key = rsa::RsaPrivateKey::from_components(
                    rsa::BigUint::try_from(&key.public.n).map_err(AgentError::other)?,
                    rsa::BigUint::try_from(&key.public.e).map_err(AgentError::other)?,
                    rsa::BigUint::try_from(&key.private.d).map_err(AgentError::other)?,
                    vec![
                        rsa::BigUint::try_from(&key.private.p).map_err(AgentError::other)?,
                        rsa::BigUint::try_from(&key.private.q).map_err(AgentError::other)?,
                    ],
                )
                .map_err(AgentError::other)?;

                use rsa::pkcs1v15::SigningKey;
                use rsa::sha2::{Sha256, Sha512};
                use rsa::signature::{RandomizedSigner, SignatureEncoding};
                use sha1::Sha1;

                let mut rng = rand::thread_rng();
                let data = &request.data;

                let (algorithm, signature) = if request.flags & 4 != 0 {
                    (
                        "rsa-sha2-512",
                        SigningKey::<Sha512>::new(private_key).sign_with_rng(&mut rng, data),
                    )
                } else if request.flags & 2 != 0 {
                    (
                        "rsa-sha2-256",
                        SigningKey::<Sha256>::new(private_key).sign_with_rng(&mut rng, data),
                    )
                } else {
                    (
                        "ssh-rsa",
                        SigningKey::<Sha1>::new_unprefixed(private_key).sign_with_rng(&mut rng, data),
                    )
                };

                Ok(Signature::new(
                    ssh_key::Algorithm::new(algorithm).map_err(AgentError::other)?,
                    signature.to_bytes().to_vec(),
                )
                .map_err(AgentError::other)?)
            }
            _ => Err(AgentError::IO(std::io::Error::other(
                "unsupported key type",
            ))),
        }
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        if let PrivateCredential::Key { privkey, comment } = identity.credential {
            let privkey = PrivateKey::try_from(privkey).map_err(AgentError::other)?;
            let pubkey = PublicKey::from(&privkey);
            self.insert_key(pubkey, privkey, comment, None);
        }
        Ok(())
    }

    async fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        let (kp, comment) = match &identity.identity.credential {
            PrivateCredential::Key { privkey, comment } => (privkey.clone(), comment.clone()),
            _ => return self.add_identity(identity.identity).await,
        };
        let privkey = PrivateKey::try_from(kp).map_err(AgentError::other)?;
        let pubkey = PublicKey::from(&privkey);
        let key_fp = fp_of_keydata(pubkey.key_data());

        // Look for an OpenSSH destination-constraint registration.
        let mut dest: Option<RestrictDestination> = None;
        for c in &identity.constraints {
            if let KeyConstraint::Extension(ext) = c {
                if let Ok(Some(rd)) = ext.parse_key_constraint::<RestrictDestination>() {
                    dest = Some(rd);
                    break;
                }
            }
        }

        if let Some(rd) = &dest {
            let mut summary = vec![format!("key: {key_fp}")];
            for dc in &rd.constraints {
                summary.push(format!(
                    "destination: {}@{} -> {}@{}",
                    dc.from.username, dc.from.hostname, dc.to.username, dc.to.hostname
                ));
            }
            let req = ApprovalRequest {
                kind: "dest-constraint".to_string(),
                timestamp: now_secs(),
                summary,
                key_fp: key_fp.clone(),
                op: String::new(),
                host_label: None,
                host_fp: None,
                recent: Vec::new(),
            };
            let allowed = matches!(request_approval(&req).await, Some(d) if d.allow);
            self.write_audit(&format!(
                "DEST-CONSTRAINT key={key_fp} constraints={} decision={}",
                rd.constraints.len(),
                if allowed { "allow" } else { "deny" }
            ));
            if !allowed {
                return Err(AgentError::other(std::io::Error::other(
                    "destination constraint registration rejected",
                )));
            }
        }

        self.insert_key(pubkey, privkey, comment, dest);
        Ok(())
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        let pubkey: PublicKey = identity.credential.key_data().clone().into();
        self.remove_key(&pubkey);
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.keys.lock().unwrap().clear();
        Ok(())
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        match extension.name.as_str() {
            "HISTORY" => {
                let contents = String::from_utf8(extension.details.into_bytes())
                    .map_err(|e| AgentError::other(e))?;

                // Dedup: use parent PID from payload (3rd field: "hostname uid pid command")
                if let Some(parent_pid) = contents.split_whitespace().nth(2)
                    .and_then(|s| s.parse::<u32>().ok())
                {
                    let mut last = self.last_commands.lock().unwrap();
                    let now = Instant::now();

                    // Evict entries older than 24h
                    last.retain(|_, v| now.duration_since(v.seen) < Duration::from_secs(86400));

                    // Skip if same command from same shell PID
                    if let Some(entry) = last.get(&parent_pid) {
                        if entry.command == contents {
                            return Ok(None);
                        }
                    }
                    last.insert(parent_pid, LastCommand { command: contents.clone(), seen: now });
                }

                let ts = now_secs();
                let bind_suffix = match &self.session_binding {
                    Some(b) => format!(" session={}", b.session_id_hex),
                    None => String::new(),
                };
                let line = format!("#{ts} {contents}{bind_suffix}\n");

                // Keep a short, host-tagged ring of recent commands for sign
                // prompt context (display only; never used to authorize).
                let host_fp = self.session_binding.as_ref().map(|b| b.host_fp.clone());
                self.recent.push_back(RecentEntry {
                    at: Instant::now(),
                    command: contents.clone(),
                    host_fp,
                });
                if self.recent.len() > 20 {
                    self.recent.pop_front();
                }
                if self.host_label.is_none() {
                    let label = contents.split_whitespace().next().unwrap_or("").to_string();
                    if !label.is_empty() {
                        self.host_label = Some(label);
                    }
                }

                let mut histfile = self.histfile.lock().unwrap();
                histfile
                    .write_all(line.as_bytes())
                    .map_err(AgentError::other)?;

                Ok(None)
            }
            "session-bind@openssh.com" => {
                let bind = match extension.parse_message::<SessionBind>() {
                    Ok(Some(b)) => b,
                    _ => return Err(AgentError::ExtensionFailure),
                };

                let verified = bind.verify_signature().is_ok();
                let host_fp = fp_of_keydata(&bind.host_key);
                let session_hex = hex_encode(&bind.session_id);

                let summary = vec![
                    format!("host key fingerprint: {host_fp}"),
                    format!("session id: {session_hex}"),
                    format!("forwarding: {}", bind.is_forwarding),
                    format!("signature verified: {verified}"),
                ];
                let req = ApprovalRequest {
                    kind: "session-bind".to_string(),
                    timestamp: now_secs(),
                    summary,
                    key_fp: String::new(),
                    op: String::new(),
                    host_label: None,
                    host_fp: Some(host_fp.clone()),
                    recent: Vec::new(),
                };
                let allowed = matches!(request_approval(&req).await, Some(d) if d.allow);
                self.write_audit(&format!(
                    "SESSION-BIND host={host_fp} session={session_hex} forwarding={} verified={verified} decision={}",
                    bind.is_forwarding as u8,
                    if allowed { "allow" } else { "deny" }
                ));

                if allowed {
                    self.session_binding = Some(SessionBindingInfo {
                        host_fp,
                        session_id_hex: session_hex,
                        is_forwarding: bind.is_forwarding,
                        verified,
                    });
                    Ok(None)
                } else {
                    Err(AgentError::ExtensionFailure)
                }
            }
            "query" => {
                let supported = vec![
                    "session-bind@openssh.com".to_string(),
                    "restrict-destination-v00@openssh.com".to_string(),
                    "HISTORY".to_string(),
                    "query".to_string(),
                ];
                let ext = Extension::new_message(QueryResponse { extensions: supported })
                    .map_err(AgentError::other)?;
                Ok(Some(ext))
            }
            _ => Err(AgentError::ExtensionFailure),
        }
    }
}

/// Wrapper that captures the peer credentials of each incoming connection
/// before handing a cloned [`HistoryAgent`] to the connection handler.
pub struct ListeningAgent {
    inner: HistoryAgent,
}

impl ListeningAgent {
    pub fn new(inner: HistoryAgent) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl Agent<UnixListener> for ListeningAgent {
    fn new_session(&mut self, socket: &tokio::net::UnixStream) -> impl Session {
        let mut agent = self.inner.clone();
        if let Ok(cred) = socket.peer_cred() {
            if let Some(pid) = cred.pid() {
                agent.peer = Some((pid as u32, cred.uid() as u32));
            }
        }
        agent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use ssh_agent_lib::ssh_encoding::Decode;

    fn test_histfile() -> (File, PathBuf) {
        let dir = std::env::temp_dir().join("boom-sshh-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(format!("test-{}-{}", std::process::id(), rand::random::<u32>()));
        let _ = fs::remove_file(&path);
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        (f, path)
    }

    fn session_bind_bytes() -> Vec<u8> {
        vec![
            0, 0, 0, 51, 0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32,
            177, 185, 198, 92, 165, 45, 127, 95, 202, 195, 226, 63, 6, 115, 10, 104, 18, 137, 172,
            240, 153, 154, 174, 74, 83, 7, 1, 204, 14, 177, 153, 40, 0, 0, 0, 32, 138, 165, 196,
            144, 149, 107, 183, 188, 222, 182, 34, 173, 59, 118, 9, 35, 186, 147, 114, 114, 50,
            106, 41, 182, 196, 119, 226, 82, 233, 148, 236, 135, 0, 0, 0, 83, 0, 0, 0, 11, 115,
            115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 64, 95, 212, 52, 189, 8, 162, 17,
            3, 15, 218, 2, 4, 136, 7, 47, 57, 121, 6, 194, 165, 221, 27, 175, 241, 6, 57, 84, 141,
            77, 55, 235, 9, 77, 160, 32, 76, 11, 227, 240, 235, 122, 178, 80, 133, 183, 91, 89, 89,
            142, 115, 145, 15, 78, 112, 139, 28, 201, 8, 197, 222, 117, 141, 88, 5, 0,
        ]
    }

    #[tokio::test]
    async fn test_extension_history() {
        let (f, path) = test_histfile();
        let mut agent = HistoryAgent::new(f);

        let ext = Extension {
            name: "HISTORY".into(),
            details: b"testhost 1000 1234   42  ls -la".to_vec().into(),
        };

        let result = agent.extension(ext).await.unwrap();
        assert!(result.is_none());

        let mut content = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.starts_with("#"));
        assert!(content.contains("testhost 1000 1234   42  ls -la"));
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_extension_unknown() {
        let (f, path) = test_histfile();
        let mut agent = HistoryAgent::new(f);

        let ext = Extension {
            name: "UNKNOWN".into(),
            details: b"data".to_vec().into(),
        };

        let result = agent.extension(ext).await;
        assert!(result.is_err());
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_extension_special_chars() {
        let (f, path) = test_histfile();
        let mut agent = HistoryAgent::new(f);

        let ext = Extension {
            name: "HISTORY".into(),
            details: b"host-1.example.com 1001 9999   5  echo 'hello world' && ls"
                .to_vec()
                .into(),
        };

        agent.extension(ext).await.unwrap();

        let mut content = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.contains("echo 'hello world' && ls"));
        assert!(content.contains("host-1.example.com"));
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_extension_multiple_entries() {
        let (f, path) = test_histfile();
        let mut agent = HistoryAgent::new(f);

        for i in 0..3 {
            let ext = Extension {
                name: "HISTORY".into(),
                details: format!("h 0 {i}   {i}  cmd{i}").into_bytes().into(),
            };
            agent.extension(ext).await.unwrap();
        }

        let mut content = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("cmd0"));
        assert!(lines[1].contains("cmd1"));
        assert!(lines[2].contains("cmd2"));
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_request_identities_empty() {
        let (f, path) = test_histfile();
        let mut agent = HistoryAgent::new(f);

        let ids = agent.request_identities().await.unwrap();
        assert!(ids.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_query_advertises_supported() {
        let (f, path) = test_histfile();
        let mut agent = HistoryAgent::new(f);

        let ext = Extension {
            name: "query".into(),
            details: vec![].into(),
        };
        let result = agent.extension(ext).await.unwrap();
        let resp = result.unwrap();
        assert_eq!(resp.name, "query");
        let qr = resp.parse_message::<QueryResponse>().unwrap().unwrap();
        assert!(qr
            .extensions
            .iter()
            .any(|e| e == "session-bind@openssh.com"));
        assert!(qr
            .extensions
            .iter()
            .any(|e| e == "restrict-destination-v00@openssh.com"));
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_session_bind_approval_modes() {
        let (f, path) = test_histfile();
        let mut agent = HistoryAgent::new(f);

        // 1) BOOM_SSHH_ASKPASS=true always allows (security-off workaround).
        std::env::set_var("BOOM_SSHH_ASKPASS", "true");
        let bind = SessionBind::decode(&mut session_bind_bytes().as_slice()).unwrap();
        let ext = Extension::new_message(bind).unwrap();
        let result = agent.extension(ext).await.unwrap();
        assert!(result.is_none());
        assert!(agent.session_binding.is_some());
        std::env::remove_var("BOOM_SSHH_ASKPASS");

        // 2) Explicit deny script must reject the binding.
        let script = std::env::temp_dir().join(format!("deny-{}.sh", std::process::id()));
        fs::write(&script, "#!/bin/sh\ncat >/dev/null\nprintf deny\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("BOOM_SSHH_ASKPASS", script.to_str().unwrap());

        let bind2 = SessionBind::decode(&mut session_bind_bytes().as_slice()).unwrap();
        let ext2 = Extension::new_message(bind2).unwrap();
        let result2 = agent.extension(ext2).await;
        assert!(result2.is_err());

        let mut content = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.contains("SESSION-BIND"));
        assert!(content.contains("decision=allow"));
        assert!(content.contains("decision=deny"));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&script);
        std::env::remove_var("BOOM_SSHH_ASKPASS");
    }

    #[test]
    fn test_classify_op() {
        // Git commit object begins with "tree ".
        assert_eq!(
            HistoryAgent::classify_op(b"tree 0123456789abcdef\nparent ...\nauthor ..."),
            Op::GitCommit
        );
        // Git tag object begins with "object ".
        assert_eq!(
            HistoryAgent::classify_op(b"object 0123\n type tag\n tag v1\n"),
            Op::GitTag
        );
        // OpenSSH ssh-keygen -Y sign wraps data in an SSH signature envelope:
        // string "SSHSIG" + string "git" (namespace) + ...
        let mut envelope = b"SSHSIG".to_vec();
        envelope.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // namespace len
        envelope.extend_from_slice(b"git");
        envelope.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
        assert_eq!(HistoryAgent::classify_op(&envelope), Op::GitCommit);
        // SSH userauth signature blob contains "ssh-connection" service name.
        let mut ua = Vec::with_capacity(128);
        ua.extend_from_slice(&[0x00, 0x00, 0x00, 0x40]); // session-id len=64
        ua.extend_from_slice(&[0x42; 64]);                 // session-id body
        ua.push(0x32);                                      // SSH_MSG_USERAUTH_REQUEST
        ua.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]);  // username len
        ua.extend_from_slice(b"mat");
        ua.extend_from_slice(&[0x00, 0x00, 0x00, 0x0e]);  // service len=14
        ua.extend_from_slice(b"ssh-connection");
        assert_eq!(HistoryAgent::classify_op(&ua), Op::SshUserAuth);
        // Unrecognized content is Unknown (prompts), never silently allowed.
        assert_eq!(HistoryAgent::classify_op(b"hello world"), Op::Unknown);
    }

    #[test]
    fn test_policy_default_allows_git_sign() {
        let (f, path) = test_histfile();
        let agent = HistoryAgent::new(f);

        // Git commit/tag signs are allowed by the seeded default rule.
        assert_eq!(
            agent.evaluate(&SignContext {
                key_fp: "k1".into(),
                op: Op::GitCommit,
                host_fp: None,
            }),
            Some(Action::Allow)
        );
        assert_eq!(
            agent.evaluate(&SignContext {
                key_fp: "k1".into(),
                op: Op::GitTag,
                host_fp: None,
            }),
            Some(Action::Allow)
        );
        // ssh-userauth has no rule yet → prompt (None).
        assert_eq!(
            agent.evaluate(&SignContext {
                key_fp: "k1".into(),
                op: Op::SshUserAuth,
                host_fp: Some("hostfp".into()),
            }),
            None
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_policy_specificity_and_ttl() {
        let (f, path) = test_histfile();
        let agent = HistoryAgent::new(f);

        let host = "hostfp".to_string();
        // Allow ssh-userauth to `host` for this session only (no expiry).
        agent.policy.lock().unwrap().push(Rule {
            key_fp: Some("k1".into()),
            op: Some(Op::SshUserAuth),
            host_fp: Some(Some(host.clone())),
            action: Action::Allow,
            expires_at: None,
        });

        let ctx_host = SignContext {
            key_fp: "k1".into(),
            op: Op::SshUserAuth,
            host_fp: Some(host.clone()),
        };
        let ctx_other = SignContext {
            key_fp: "k1".into(),
            op: Op::SshUserAuth,
            host_fp: Some("other".into()),
        };

        assert_eq!(agent.evaluate(&ctx_host), Some(Action::Allow));
        // A different host still has no rule → prompt.
        assert_eq!(agent.evaluate(&ctx_other), None);

        // Expired rule is dropped and no longer matches.
        {
            let mut pol = agent.policy.lock().unwrap();
            pol.push(Rule {
                key_fp: None,
                op: Some(Op::SshUserAuth),
                host_fp: None,
                action: Action::Allow,
                expires_at: Some(std::time::Instant::now() - Duration::from_secs(1)),
            });
        }
        assert_eq!(agent.evaluate(&ctx_host), Some(Action::Allow)); // still matched by session rule
        assert_eq!(agent.evaluate(&ctx_other), None); // expired catch-all dropped
        let _ = fs::remove_file(&path);
    }
}
