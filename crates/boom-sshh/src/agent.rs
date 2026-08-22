use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

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
#[allow(dead_code)]
struct SessionBindingInfo {
    host_fp: String,
    session_id_hex: String,
    is_forwarding: bool,
    verified: bool,
}

#[derive(Clone)]
pub struct HistoryAgent {
    keys: Arc<Mutex<Vec<StoredKey>>>,
    histfile: Arc<Mutex<File>>,
    /// Set when a `session-bind@openssh.com` is accepted on this connection.
    session_binding: Option<SessionBindingInfo>,
    /// PID/UID of the process on the other end of the agent socket.
    peer: Option<(u32, u32)>,
}

impl HistoryAgent {
    pub fn new(histfile: File) -> Self {
        Self {
            keys: Arc::new(Mutex::new(Vec::new())),
            histfile: Arc::new(Mutex::new(histfile)),
            session_binding: None,
            peer: None,
        }
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

        if !bound {
            let summary = vec![format!("key: {key_fp}"), format!("peer: {peer}")];
            let req = ApprovalRequest {
                kind: "sign".to_string(),
                timestamp: now_secs(),
                summary,
            };
            let allowed = request_approval(&req).await;
            self.write_audit(&format!(
                "SIGN key={key_fp} peer={peer} bound=0 decision={}",
                if allowed { "allow" } else { "deny" }
            ));
            if !allowed {
                return Err(AgentError::other(std::io::Error::other(
                    "signing denied by approver",
                )));
            }
        } else {
            self.write_audit(&format!("SIGN key={key_fp} peer={peer} bound=1 decision=allow"));
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
            };
            let allowed = request_approval(&req).await;
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

                let ts = now_secs();
                let bind_suffix = match &self.session_binding {
                    Some(b) => format!(" session={}", b.session_id_hex),
                    None => String::new(),
                };
                let line = format!("#{ts} {contents}{bind_suffix}\n");

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
                };
                let allowed = request_approval(&req).await;
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
}
