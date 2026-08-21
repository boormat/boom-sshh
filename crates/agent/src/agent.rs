use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, Extension, Identity, PrivateCredential, RemoveIdentity,
    SignRequest,
};
use ssh_key::private::KeypairData;
use ssh_key::{PrivateKey, PublicKey, Signature};

#[derive(Clone)]
struct StoredKey {
    pubkey: PublicKey,
    privkey: PrivateKey,
    comment: String,
}

#[derive(Clone)]
pub struct HistoryAgent {
    keys: Arc<Mutex<Vec<StoredKey>>>,
    histfile: Arc<Mutex<File>>,
}

impl HistoryAgent {
    pub fn new(histfile: File) -> Self {
        Self {
            keys: Arc::new(Mutex::new(Vec::new())),
            histfile: Arc::new(Mutex::new(histfile)),
        }
    }

    fn find_key(&self, pubkey: &PublicKey) -> Option<StoredKey> {
        let keys = self.keys.lock().unwrap();
        keys.iter()
            .find(|k| &k.pubkey == pubkey)
            .cloned()
    }

    fn add_key(&self, key: StoredKey) {
        let mut keys = self.keys.lock().unwrap();
        if !keys.iter().any(|k| k.pubkey == key.pubkey) {
            keys.push(key);
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
                        SigningKey::<Sha1>::new_unprefixed(private_key)
                            .sign_with_rng(&mut rng, data),
                    )
                };

                Ok(Signature::new(
                    ssh_key::Algorithm::new(algorithm).map_err(AgentError::other)?,
                    signature.to_bytes().to_vec(),
                )
                .map_err(AgentError::other)?)
            }
            _ => Err(AgentError::IO(std::io::Error::other("unsupported key type"))),
        }
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        if let PrivateCredential::Key { privkey, comment } = identity.credential {
            let privkey = PrivateKey::try_from(privkey).map_err(AgentError::other)?;
            self.add_key(StoredKey {
                pubkey: PublicKey::from(&privkey),
                privkey,
                comment,
            });
        }
        Ok(())
    }

    async fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        self.add_identity(identity.identity).await
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

                let ts = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(AgentError::other)?
                    .as_secs();

                let line = format!("#{ts} {contents}\n");

                let mut histfile = self.histfile.lock().unwrap();
                histfile
                    .write_all(line.as_bytes())
                    .map_err(AgentError::other)?;

                Ok(None)
            }
            _ => Err(AgentError::ExtensionFailure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::path::PathBuf;

    fn test_histfile() -> (File, PathBuf) {
        let dir = std::env::temp_dir().join("ssh-agent-history-test");
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
}
