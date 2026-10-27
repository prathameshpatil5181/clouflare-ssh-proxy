//! Pure-Rust SSH2 host-key probe — replaces the `ssh-keyscan` dependency in
//! flows where no SSH client tooling can be assumed (the GUI ships standalone).
//!
//! Connects through a local forwarder (which bridges to the tunnel origin
//! sshd), completes key exchange, captures every host key the server offers
//! (one connection per host-key algorithm we can name, plus the server's own
//! default preference), and aborts before any user authentication.
//! Security property: the probe never sends credentials; it can only *see*
//! what sshd presents — exactly what an `ssh -v` connection shows.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PublicKeyOrCertificate};
use tokio::sync::Mutex;

use crate::error::Error;

/// One host key captured from the server, ready for pinning.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostKey {
    /// OpenSSH key-type string, e.g. `ssh-ed25519` / `ssh-rsa` / `ecdsa-sha2-nistp256`.
    pub keytype: String,
    /// Base64 key blob (the pin field after the key type).
    pub blob: String,
    /// OpenSSH-style `SHA256:…` fingerprint.
    pub fingerprint: String,
}

impl HostKey {
    /// The known_hosts line *without* the host field: `keytype blob`.
    pub fn pin_line(&self) -> String {
        format!("{} {}", self.keytype, self.blob)
    }
}

#[derive(Debug)]
enum ProbeErr {
    Ssh(russh::Error),
    Encoding(String),
}

impl From<russh::Error> for ProbeErr {
    fn from(e: russh::Error) -> Self {
        ProbeErr::Ssh(e)
    }
}

impl std::fmt::Display for ProbeErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeErr::Ssh(e) => write!(f, "ssh kex: {e}"),
            ProbeErr::Encoding(m) => write!(f, "host key encoding: {m}"),
        }
    }
}

struct Capture {
    keys: Arc<Mutex<Vec<HostKey>>>,
}

impl russh::client::Handler for Capture {
    type Error = ProbeErr;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Plain keys land here directly; certificates surface wrapped around
        // their (usefully comparable) public key — record either form.
        let pk = server_public_key.public_key();
        let openssh = pk
            .to_openssh()
            .map_err(|e| ProbeErr::Encoding(format!("cannot serialize the server key: {e}")))?;
        let mut fields = openssh.split_whitespace();
        let keytype = fields.next().unwrap_or_default().to_string();
        let blob = fields.next().unwrap_or_default().to_string();
        if keytype.is_empty() || blob.is_empty() {
            return Err(ProbeErr::Encoding(format!(
                "malformed server key: {openssh}"
            )));
        }
        let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();
        self.keys.lock().await.push(HostKey {
            keytype,
            blob,
            fingerprint,
        });
        // ALWAYS false: a probe never authenticates. The library then fails
        // the session; we treat that as the expected stop signal.
        Ok(false)
    }
}

/// Capture the host keys `addr` presents (`addr` = a local forwarder bound to
/// `127.0.0.1` bridging to the tunnel origin sshd). Attempts: the server's
/// default preference first (its primary key), then explicit preferences for
/// the key types OpenSSH servers commonly advertise. Dedupes by fingerprint.
pub async fn probe_host_keys(addr: std::net::SocketAddr) -> Result<Vec<HostKey>, Error> {
    let explicit: [Vec<Algorithm>; 3] = [
        vec![Algorithm::Ed25519],
        vec![Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }],
        vec![Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        }],
    ];
    let mut attempts: Vec<Option<Vec<Algorithm>>> = vec![None];
    attempts.extend(explicit.into_iter().map(Some));

    let keys = Arc::new(Mutex::new(Vec::<HostKey>::new()));
    for pref in attempts {
        let config = russh::client::Config {
            inactivity_timeout: Some(Duration::from_secs(12)),
            preferred: {
                let mut p = russh::client::Config::default().preferred;
                if let Some(names) = pref {
                    p.key = Cow::Owned(names);
                }
                p
            },
            ..Default::default()
        };
        let handler = Capture { keys: keys.clone() };
        let _ = tokio::time::timeout(
            Duration::from_secs(30),
            russh::client::connect(Arc::new(config), addr, handler),
        )
        .await;
        // Both Ok and Err are fine: Err is our own `Ok(false)` rejection or a
        // plain connection failure for ala unsupported algorithm attempt.
    }

    let captured = keys.lock().await.clone();
    if captured.is_empty() {
        return Err(Error::WsSetup(
            "host-key probe captured no keys (is the tunnel up and the origin sshd \
             running?)"
                .to_string(),
        ));
    }
    // Dedupe by fingerprint, preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    Ok(captured
        .into_iter()
        .filter(|k| seen.insert(k.fingerprint.clone()))
        .collect())
}
