use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::KeyLog;

/// Secrets captured from the TLS 1.3 key schedule via the KeyLog interface.
///
/// The host uses these to decrypt encrypted handshake records locally so it
/// can read CertificateVerify and compute transcript hashes.
/// None of these secrets are passed to the SP1 guest — the guest re-derives
/// everything from scratch using only `client_ecdh_private`.
#[derive(Default, Clone)]
pub struct CapturedSecrets {
    /// Derives the server handshake write key used to decrypt
    /// EncryptedExtensions, Certificate, CertificateVerify, Finished.
    pub server_hs_traffic_secret: Option<Vec<u8>>,

    /// Available for cross-checking key derivation during development.
    /// Not used in production witness building.
    pub server_app_traffic_secret: Option<Vec<u8>>,
}

/// A `KeyLog` implementation that captures the TLS 1.3 traffic secrets
/// emitted by rustls during the handshake key schedule.
pub struct CapturingKeyLog {
    pub secrets: Arc<Mutex<CapturedSecrets>>,
}

impl CapturingKeyLog {
    pub fn new() -> (Self, Arc<Mutex<CapturedSecrets>>) {
        let secrets = Arc::new(Mutex::new(CapturedSecrets::default()));
        (
            Self {
                secrets: secrets.clone(),
            },
            secrets,
        )
    }
}

impl fmt::Debug for CapturingKeyLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapturingKeyLog")
    }
}

impl KeyLog for CapturingKeyLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        let mut s = self.secrets.lock().unwrap();
        match label {
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                s.server_hs_traffic_secret = Some(secret.to_vec());
            }
            "SERVER_TRAFFIC_SECRET_0" => {
                s.server_app_traffic_secret = Some(secret.to_vec());
            }
            _ => {}
        }
    }

    fn will_log(&self, label: &str) -> bool {
        matches!(
            label,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" | "SERVER_TRAFFIC_SECRET_0"
        )
    }
}
