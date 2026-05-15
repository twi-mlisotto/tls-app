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

    /// Derives the server *application* write key — the one used to
    /// encrypt the post-handshake HTTP response.
    ///
    /// **SECURITY NOTE** — capturable from the client side because RFC 8446
    /// §7.1 derives it from `Master-Secret` and the handshake transcript:
    ///
    ///     server_application_traffic_secret_0 = HKDF-Expand-Label(
    ///         Master-Secret, "s ap traffic", transcript_hash, 32)
    ///
    /// `Master-Secret` derives from `ECDHE_shared = X25519(client_priv,
    /// server_pub)`, which the client holds. So the prover/client computes
    /// the server's application write secret on its own.
    ///
    /// Once held, this secret is sufficient to *encrypt* records that any
    /// honest verifier (including the SP1 guest) accepts as if the server
    /// had produced them. The `--forge-json` PoC in `script/src/main.rs`
    /// exploits exactly this: it captures the secret here, then re-uses it
    /// in `witness::forge_app_record` to mint a fake server response.
    ///
    /// This is the root cause of the non-repudiation gap documented in
    /// `PR_BODY.md`. A working zkTLS design needs a key-schedule structure
    /// in which the prover *cannot* derive this secret alone — see
    /// MPC-TLS / TLSNotary for the standard answer.
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
