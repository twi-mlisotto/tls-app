use serde::{Deserialize, Serialize};

/// The full TLS 1.3 witness passed from host → guest via SP1 stdin.
///
/// The guest uses this to cryptographically verify the entire trust chain:
///   ECDH shared secret → HKDF key schedule → AES-GCM decryption → HTTP body
/// and independently verify the server's certificate chain + CertificateVerify
/// before trusting a single byte of the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsWitness {
    /// Client ephemeral X25519 private key (32 bytes).
    pub client_ecdh_private: [u8; 32],

    /// Server ephemeral X25519 public key from ServerHello key_share (32 bytes).
    pub server_ecdh_public: [u8; 32],

    /// DER-encoded certificate chain: leaf first, then intermediates.
    pub cert_chain_der: Vec<Vec<u8>>,

    /// Raw CertificateVerify handshake message body (SignatureScheme + sig).
    pub cert_verify_msg: Vec<u8>,

    /// Raw handshake message bytes in transcript order, each including the
    /// 4-byte header (type + 3-byte length):
    ///   [0] ClientHello
    ///   [1] ServerHello
    ///   [2] EncryptedExtensions
    ///   [3] Certificate
    ///   [4] CertificateVerify
    ///   [5] ServerFinished
    /// The guest computes all transcript hashes from these bytes.
    pub handshake_messages: Vec<Vec<u8>>,

    /// Encrypted TLS 1.3 application data records (full 5-byte header + ciphertext).
    pub encrypted_app_records: Vec<Vec<u8>>,

    /// Server Finished handshake message body (HMAC verify data).
    pub server_finished_body: Vec<u8>,
}

/// What the guest commits as public output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicClaim {
    /// The server hostname that was verified.
    pub host: String,

    /// The JSON Pointer that was checked (e.g. "/data/amount").
    pub field: String,

    /// The threshold value.
    pub threshold: f64,

    /// The actual field value extracted from the verified response.
    pub value: f64,
}
