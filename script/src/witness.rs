/// TLS 1.3 record parser and handshake decryptor.
///
/// Consumes the raw inbound wire bytes captured by `CapturingStream` and the
/// `SERVER_HANDSHAKE_TRAFFIC_SECRET` from `CapturingKeyLog`, and produces
/// the `TlsWitness` that is handed to the SP1 guest for verification.
pub use sp1_https_json_shared::TlsWitness;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

// ---------------------------------------------------------------------------
// TLS record layer
// ---------------------------------------------------------------------------

const TLS_RECORD_HDR: usize = 5;

/// One raw TLS record off the wire.
#[derive(Debug, Clone)]
pub struct RawRecord {
    pub content_type: u8,
    pub legacy_version: u16,
    pub payload: Vec<u8>,
}

/// Parse `bytes` into a sequence of TLS records.  Returns an error if the
/// bytes are truncated or malformed.
pub fn parse_records(bytes: &[u8]) -> anyhow::Result<Vec<RawRecord>> {
    let mut records = Vec::new();
    let mut pos = 0;

    while pos < bytes.len() {
        if bytes.len() - pos < TLS_RECORD_HDR {
            anyhow::bail!("truncated TLS record header at offset {pos}");
        }
        let ct = bytes[pos];
        let version = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]);
        let length = u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]]) as usize;
        pos += TLS_RECORD_HDR;

        if bytes.len() - pos < length {
            anyhow::bail!(
                "truncated TLS record body: need {length} bytes, have {}",
                bytes.len() - pos
            );
        }

        records.push(RawRecord {
            content_type: ct,
            legacy_version: version,
            payload: bytes[pos..pos + length].to_vec(),
        });
        pos += length;
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// TLS 1.3 HKDF helpers (RFC 8446 §7.1)
// ---------------------------------------------------------------------------

/// HKDF-Expand-Label as defined in RFC 8446.
fn hkdf_expand_label(prk: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    // HkdfLabel = length(2) || "tls13 " || label || context
    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::from_prk(prk).expect("valid PRK");
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("HKDF-Expand-Label");
    out
}

/// Derive AES-128-GCM key (16 bytes) and IV (12 bytes) from a traffic secret.
fn derive_key_iv(traffic_secret: &[u8]) -> ([u8; 16], [u8; 12]) {
    let key_bytes = hkdf_expand_label(traffic_secret, "key", &[], 16);
    let iv_bytes = hkdf_expand_label(traffic_secret, "iv", &[], 12);

    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&key_bytes);
    iv.copy_from_slice(&iv_bytes);
    (key, iv)
}

/// XOR the per-record nonce: RFC 8446 §5.3 — XOR `iv` with the 64-bit
/// big-endian sequence number placed in the rightmost 8 bytes.
fn per_record_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for (i, b) in seq_bytes.iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    nonce
}

// ---------------------------------------------------------------------------
// Encrypted record decryption
// ---------------------------------------------------------------------------

/// Decrypt one TLS 1.3 `ApplicationData` record (content_type = 23).
///
/// `record` is the 5-byte header + ciphertext (the full wire bytes).
/// The last byte of the decrypted plaintext is the real content type;
/// strip it and return `(plaintext, inner_content_type)`.
fn decrypt_record(
    key: &[u8; 16],
    iv: &[u8; 12],
    seq: u64,
    record: &RawRecord,
) -> anyhow::Result<(Vec<u8>, u8)> {
    let nonce_bytes = per_record_nonce(iv, seq);
    let nonce = Nonce::from(nonce_bytes);

    // AAD = the 5-byte TLS record header of the *outer* ApplicationData record.
    let aad = {
        let mut h = [0u8; 5];
        h[0] = record.content_type; // 0x17
        h[1..3].copy_from_slice(&record.legacy_version.to_be_bytes());
        h[3..5].copy_from_slice(&(record.payload.len() as u16).to_be_bytes());
        h
    };

    let cipher = Aes128Gcm::new(key.into());
    let mut buf = record.payload.clone();
    let tag_start = buf.len() - 16;

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&buf[tag_start..]);
    buf.truncate(tag_start);

    cipher
        .decrypt_in_place_detached(&nonce, &aad, &mut buf, &tag.into())
        .map_err(|_| anyhow::anyhow!("AES-GCM authentication failed (seq={seq})"))?;

    // Strip the inner content-type byte (last byte of plaintext).
    let inner_ct = *buf
        .last()
        .ok_or_else(|| anyhow::anyhow!("empty decrypted record"))?;
    buf.pop();

    Ok((buf, inner_ct))
}

// ---------------------------------------------------------------------------
// Handshake message parsing
// ---------------------------------------------------------------------------

const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

/// A parsed TLS 1.3 handshake message (type + raw body bytes).
#[derive(Debug, Clone)]
pub struct HandshakeMsg {
    pub msg_type: u8,
    pub body: Vec<u8>,
}

/// Parse handshake messages from a flat byte slice.
/// Handshake header: 1 byte type + 3 bytes length.
fn parse_handshake_messages(data: &[u8]) -> anyhow::Result<Vec<HandshakeMsg>> {
    let mut msgs = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        if data.len() - pos < 4 {
            anyhow::bail!("truncated handshake header at offset {pos}");
        }
        let msg_type = data[pos];
        let length = u32::from_be_bytes([0, data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if data.len() - pos < length {
            anyhow::bail!(
                "truncated handshake body: need {length}, have {}",
                data.len() - pos
            );
        }

        msgs.push(HandshakeMsg {
            msg_type,
            body: data[pos..pos + length].to_vec(),
        });
        pos += length;
    }

    Ok(msgs)
}

/// Parse DER certificates from a TLS 1.3 Certificate message body.
///
/// TLS 1.3 Certificate body layout (RFC 8446 §4.4.2):
///   certificate_request_context (1 byte length + data)
///   certificate_list (3-byte length + entries)
///     each entry: cert_data (3-byte length + DER) + extensions (2-byte length + data)
fn parse_cert_message(body: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut pos = 0;

    // Skip certificate_request_context.
    if pos >= body.len() {
        anyhow::bail!("empty Certificate message");
    }
    let ctx_len = body[pos] as usize;
    pos += 1 + ctx_len;

    // certificate_list length (3 bytes).
    if body.len() - pos < 3 {
        anyhow::bail!("truncated certificate_list length");
    }
    let list_len = u32::from_be_bytes([0, body[pos], body[pos + 1], body[pos + 2]]) as usize;
    pos += 3;

    let list_end = pos + list_len;
    let mut certs = Vec::new();

    while pos < list_end {
        if list_end - pos < 3 {
            anyhow::bail!("truncated cert_data length");
        }
        let cert_len = u32::from_be_bytes([0, body[pos], body[pos + 1], body[pos + 2]]) as usize;
        pos += 3;

        if list_end - pos < cert_len {
            anyhow::bail!("truncated cert_data");
        }
        certs.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;

        // Skip extensions (2-byte length).
        if list_end - pos < 2 {
            anyhow::bail!("truncated cert extensions length");
        }
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2 + ext_len;
    }

    Ok(certs)
}

// ---------------------------------------------------------------------------
// Main assembly function
// ---------------------------------------------------------------------------

/// Assemble a `TlsWitness` from the captured wire bytes and keys.
pub fn assemble_witness(
    inbound: &[u8],
    outbound: &[u8],
    client_ecdh_private: [u8; 32],
    server_ecdh_public: [u8; 32],
    server_hs_traffic_secret: &[u8],
) -> anyhow::Result<TlsWitness> {
    let in_records = parse_records(inbound)?;
    let out_records = parse_records(outbound)?;

    let mut hs_seq: u64 = 0;
    let (hs_key, hs_iv) = derive_key_iv(server_hs_traffic_secret);

    // Ordered handshake messages [CH, SH, EE, Cert, CertVerify, Finished].
    // Each entry is the raw 4-byte header + body (the transcript input).
    let mut handshake_messages: Vec<Vec<u8>> = Vec::new();

    // ClientHello — first plaintext outbound handshake record.
    let ch_payload = out_records
        .iter()
        .find(|r| r.content_type == 22)
        .ok_or_else(|| anyhow::anyhow!("ClientHello not found"))?
        .payload
        .clone();
    handshake_messages.push(ch_payload);

    // ServerHello — first plaintext inbound handshake record.
    let sh_payload = in_records
        .iter()
        .find(|r| r.content_type == 22)
        .ok_or_else(|| anyhow::anyhow!("ServerHello not found"))?
        .payload
        .clone();
    handshake_messages.push(sh_payload);

    let mut cert_chain_der: Option<Vec<Vec<u8>>> = None;
    let mut cert_verify_msg: Option<Vec<u8>> = None;
    let mut server_finished_body: Option<Vec<u8>> = None;
    let mut handshake_done = false;
    let mut encrypted_app_records: Vec<Vec<u8>> = Vec::new();

    for r in &in_records {
        if r.content_type != 23 {
            continue;
        }
        if handshake_done {
            encrypted_app_records.push(record_bytes(r));
            continue;
        }

        let (plaintext, inner_ct) = decrypt_record(&hs_key, &hs_iv, hs_seq, r)?;
        hs_seq += 1;

        if inner_ct == 23 {
            handshake_done = true;
            encrypted_app_records.push(record_bytes(r));
            continue;
        }

        for msg in &parse_handshake_messages(&plaintext)? {
            let raw: Vec<u8> = hs_header(msg).iter().chain(&msg.body).copied().collect();
            match msg.msg_type {
                HS_ENCRYPTED_EXTENSIONS => {
                    handshake_messages.push(raw);
                }
                HS_CERTIFICATE => {
                    cert_chain_der = Some(parse_cert_message(&msg.body)?);
                    handshake_messages.push(raw);
                }
                HS_CERTIFICATE_VERIFY => {
                    cert_verify_msg = Some(msg.body.clone());
                    handshake_messages.push(raw);
                }
                HS_FINISHED => {
                    server_finished_body = Some(msg.body.clone());
                    handshake_messages.push(raw);
                    handshake_done = true;
                }
                _ => {
                    handshake_messages.push(raw);
                }
            }
        }
    }

    Ok(TlsWitness {
        client_ecdh_private,
        server_ecdh_public,
        cert_chain_der: cert_chain_der
            .ok_or_else(|| anyhow::anyhow!("Certificate message not found"))?,
        cert_verify_msg: cert_verify_msg
            .ok_or_else(|| anyhow::anyhow!("CertificateVerify message not found"))?,
        handshake_messages,
        encrypted_app_records,
        server_finished_body: server_finished_body
            .ok_or_else(|| anyhow::anyhow!("Server Finished not found"))?,
    })
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Encode the 4-byte handshake message header (type + 3-byte length).
fn hs_header(msg: &HandshakeMsg) -> [u8; 4] {
    let len = msg.body.len() as u32;
    [msg.msg_type, (len >> 16) as u8, (len >> 8) as u8, len as u8]
}

/// Reconstruct the full 5+n raw bytes of a TLS record.
fn record_bytes(r: &RawRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + r.payload.len());
    out.push(r.content_type);
    out.extend_from_slice(&r.legacy_version.to_be_bytes());
    out.extend_from_slice(&(r.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&r.payload);
    out
}
