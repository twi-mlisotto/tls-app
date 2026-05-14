#![no_main]
sp1_zkvm::entrypoint!(main);

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm,
};
use der::Decode;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Verifier as EcVerifier, DerSignature, VerifyingKey};
use p384::ecdsa::{
    signature::Verifier as P384Verifier, DerSignature as P384DerSignature,
    VerifyingKey as P384VerifyingKey,
};
use rsa::{pkcs1v15, pkcs8::DecodePublicKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use sp1_https_json_shared::{PublicClaim, TlsWitness};
use x25519_dalek::{PublicKey, StaticSecret};
use x509_cert::Certificate;

pub fn main() {
    // -----------------------------------------------------------------------
    // 1. Read witness + parameters.
    // -----------------------------------------------------------------------
    let witness: TlsWitness = sp1_zkvm::io::read();
    let host: String = sp1_zkvm::io::read();
    let field: String = sp1_zkvm::io::read();
    let threshold: f64 = sp1_zkvm::io::read();

    // handshake_messages order: [CH, SH, EE, Cert, CertVerify, ServerFinished]
    assert!(
        witness.handshake_messages.len() >= 6,
        "need at least 6 handshake messages"
    );

    // -----------------------------------------------------------------------
    // 2. Compute transcript hashes in-guest (transcript integrity).
    // -----------------------------------------------------------------------
    // transcript_after_sh: hash(CH || SH) — used for HS key schedule
    let transcript_after_sh: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&witness.handshake_messages[0]);
        h.update(&witness.handshake_messages[1]);
        h.finalize().into()
    };

    // transcript_before_cv: hash(CH || SH || EE || Cert) — for CertVerify sig
    let transcript_before_cv: [u8; 32] = {
        let mut h = Sha256::new();
        for msg in &witness.handshake_messages[..4] {
            h.update(msg);
        }
        h.finalize().into()
    };

    // transcript_before_finished: hash(CH..CertVerify) — for Finished HMAC
    let transcript_before_finished: [u8; 32] = {
        let mut h = Sha256::new();
        for msg in &witness.handshake_messages[..5] {
            h.update(msg);
        }
        h.finalize().into()
    };

    // transcript_after_finished: hash(CH..ServerFinished) — for app traffic secret
    let transcript_after_finished: [u8; 32] = {
        let mut h = Sha256::new();
        for msg in &witness.handshake_messages[..6] {
            h.update(msg);
        }
        h.finalize().into()
    };

    // -----------------------------------------------------------------------
    // 3. ECDH → HKDF key schedule (RFC 8446 §7.1).
    // -----------------------------------------------------------------------
    let client_secret = StaticSecret::from(witness.client_ecdh_private);
    let server_pub = PublicKey::from(witness.server_ecdh_public);
    let ecdh = client_secret.diffie_hellman(&server_pub);

    let (early_secret, _) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &[0u8; 32]);
    let derived1 = expand_label(&early_secret, "derived", &empty_hash(), 32);
    let (hs_secret, _) = Hkdf::<Sha256>::extract(Some(&derived1), ecdh.as_bytes());

    // server_handshake_traffic_secret — needed to derive finished_key
    let server_hs_secret = expand_label(&hs_secret, "s hs traffic", &transcript_after_sh, 32);

    let derived2 = expand_label(&hs_secret, "derived", &empty_hash(), 32);
    let (master_secret, _) = Hkdf::<Sha256>::extract(Some(&derived2), &[0u8; 32]);

    // server_application_traffic_secret_0
    let server_app_secret = expand_label(
        &master_secret,
        "s ap traffic",
        &transcript_after_finished,
        32,
    );

    // -----------------------------------------------------------------------
    // 4. Verify Server Finished (proves the server knew the HS key).
    // -----------------------------------------------------------------------
    let finished_key = expand_label(&server_hs_secret, "finished", &[], 32);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&finished_key).unwrap();
    mac.update(&transcript_before_finished);
    let expected_verify_data = mac.finalize().into_bytes();

    assert_eq!(
        expected_verify_data.as_ref() as &[u8],
        witness.server_finished_body.as_slice(),
        "Server Finished HMAC verification failed"
    );

    // -----------------------------------------------------------------------
    // 5. Certificate chain verification.
    //
    //    cert_chain_der: [leaf, intermediate(s)...]
    //    Each cert's signature is verified by the next cert's public key.
    //    The last cert is verified against a webpki trust anchor.
    // -----------------------------------------------------------------------
    let chain: Vec<Certificate> = witness
        .cert_chain_der
        .iter()
        .map(|der| Certificate::from_der(der).expect("invalid DER cert"))
        .collect();

    assert!(!chain.is_empty(), "empty cert chain");

    // Locate where the trust-anchor boundary falls in the chain.
    //
    // Case A: the server included the root cert itself — its SUBJECT matches a
    //         trust anchor.  We verify certs [0, anchor_idx) normally and skip
    //         anchor_idx (it is trusted by definition).
    //
    // Case B: the last cert's ISSUER matches a trust anchor (server didn't send
    //         the root).  We verify all certs in the chain using the anchor SPKI
    //         for the final one.
    let (anchor_boundary, anchor_spki) = find_trust_anchor(&chain, &witness.cert_chain_der);

    for i in 0..anchor_boundary {
        let issuer_spki = if i + 1 < anchor_boundary {
            chain[i + 1].tbs_certificate.subject_public_key_info.clone()
        } else {
            anchor_spki.clone()
        };
        verify_cert_signature(&chain[i], &issuer_spki);
    }

    // -----------------------------------------------------------------------
    // 6. Hostname verification (leaf cert SAN must match `host`).
    // -----------------------------------------------------------------------
    verify_hostname(&chain[0], &host);

    // -----------------------------------------------------------------------
    // 7. CertificateVerify — server proves it holds the leaf cert private key.
    //
    //    Signed message = 64×0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_before_cv
    // -----------------------------------------------------------------------
    let cv_msg = &witness.cert_verify_msg;
    // TLS 1.3 CertificateVerify body: 2-byte SignatureScheme || 2-byte length || signature
    assert!(cv_msg.len() >= 4, "CertificateVerify too short");
    let scheme = u16::from_be_bytes([cv_msg[0], cv_msg[1]]);
    let sig_len = u16::from_be_bytes([cv_msg[2], cv_msg[3]]) as usize;
    assert!(cv_msg.len() >= 4 + sig_len, "CertificateVerify truncated");
    let sig_bytes = &cv_msg[4..4 + sig_len];

    let mut signed_content = vec![0x20u8; 64];
    signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content.push(0x00);
    signed_content.extend_from_slice(&transcript_before_cv);

    let leaf_spki = &chain[0].tbs_certificate.subject_public_key_info;
    let leaf_pk = leaf_spki.subject_public_key.raw_bytes();

    // Dispatch on RFC 8446 §4.2.3 SignatureScheme values
    match scheme {
        0x0403 => {
            // ecdsa_secp256r1_sha256
            let vk = VerifyingKey::from_sec1_bytes(leaf_pk).expect("leaf cert not P-256");
            let sig = DerSignature::try_from(sig_bytes).expect("invalid ECDSA-P256 sig DER");
            vk.verify(&signed_content, &sig)
                .expect("CertificateVerify ECDSA-P256 sig invalid");
        }
        0x0503 => {
            // ecdsa_secp384r1_sha384
            let vk = P384VerifyingKey::from_sec1_bytes(leaf_pk).expect("leaf cert not P-384");
            let sig = P384DerSignature::try_from(sig_bytes).expect("invalid ECDSA-P384 sig DER");
            P384Verifier::verify(&vk, &signed_content, &sig)
                .expect("CertificateVerify ECDSA-P384 sig invalid");
        }
        0x0804 => {
            // rsa_pss_rsae_sha256
            use der::Encode;
            use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVk};
            let spki_der = leaf_spki.to_der().expect("encode leaf SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA leaf key");
            let vk = PssVk::<Sha256>::new(pk);
            let sig = PssSignature::try_from(sig_bytes).expect("invalid RSA-PSS sig");
            rsa::signature::Verifier::verify(&vk, &signed_content, &sig)
                .expect("CertificateVerify RSA-PSS-SHA256 sig invalid");
        }
        0x0805 => {
            // rsa_pss_rsae_sha384
            use der::Encode;
            use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVk};
            use sha2::Sha384;
            let spki_der = leaf_spki.to_der().expect("encode leaf SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA leaf key");
            let vk = PssVk::<Sha384>::new(pk);
            let sig = PssSignature::try_from(sig_bytes).expect("invalid RSA-PSS sig");
            rsa::signature::Verifier::verify(&vk, &signed_content, &sig)
                .expect("CertificateVerify RSA-PSS-SHA384 sig invalid");
        }
        0x0401 => {
            // rsa_pkcs1_sha256
            use der::Encode;
            let spki_der = leaf_spki.to_der().expect("encode leaf SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA leaf key");
            let vk = pkcs1v15::VerifyingKey::<Sha256>::new(pk);
            let sig = pkcs1v15::Signature::try_from(sig_bytes).expect("invalid RSA-PKCS1 sig");
            rsa::signature::Verifier::verify(&vk, &signed_content, &sig)
                .expect("CertificateVerify RSA-PKCS1-SHA256 sig invalid");
        }
        other => panic!("unsupported CertificateVerify scheme: 0x{:04x}", other),
    }

    // -----------------------------------------------------------------------
    // 8. Derive app traffic key + IV; decrypt application data records.
    // -----------------------------------------------------------------------
    let app_key_vec = expand_label(&server_app_secret, "key", &[], 16);
    let app_iv_vec = expand_label(&server_app_secret, "iv", &[], 12);
    let mut app_key = [0u8; 16];
    let mut app_iv = [0u8; 12];
    app_key.copy_from_slice(&app_key_vec);
    app_iv.copy_from_slice(&app_iv_vec);

    let mut plaintext = Vec::new();
    for (seq, record_bytes) in witness.encrypted_app_records.iter().enumerate() {
        assert!(record_bytes.len() >= 5);
        let ct = record_bytes[0];
        let version = u16::from_be_bytes([record_bytes[1], record_bytes[2]]);
        let payload = &record_bytes[5..];

        let nonce = xor_nonce(&app_iv, seq as u64);
        let aad = {
            let mut h = [0u8; 5];
            h[0] = ct;
            h[1..3].copy_from_slice(&version.to_be_bytes());
            h[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            h
        };

        let tag_start = payload.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&payload[tag_start..]);
        let mut buf = payload[..tag_start].to_vec();

        <Aes128Gcm as KeyInit>::new(&app_key.into())
            .decrypt_in_place_detached(nonce.as_ref().into(), &aad, &mut buf, &tag.into())
            .expect("AES-GCM app record auth failed");

        // The last byte is the inner content type (RFC 8446 §5.2).
        // 23 = ApplicationData (HTTP), 22 = Handshake (session tickets, KeyUpdate).
        let inner_ct = *buf.last().expect("empty decrypted record");
        buf.pop();
        if inner_ct == 23 {
            plaintext.extend_from_slice(&buf);
        }
    }

    // -----------------------------------------------------------------------
    // 9. HTTP response → body → JSON assertion.
    // -----------------------------------------------------------------------
    let response = String::from_utf8(plaintext).expect("response is not UTF-8");
    // Split headers from body on the blank line.
    let raw_body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    // Decode chunked transfer encoding if present (strip hex chunk sizes).
    let body = unchunk(raw_body);

    let json: serde_json::Value = serde_json::from_str(&body).expect("body is not valid JSON");

    let field_value = json
        .pointer(&field)
        .unwrap_or_else(|| panic!("field '{}' not found", field))
        .as_f64()
        .unwrap_or_else(|| panic!("field '{}' is not a number", field));

    assert!(
        field_value > threshold,
        "{} = {} is not > {}",
        field,
        field_value,
        threshold
    );

    // -----------------------------------------------------------------------
    // 10. Commit public values.
    // -----------------------------------------------------------------------
    sp1_zkvm::io::commit(&PublicClaim {
        host,
        field,
        threshold,
        value: field_value,
    });
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

// OID strings for signature algorithms
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";

/// Verify `cert`'s signature using the parsed SPKI of its issuer.
/// Dispatches on the cert's signature algorithm OID (ECDSA-P256 or RSA PKCS#1v1.5).
fn verify_cert_signature(
    cert: &Certificate,
    issuer_spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) {
    use der::Encode;
    let tbs_der = cert.tbs_certificate.to_der().expect("encode TBS");
    let sig_bytes = cert.signature.raw_bytes();
    let oid = cert.signature_algorithm.oid.to_string();

    match oid.as_str() {
        OID_ECDSA_SHA256 => {
            let pk = issuer_spki.subject_public_key.raw_bytes();
            let vk = VerifyingKey::from_sec1_bytes(pk).expect("issuer not P-256");
            let sig = DerSignature::try_from(sig_bytes).expect("invalid ECDSA-P256 sig");
            EcVerifier::verify(&vk, &tbs_der, &sig).expect("cert ECDSA-P256 sig invalid");
        }
        OID_ECDSA_SHA384 => {
            let pk = issuer_spki.subject_public_key.raw_bytes();
            let vk = P384VerifyingKey::from_sec1_bytes(pk).expect("issuer not P-384");
            let sig = P384DerSignature::try_from(sig_bytes).expect("invalid ECDSA-P384 sig");
            P384Verifier::verify(&vk, &tbs_der, &sig).expect("cert ECDSA-P384 sig invalid");
        }
        OID_RSA_SHA256 => {
            let spki_der = issuer_spki.to_der().expect("encode SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA key");
            let vk = pkcs1v15::VerifyingKey::<Sha256>::new(pk);
            let sig = pkcs1v15::Signature::try_from(sig_bytes).expect("invalid RSA sig");
            rsa::signature::Verifier::verify(&vk, &tbs_der, &sig)
                .expect("cert RSA-SHA256 sig invalid");
        }
        OID_RSA_SHA384 => {
            use sha2::Sha384;
            let spki_der = issuer_spki.to_der().expect("encode SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA key");
            let vk = pkcs1v15::VerifyingKey::<Sha384>::new(pk);
            let sig = pkcs1v15::Signature::try_from(sig_bytes).expect("invalid RSA sig");
            rsa::signature::Verifier::verify(&vk, &tbs_der, &sig)
                .expect("cert RSA-SHA384 sig invalid");
        }
        other => panic!("unsupported sig alg: {}", other),
    }
}

/// Find the trust-anchor boundary in the chain and return
/// `(anchor_boundary, anchor_spki)` where:
///   - certs [0, anchor_boundary) need to be signature-verified
///   - `anchor_spki` signs cert[anchor_boundary - 1]
///
/// We try two strategies:
///   A. A cert's SUBJECT matches a trust anchor (server sent the root cert).
///      anchor_boundary = that cert's index.
///   B. The last cert's ISSUER matches a trust anchor.
///      anchor_boundary = chain.len().
fn find_trust_anchor(
    chain: &[Certificate],
    chain_ders: &[Vec<u8>],
) -> (usize, x509_cert::spki::SubjectPublicKeyInfoOwned) {
    // Strategy A: look for a cert whose subject bytes match a trust anchor.
    for i in 0..chain.len() {
        if let Some(subj_content) = raw_name_content(chain_ders, i, NameField::Subject) {
            if let Some(anchor) = webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .find(|a| a.subject.as_ref() == subj_content)
            {
                let spki = parse_anchor_spki(anchor.subject_public_key_info.as_ref());
                return (i, spki);
            }
        }
    }

    // Strategy B: last cert's ISSUER matches a trust anchor.
    let last = chain.len() - 1;
    if let Some(iss_content) = raw_name_content(chain_ders, last, NameField::Issuer) {
        if let Some(anchor) = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .find(|a| a.subject.as_ref() == iss_content)
        {
            let spki = parse_anchor_spki(anchor.subject_public_key_info.as_ref());
            return (chain.len(), spki);
        }
    }

    panic!("root CA not found in trust store");
}

/// Parse a trust anchor's `subject_public_key_info` bytes into an SPKI struct.
///
/// webpki-roots stores SPKI as the SEQUENCE *content* (AlgorithmIdentifier +
/// BIT STRING) without the outer 0x30 tag/length wrapper.  We add the wrapper
/// so that x509-cert's DER decoder is happy.
fn parse_anchor_spki(content: &[u8]) -> x509_cert::spki::SubjectPublicKeyInfoOwned {
    let len = content.len();
    let mut full = Vec::with_capacity(4 + len);
    full.push(0x30);
    if len < 0x80 {
        full.push(len as u8);
    } else if len < 0x100 {
        full.push(0x81);
        full.push(len as u8);
    } else {
        full.push(0x82);
        full.push((len >> 8) as u8);
        full.push(len as u8);
    }
    full.extend_from_slice(content);
    x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&full).expect("parse trust anchor SPKI")
}

enum NameField {
    Subject,
    Issuer,
}

/// Extract the raw content bytes (inner SEQUENCE content, no outer tag/length)
/// of either the issuer or subject Name from a DER-encoded Certificate at
/// `chain_ders[idx]`.
fn raw_name_content(chain_ders: &[Vec<u8>], idx: usize, field: NameField) -> Option<&[u8]> {
    let cert_der = &chain_ders[idx];
    let cert_content = der_unwrap_sequence(cert_der)?;
    let (tbs_tlv, _) = der_next_tlv(cert_content)?;
    let tbs_content = der_unwrap_sequence(tbs_tlv)?;

    let mut pos = tbs_content;
    // Skip version [0] EXPLICIT if present
    if pos.first() == Some(&0xa0) {
        let (_, rest) = der_next_tlv(pos)?;
        pos = rest;
    }
    // Skip serialNumber
    let (_, rest) = der_next_tlv(pos)?;
    pos = rest;
    // Skip signature AlgorithmIdentifier
    let (_, rest) = der_next_tlv(pos)?;
    pos = rest;
    // TBSCertificate: next field is issuer
    let (issuer_tlv, rest) = der_next_tlv(pos)?;

    let name_tlv = match field {
        NameField::Issuer => issuer_tlv,
        NameField::Subject => {
            // Skip validity (SEQUENCE of two times)
            let (_, rest2) = der_next_tlv(rest)?;
            let (subject_tlv, _) = der_next_tlv(rest2)?;
            subject_tlv
        }
    };

    // Trust anchor subjects are the inner content (without the outer 0x30 TLV).
    der_unwrap_sequence(name_tlv)
}

/// Check that the leaf cert's SAN contains `host` (exact or wildcard match).
fn verify_hostname(cert: &Certificate, host: &str) {
    use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};

    // OID for SubjectAltName: 2.5.29.17
    const ID_CE_SUBJECT_ALT_NAME: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("leaf cert has no extensions");

    let san_ext = exts
        .iter()
        .find(|e| e.extn_id == ID_CE_SUBJECT_ALT_NAME)
        .expect("leaf cert has no SAN extension");

    let san: SubjectAltName =
        SubjectAltName::from_der(san_ext.extn_value.as_bytes()).expect("parse SAN");

    let matched = san.0.iter().any(|name| {
        if let GeneralName::DnsName(dns) = name {
            hostname_matches(dns.as_str(), host)
        } else {
            false
        }
    });

    assert!(matched, "hostname '{}' not in cert SAN", host);
}

/// Unwrap a DER SEQUENCE, returning its content bytes.
fn der_unwrap_sequence(der: &[u8]) -> Option<&[u8]> {
    if der.first() != Some(&0x30) {
        return None;
    }
    der_next_tlv(der)
        .map(|(_, rest)| &der[..der.len() - rest.len()])
        .map(|seq| {
            let tag_len = if seq[1] & 0x80 == 0 {
                2
            } else {
                2 + (seq[1] & 0x7f) as usize
            };
            &seq[tag_len..]
        })
}

/// Return (this_tlv_bytes, remaining_bytes) for a DER stream.
fn der_next_tlv(der: &[u8]) -> Option<(&[u8], &[u8])> {
    if der.len() < 2 {
        return None;
    }
    let (len, header_len) = if der[1] & 0x80 == 0 {
        (der[1] as usize, 2)
    } else {
        let n = (der[1] & 0x7f) as usize;
        if der.len() < 2 + n {
            return None;
        }
        let mut l = 0usize;
        for &b in &der[2..2 + n] {
            l = (l << 8) | b as usize;
        }
        (l, 2 + n)
    };
    let total = header_len + len;
    if der.len() < total {
        return None;
    }
    Some((&der[..total], &der[total..]))
}

fn hostname_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // wildcard: *.example.com matches api.example.com but not api.sub.example.com
        host.ends_with(suffix)
            && host.len() > suffix.len() + 1
            && !host[..host.len() - suffix.len() - 1].contains('.')
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// Decode HTTP/1.1 chunked transfer encoding.
/// Format: (hex-size CRLF data CRLF)* "0" CRLF CRLF
/// If the body doesn't look chunked, return it unchanged.
fn unchunk(body: &str) -> String {
    let mut out = String::new();
    let mut s = body;
    while let Some(p) = s.find("\r\n") {
        // Find the chunk-size line
        let crlf = p;
        let size_str = s[..crlf].trim();
        // Chunk size might have extensions after ';' — ignore them
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_len = match usize::from_str_radix(size_hex, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        s = &s[crlf + 2..]; // skip size line + CRLF
        if chunk_len == 0 {
            break; // terminal chunk
        }
        if s.len() < chunk_len {
            break;
        }
        out.push_str(&s[..chunk_len]);
        s = &s[chunk_len..];
        // skip trailing CRLF after chunk data
        if s.starts_with("\r\n") {
            s = &s[2..];
        }
    }
    if out.is_empty() {
        body.to_string()
    } else {
        out
    }
}

// ---------------------------------------------------------------------------
// HKDF / crypto helpers
// ---------------------------------------------------------------------------

fn expand_label(prk: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
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

fn empty_hash() -> [u8; 32] {
    Sha256::digest([]).into()
}

fn xor_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    nonce
}
