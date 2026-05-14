# zkTLS JSON Assertion — Implementation Plan

## Goal

Generate a ZK proof that says:
> "A server whose TLS certificate chains to a trusted root CA participated in a handshake
> that produced a response whose JSON field `/data/amount` is greater than `50000`."

No trusted third party. No oracle. The server's own certificate is the trust anchor.

---

## Why This Works (Trust Model)

TLS 1.3's **CertificateVerify** message is the key. The server signs the entire handshake
transcript with its certificate private key. This means:

- If the guest verifies the cert chain → the certificate is legitimately issued
- If the guest verifies CertificateVerify → the real server (holder of the cert's private key) participated in this exact handshake
- If the guest derives traffic keys from the handshake → the decrypted plaintext is what the server sent
- The prover **cannot forge any of this** without the server's private key

The guest does not need network access. It is a pure function over the transcript bytes.

---

## What the Proof Does NOT Cover

- The prover could replay an old valid session (mitigation: include a timestamp/nonce assertion)
- The guest trusts hardcoded root CAs — if a CA is compromised, the proof is compromised
- Certificate revocation is not checked (would require OCSP inside the guest — too expensive)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        HOST (script)                        │
│                                                             │
│  TcpStream wrapped in CapturingStream                       │
│       │ raw bytes captured (both directions)                │
│  rustls ClientConnection on top                             │
│       │ actual TLS handshake with api.coinbase.com          │
│       ▼                                                     │
│  TlsTranscriptExtractor                                     │
│   - parses raw captured bytes into TLS 1.3 records          │
│   - extracts: certs, CertVerify sig, transcript hash,       │
│     server ECDH pubkey, encrypted app records               │
│   - reads client ephemeral privkey from rustls KeyLog       │
│       │                                                     │
│       ▼                                                     │
│  TlsWitness { ... }  ←── serialised into guest stdin        │
└─────────────────────────────────────────────────────────────┘
                            │ sp1_zkvm::io::read()
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                     GUEST (program)                          │
│                                                              │
│  1. verify_cert_chain()                                      │
│     webpki-roots (hardcoded Mozilla roots) + webpki          │
│                                                              │
│  2. verify_cert_verify()                                     │
│     p256::ecdsa — server signed the transcript with its cert │
│     (or rsa if server uses RSA cert)                         │
│                                                              │
│  3. derive_traffic_keys()                                    │
│     X25519 shared secret → HKDF-SHA256 key schedule          │
│     → server_write_key + server_write_iv                     │
│     SHA-256 is precompiled in SP1 → this step is cheap       │
│                                                              │
│  4. decrypt_records()                                        │
│     AES-128-GCM or ChaCha20-Poly1305 over encrypted records  │
│                                                              │
│  5. assert_json_field()                                      │
│     serde_json pointer lookup + numeric comparison           │
│                                                              │
│  6. sp1_zkvm::io::commit() public outputs                    │
│     - server hostname (from cert CN/SAN)                     │
│     - field pointer                                          │
│     - threshold                                              │
│     - actual value                                           │
└──────────────────────────────────────────────────────────────┘
```

---

## Data Model

```rust
// Passed host → guest via stdin (bincode serialised)
struct TlsWitness {
    // Raw handshake message bytes in transcript order:
    // ClientHello, ServerHello, EncryptedExtensions, Certificate,
    // CertificateVerify, Finished
    // Each entry is the full message: [type u8][length u24][body...]
    // Guest parses these to extract: server_ecdh_pub (from ServerHello),
    // cert chain DER (from Certificate), sig+scheme (from CertificateVerify),
    // and computes transcript hashes itself.
    handshake_messages: Vec<Vec<u8>>,

    // Client ephemeral X25519 private key — captured via CapturingKxGroup.
    // Guest uses this to recompute X25519(client_priv, server_pub) and the
    // full HKDF key schedule, proving traffic keys came from this handshake.
    client_ecdh_private: [u8; 32],

    // Negotiated cipher suite (0x1301=TLS_AES_128_GCM_SHA256,
    // 0x1302=TLS_AES_256_GCM_SHA384, 0x1303=TLS_CHACHA20_POLY1305_SHA256)
    cipher_suite: u16,

    // Encrypted application data TLS records.
    // Each entry is (5-byte record header, ciphertext payload).
    // Guest decrypts these using derived traffic keys.
    encrypted_app_records: Vec<([u8; 5], Vec<u8>)>,

    // JSON assertion parameters
    field_pointer: String,
    threshold: f64,
}
```

---

## Ephemeral Key Capture — The Core Problem

### Why KeyLog is not enough

`rustls::KeyLog` (the `SSLKEYLOGFILE` interface) emits derived *traffic secrets*:

```
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
SERVER_TRAFFIC_SECRET_0         <client_random> <secret>
```

These look useful but are **insufficient for the guest**. If the guest is given
`SERVER_TRAFFIC_SECRET_0` directly, it can decrypt the records — but a malicious
prover could supply a fabricated secret paired with fabricated ciphertext. The
decryption would succeed and the JSON assertion would hold, but no real server
was ever involved.

The guest must verify the complete trust chain:

```
client_priv × server_pub  →  shared_secret        [X25519]
shared_secret + transcript  →  traffic_keys        [HKDF-SHA256]
traffic_keys + ciphertext   →  plaintext           [AES-GCM]
server_cert.sign(transcript) = cert_verify_sig     [ECDSA P-256]
```

Every arrow must be verified in the guest. Giving it `SERVER_TRAFFIC_SECRET_0`
breaks the chain at the first arrow — X25519 is never checked.

The server's CertificateVerify signature covers the full handshake transcript,
which includes the ServerHello `key_share` extension containing `server_ecdh_pub`.
So if the guest verifies CertVerify AND re-derives traffic keys from
`X25519(client_priv, server_ecdh_pub)`, the entire chain is anchored to the
server's certificate. Nothing can be forged.

### Why the client ephemeral private key is the right primitive

We need `client_ecdh_private` specifically because:
- It is the only secret input to the ECDH exchange not visible on the wire
- `server_ecdh_pub` is in the ServerHello (wire-visible, captured directly)
- `shared_secret = X25519(client_priv, server_pub)` — guest recomputes this
- Everything downstream (HKDF, decryption) follows deterministically

### The solution: custom `SupportedKxGroup`

rustls 0.23 generates ephemeral keys internally through the `CryptoProvider`
abstraction. We replace the built-in X25519 implementation with our own that
exposes its secrets:

```rust
// Trait rustls calls to start a key exchange
pub trait SupportedKxGroup: Send + Sync + Debug {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error>;
    fn name(&self) -> NamedGroup;
}

// Trait rustls calls when ServerHello arrives with the server's public key
pub trait ActiveKeyExchange: Send + Sync {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error>;
    fn pub_key(&self) -> &[u8];   // our public key — sent in ClientHello
    fn group(&self) -> NamedGroup;
}
```

Our implementation:

```rust
pub struct CapturingKxGroup {
    // Written to by complete(); read by the host after handshake
    pub captured: Arc<Mutex<Option<KeyMaterial>>>,
}

pub struct KeyMaterial {
    pub client_private: [u8; 32],
    pub server_public:  [u8; 32],
}

impl SupportedKxGroup for CapturingKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret  = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
        let public  = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(CapturingActiveKx {
            secret,
            public,
            captured: self.captured.clone(),
        }))
    }
    fn name(&self) -> NamedGroup { NamedGroup::X25519 }
}

impl ActiveKeyExchange for CapturingActiveKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let server_pub = <[u8; 32]>::try_from(peer_pub_key).unwrap();
        // Capture both keys before consuming the secret
        *self.captured.lock().unwrap() = Some(KeyMaterial {
            client_private: self.secret.to_bytes(),  // see note below
            server_public:  server_pub,
        });
        let shared = self.secret.diffie_hellman(
            &x25519_dalek::PublicKey::from(server_pub)
        );
        Ok(SharedSecret::from(&shared.to_bytes()[..]))
    }
    fn pub_key(&self) -> &[u8] { self.public.as_bytes() }
    fn group(&self) -> NamedGroup { NamedGroup::X25519 }
}
```

**Note on `to_bytes()`:** `x25519_dalek::EphemeralSecret` deliberately does not
implement `Clone` or expose bytes to discourage key reuse. We must switch to
`x25519_dalek::StaticSecret` (which is byte-accessible) for this use case, since
we explicitly need to extract the private key for the ZK witness. This is
intentional — the security model here is that the prover is the same party who
holds the private key.

Wire into rustls:

```rust
let kx_capture = Arc::new(Mutex::new(None));
let provider = CryptoProvider {
    kx_groups: vec![Arc::new(CapturingKxGroup { captured: kx_capture.clone() })],
    ..rustls::crypto::ring::default_provider()
};
let config = ClientConfig::builder_with_provider(Arc::new(provider))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

After the handshake, `kx_capture.lock().unwrap()` contains both keys.

---

### What the custom KxGroup gives us (and what it does not)

| Data | Source |
|---|---|
| `client_ecdh_private` | ✅ CapturingKxGroup |
| `server_ecdh_public` | ✅ CapturingKxGroup (peer_pub_key in complete()) |
| `cert_chain` | ✅ rustls `peer_certificates()` |
| `cipher_suite` | ✅ rustls `negotiated_cipher_suite()` |
| `client_random` | ⚠️ raw ClientHello bytes |
| `server_random` | ⚠️ raw ServerHello bytes |
| `transcript_hash` (for CertVerify) | ⚠️ must compute from raw handshake messages |
| `handshake_hash` (for app traffic) | ⚠️ must compute from raw handshake messages |
| `cert_verify_sig` + `scheme` | ⚠️ must decrypt + parse CertificateVerify record |
| `encrypted_app_records` | ⚠️ raw inbound bytes after handshake |

The ⚠️ items require parsing the raw byte stream — see Host Implementation below.

---

## Host Implementation

### Step 1 — CapturingStream

Wrap `TcpStream` to record every byte in both directions before rustls sees them:

```rust
struct CapturingStream {
    inner:    TcpStream,
    inbound:  Vec<u8>,   // server → client (TLS records as sent on the wire)
    outbound: Vec<u8>,   // client → server
}
impl Read  for CapturingStream { /* forward + append to inbound  */ }
impl Write for CapturingStream { /* forward + append to outbound */ }
```

### Step 2 — KeyLog for handshake decryption (host-side only)

rustls KeyLog emits `SERVER_HANDSHAKE_TRAFFIC_SECRET`. The host uses this to
decrypt the encrypted handshake records (EncryptedExtensions, Certificate,
CertificateVerify, Finished) **locally**, so it can extract the raw handshake
message bytes needed for transcript hashing.

This secret never enters the guest. It is only used by the host to reconstruct
plaintext handshake messages from the wire bytes.

```rust
struct HandshakeSecretLog {
    server_hs_secret: Arc<Mutex<Option<Vec<u8>>>>,
}
impl KeyLog for HandshakeSecretLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
            *self.server_hs_secret.lock().unwrap() = Some(secret.to_vec());
        }
    }
}
```

### Step 3 — TLS record parsing

Parse the captured `inbound` bytes into TLS records:

```
TLS record:  [content_type u8][version u16][length u16][payload: length bytes]
  content types:  0x14=ChangeCipherSpec  0x15=Alert  0x16=Handshake  0x17=AppData

TLS 1.3 handshake messages (inside record payload):
  [msg_type u8][length u24][body: length bytes]
  msg_type:  0x01=ClientHello  0x02=ServerHello  0x08=EncryptedExtensions
             0x0B=Certificate  0x0F=CertificateVerify  0x14=Finished
```

**Unencrypted records** (before server Finished):
- ClientHello (content_type=0x16) — extract `client_random` at offset 6
- ServerHello (content_type=0x16) — extract `server_random` at offset 6,
  parse extensions to find `key_share` (type 0x0033) → `server_ecdh_pub`

**Encrypted handshake records** (content_type=0x17, after ServerHello):
- Decrypt with host-side HKDF from `SERVER_HANDSHAKE_TRAFFIC_SECRET`
- Strip the 1-byte inner content type suffix
- Parse inner handshake messages: EncryptedExtensions, Certificate,
  CertificateVerify, Finished

**Application data records** (content_type=0x17, after server Finished):
- Collected as raw `(header_bytes, payload_bytes)` pairs
- These are passed to the guest for decryption

### Step 4 — Compute transcript hashes (on host, verified by guest)

The TLS 1.3 transcript hash is SHA-256 over concatenated **handshake message bytes**
(the 4-byte header + body, NOT TLS record framing).

```
transcript_hash_for_cert_verify =
    SHA256( CH_msg || SH_msg || EE_msg || Cert_msg )

handshake_hash =
    SHA256( CH_msg || SH_msg || EE_msg || Cert_msg || CV_msg || Fin_msg )
```

The guest recomputes these independently from the raw messages in `TlsWitness`
and checks they match what CertificateVerify was signed over.

### Step 5 — Assemble TlsWitness and write to stdin

```rust
let witness = TlsWitness {
    handshake_messages,       // Vec<Vec<u8>> — raw msg bytes in order
    client_ecdh_private,      // from CapturingKxGroup
    cipher_suite,             // from rustls negotiated_cipher_suite()
    encrypted_app_records,    // Vec<(header: [u8;5], payload: Vec<u8>)>
    field_pointer,
    threshold,
};
stdin.write(&witness);
```

The `cert_chain` and `server_ecdh_pub` are NOT passed separately — the guest
parses them directly from `handshake_messages` (Certificate and ServerHello
messages respectively). This ensures the guest verifies what's actually in the
transcript, not a pre-parsed copy the host could lie about.

---

## Guest Implementation

### Crates (all no_std compatible)

| Crate | Purpose | no_std |
|---|---|---|
| `p256` | ECDSA P-256 cert verify sig | ✅ |
| `rsa` | RSA cert verify sig (fallback) | ✅ |
| `x25519-dalek` | ECDH shared secret | ✅ |
| `sha2` | SHA-256 (SP1 precompiled) | ✅ |
| `hmac` + `hkdf` | TLS 1.3 key schedule | ✅ |
| `aes-gcm` | Decrypt app records | ✅ |
| `chacha20poly1305` | Decrypt app records (alt) | ✅ |
| `webpki` | Certificate chain validation | ✅ |
| `webpki-roots` | Mozilla root CAs (hardcoded) | ✅ |
| `x509-parser` | Parse DER cert fields | ✅ |
| `serde_json` | JSON pointer assertion | ✅ (alloc) |

### Key derivation (TLS 1.3 schedule)

```
shared_secret = X25519(client_priv, server_pub)

early_secret          = HKDF-Extract(salt=0x00*32, ikm=0x00*32)
derived_secret        = HKDF-Expand-Label(early_secret, "derived", SHA256(""), 32)
handshake_secret      = HKDF-Extract(salt=derived_secret, ikm=shared_secret)
server_hs_traffic     = HKDF-Expand-Label(handshake_secret, "s hs traffic", transcript_hash, 32)
derived_secret2       = HKDF-Expand-Label(handshake_secret, "derived", SHA256(""), 32)
master_secret         = HKDF-Extract(salt=derived_secret2, ikm=0x00*32)
server_app_traffic    = HKDF-Expand-Label(master_secret, "s ap traffic", handshake_hash, 32)
server_write_key      = HKDF-Expand-Label(server_app_traffic, "key", "", 16)  // AES-128
server_write_iv       = HKDF-Expand-Label(server_app_traffic, "iv",  "", 12)
```

### AES-GCM record decryption

```
nonce = server_write_iv XOR (record_sequence_number as 12-byte big-endian)
plaintext = AES-128-GCM-Decrypt(key=server_write_key, nonce, aad=tls_record_header, ciphertext)
// last byte of plaintext is inner content type — strip it
```

### CertificateVerify message

The server signs:
```
msg = 0x20 * 64          // 64 space bytes
   || "TLS 1.3, server CertificateVerify\0"
   || transcript_hash    // SHA256 of handshake up to Certificate message
```
Guest verifies with the leaf cert's public key.

---

## Cycle Cost Estimate

| Step | Precompile | ~Cycles |
|---|---|---|
| Cert chain verify (webpki) | ❌ | ~50M |
| P-256 ECDSA (CertVerify) | ❌ | ~100M |
| X25519 ECDH | ❌ | ~30M |
| HKDF-SHA256 key schedule | ✅ SHA-256 | ~2M |
| AES-128-GCM (1KB payload) | ❌ | ~80M |
| JSON parse + assert | ✅ | ~1M |
| **Total** | | **~263M** |

At ~2M cycles/s proving on CPU → ~2 min. GPU would be ~10–15s.

---

## Directory Structure After Implementation

```
sp1-demo/
├── program/
│   └── src/main.rs          ← guest: verify TLS transcript + assert JSON
├── script/
│   └── src/
│       ├── main.rs          ← CLI entry point
│       ├── capture.rs       ← CapturingStream + TLS record parser
│       ├── witness.rs       ← TlsWitness struct + builder
│       └── keylog.rs        ← KeyLog impl to capture ephemeral keys
└── shared/                  ← new crate
    └── src/lib.rs           ← TlsWitness struct (shared between host and guest)
```

---

## Implementation Order

1. `shared/` crate — `TlsWitness` struct with serde derives
2. `script/src/capture.rs` — `CapturingStream`
3. `script/src/keylog.rs` — `KeyLog` impl  
4. `script/src/witness.rs` — TLS record parser → `TlsWitness`
5. `script/src/main.rs` — wire it all together
6. `program/src/main.rs` — guest verification logic, one step at a time:
   a. cert chain
   b. CertificateVerify
   c. key derivation
   d. decryption
   e. JSON assertion

---

## Current Status (2026-05-14)

### ✅ Fully Working End-to-End

The pipeline passes for `https://blockchain.info/ticker` with field `/USD/last` threshold `1000`.  
Execution: **~21.2M cycles** (much lower than the earlier estimate of 263M).

```
cargo run --release --bin sp1-https-json-script -- \
  --url https://blockchain.info/ticker \
  --field /USD/last --threshold 1000
```

All components implemented and `cargo clippy` is clean.

| Component | File | Notes |
|---|---|---|
| `CapturingKxGroup` | `script/src/capture.rs` | Captures client X25519 private key + server public key |
| `CapturingStream` | `script/src/capture.rs` | Captures all raw TLS wire bytes |
| `CapturingKeyLog` | `script/src/keylog.rs` | Captures `SERVER_HANDSHAKE_TRAFFIC_SECRET` for host-side HS decryption |
| TLS record parser | `script/src/witness.rs` | Parses records, decrypts encrypted handshake, assembles `TlsWitness` |
| `shared/TlsWitness` | `shared/src/lib.rs` | Serde-serialisable witness struct shared between host and guest |
| Host TLS connection | `script/src/main.rs` | Real TLS connection using all capturing infrastructure |
| Transcript integrity | `program/src/main.rs` | All four transcript hashes computed in-guest |
| Server Finished HMAC | `program/src/main.rs` | Proves server completed handshake |
| Cert chain verification | `program/src/main.rs` | ECDSA-P256, ECDSA-P384, RSA-PSS, RSA-PKCS1 + webpki-roots |
| CertificateVerify | `program/src/main.rs` | Multi-scheme: 0x0403, 0x0503, 0x0804, 0x0805, 0x0401 |
| Hostname check | `program/src/main.rs` | Leaf cert SAN, wildcard support |
| ECDH + HKDF + AES-GCM | `program/src/main.rs` | Full key schedule and app record decryption |
| Chunked HTTP decoder | `program/src/main.rs` | `unchunk()` — handles Transfer-Encoding: chunked |
| Session ticket filter | `program/src/main.rs` | Skips NewSessionTicket records (inner_ct=22) |

### Guest verification flow (complete)

```
witness.handshake_messages
  → compute transcript hashes at each checkpoint              [SHA-256, in-guest]
  → verify Server Finished HMAC                               [HMAC-SHA256]
  → verify cert chain signatures                              [ECDSA-P256/P384/RSA]
  → verify against webpki-roots trust anchors                 [DER byte comparison]
      Strategy A: cert subject matches anchor
      Strategy B: last cert issuer matches anchor (cross-signed roots)
  → verify leaf cert SAN contains `host`                      [DER parsing]
  → verify CertificateVerify signature (leaf cert private key) [multi-scheme]
  → X25519(client_priv, server_pub) + HKDF → app traffic key [X25519 + HKDF-SHA256]
  → AES-128-GCM decrypt app records, filter session tickets   [AES-GCM]
  → unchunk HTTP body → JSON pointer → numeric assertion
  → commit(host, field, threshold, value)
```

### Implementation notes

- **webpki-roots 0.26 format:** `TrustAnchor::subject` and `subject_public_key_info` store
  the *inner content* of their DER SEQUENCE — without the outer `0x30` wrapper. Trust anchor
  matching uses raw DER byte comparison after stripping wrappers from the chain's DER. The
  `parse_anchor_spki()` helper re-wraps the content into a full SEQUENCE before calling
  `SubjectPublicKeyInfoOwned::from_der`.

- **Cross-signed certificate chains:** Some servers (e.g. blockchain.info) include a root cert
  in the chain whose SUBJECT is in the trust store (DigiCert Global Root G2) but whose ISSUER
  points to an older root not in webpki-roots. `find_trust_anchor` uses two strategies:
  (A) find any cert whose subject matches a trust anchor, (B) check if the last cert's issuer
  matches a trust anchor (for chains that don't include the root at all).

- **TLS NewSessionTicket records:** After the handshake the server sends NewSessionTicket
  as encrypted ApplicationData records with inner content type 22 (Handshake), not 23.
  These are filtered before appending to the HTTP plaintext.

### Known limitations / follow-ups

- **Real STARK proof requires 32–64 GB RAM.** Running `--prove` on a laptop is OOM-killed.
  Use `SP1_PROVER=mock` for development or submit to the Succinct prover network.
- **Certificate revocation not checked.** OCSP inside zkVM is prohibitively expensive.
- **Replay not prevented.** A prover could reuse an old valid session transcript. Mitigation:
  assert on a timestamp or nonce field in the JSON response (e.g. `/timestamp`).
- **Single cipher suite.** Only `TLS_AES_128_GCM_SHA256` is negotiated. ChaCha20-Poly1305
  and AES-256-GCM would need additional decryption paths in the guest.
- **No ChaCha20-Poly1305 / AES-256 support.** The script forces AES-128-GCM but if the
  server rejects it the connection will fail.

### Potential next steps

1. **Succinct network integration** — submit proof job via `SP1_PROVER=network` to avoid
   local RAM requirements.
2. **Timestamp / replay prevention** — add `--nonce-field` CLI arg; guest asserts the JSON
   field equals a fresh nonce or is within an acceptable time window.
3. **On-chain verifier** — generate a Solidity verifier with `sp1-sdk`'s `evm` feature and
   post proofs to a smart contract.
4. **Broader URL support** — test against more endpoints; handle servers that don't support
   TLS 1.3-only or require SNI fallback.
