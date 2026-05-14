# NEXT — Roadmap from demo to production-oriented zkTLS prover

This document collects **implementation-ready** notes from design review: what it means to close the gaps around **freshness**, **integer arithmetic**, **transcript parsing**, and **stricter PKIX**, and what **still** separates a hardened prover from “production” in the operational sense.

For historical task bullets, see [`TODO.md`](TODO.md). For architecture and trust model, see [`PLAN.md`](PLAN.md) and [`README.md`](README.md).

---

## 1. Executive summary

### 1.1 What the four pillars buy you

| Pillar | Problem it fixes | Does not fix |
|--------|------------------|--------------|
| **Freshness** | TLS/session replay and “pick the best historical response” within unbounded time | Malicious prover logging secrets off-machine; proof-layer replay |
| **Integer / fixed-scale values** | `f64` precision and non-determinism for thresholds | Ambiguity of JSON number ↔ domain type without a schema |
| **Tighter transcript parsing** | Fragile host witness assembly; odd record fragmentation | Protocol upgrades (HTTP/2, QUIC) without new parsers |
| **Stricter PKIX** | Accepting chains a conservative HTTPS client would reject (expiry, KU/EKU, CA semantics) | Revocation without OCSP/CRL or out-of-band policy |

### 1.2 “Production ready” vs “production candidate”

Implementing **§2–§5** below moves the repo toward a **production candidate for a narrowly specified product** (exact URL semantics, TLS profile, public inputs, verifier deployment).

**Production ready** in practice also requires **§6** (operations, threat-model text, testing, audits). Neither milestone removes **delegated-proving** concerns: if someone else runs the prover, they still see API keys and full responses unless you add MPC-TLS, a TEE, or similar ([`TODO.md` — Future Directions](TODO.md)).

---

## 2. Freshness (replay and cherry-picking)

### 2.1 Threat model

- **TLS replay:** An old witness/proof remains cryptographically valid forever unless the **statement** binds time or nonce.
- **Cherry-picking:** The prover runs many fetches and submits the proof where the asserted field is best for them.

### 2.2 Recommended statement shape

Commit as **public outputs** (alongside existing [`PublicClaim`](shared/src/lib.rs)):

- **`now_unix`** (or `now_ms`): reference wall time agreed with the verifier (supplied by verifier to prover, or derived from a consensus clock — document which).
- **`freshness_field`** / **`freshness_min_age`** / **`freshness_max_age`**: rules such as  
  `server_time ≥ now - window_low` and `server_time ≤ now + window_high` to bound clock skew and stale responses.

Example pattern already sketched in [`TODO.md`](TODO.md): Binance-style JSON with `/serverTime` (milliseconds).

### 2.3 Implementation notes

**CLI / host (`script/src/main.rs`):**

- Add flags, e.g. `--freshness-field`, `--freshness-window-past-secs`, `--freshness-window-future-secs`, and `--now` (optional override for testing) or require verifier-supplied `now` via stdin/config.
- Pass `now` and window parameters into the guest via `sp1_zkvm::io::read()` alongside existing inputs.

**Guest (`program/src/main.rs`):**

- After parsing JSON, read second numeric field (prefer **integer** path once §3 lands), compare against `now` with explicit skew tolerance.
- Document **units** (seconds vs milliseconds) per API; consider requiring APIs that expose integer epoch ms.

**Verifier:**

- Verifier must reject proofs where committed `now` is implausible (e.g. far in the future) under **their** policy.

### 2.4 References

- RFC 8446 — TLS 1.3; freshness is **application/policy**, not TLS layer alone: <https://www.rfc-editor.org/rfc/rfc8446>
- OWASP / generic guidance on replay-resistant protocols (conceptual): bind timestamps or nonces in the **signed/proved** statement

---

## 3. Integers and thresholds (replace `f64`)

### 3.1 Problem

[`PublicClaim`](shared/src/lib.rs) and the guest assertion use `f64` ([`program/src/main.rs`](program/src/main.rs)). IEEE doubles lose precision beyond ~15 decimal digits and introduce equality edge cases unsuitable for balances, prices, or satoshi-scale amounts.

### 3.2 Options (pick one product-wide convention)

1. **Scaled integers** — CLI accepts `--threshold-satoshi` / `--field-scale 10000`; guest compares `i128` or `u128` after parsing JSON number string → decimal conversion **in-guest** with explicit rounding mode, or host passes pre-scaled integer witness fields (smaller guest if host is trusted only for formatting — prefer parsing in guest for binding).

2. **String / decimal crate** — Parse JSON string fields only (e.g. `"1234.56"`) with a **fixed-precision** decimal type (`rust_decimal`, etc.) if available under zkVM constraints; may increase cycle cost.

3. **Binary integer JSON** — If API allows, assert on integer JSON values only (`serde_json::Number` → `as_u64()` / big-int).

### 3.3 Implementation notes

- Extend [`PublicClaim`](shared/src/lib.rs): e.g. `value_i128`, `threshold_i128`, `scale` or use string commitments for decimal snapshots.
- Align host CLI validation with guest (reject ambiguous inputs before proving).
- Add tests around boundary values and negative amounts if applicable.

### 3.4 References

- JSON numbers are IEEE binary64 in RFC 8259 practice; financial systems often avoid JSON number for money: <https://www.rfc-editor.org/rfc/rfc8259>

---

## 4. Tighter transcript parsing and witness integrity

### 4.1 Current brittle spots

| Area | Location | Risk |
|------|----------|------|
| First CH/SH records | [`script/src/witness.rs`](script/src/witness.rs) `assemble_witness`: `.find(|r| content_type == 22)` | Wrong if multiple plaintext handshake records or reordering |
| Redundant witness fields | [`shared/src/lib.rs`](shared/src/lib.rs) `server_ecdh_public`, `cert_verify_msg`, `server_finished_body` vs transcript | Host could theoretically desync fields (partially mitigated by Finished/HMAC); parsing from transcript is clearer |
| Chunked empty body | [`program/src/main.rs`](program/src/main.rs) `unchunk` | [`TODO.md`](TODO.md): `0\r\n\r\n` edge case → wrong body → panic |
| Guest errors | Whole guest | Panics only; verifier sees failure as invalid proof, not structured errors |

### 4.2 Recommended work

1. **Parse `server_ecdh_public` from `handshake_messages[1]` in the guest**  
   - Extension `key_share` in ServerHello (RFC 8446 §4.2.8).  
   - Drop duplicate `witness.server_ecdh_public` once verified parse matches wire layout.

2. **Stricter record iteration on host**  
   - Walk outbound/inbound in order; assert expected **finite state machine** (CH → SH → encrypted flight…) instead of global `.find()`.

3. **Derive redundant fields from `handshake_messages`**  
   - `cert_verify_msg` ← message type 15 body + header consistency checks.  
   - `server_finished_body` ← message type 20 body.

4. **`Result` in guest for HTTP/JSON**  
   - Either map errors to committed failure codes or use SP1 patterns for graceful abort with **public** error enum (if supported by your proving UX).

### 4.3 References

- TLS 1.3 handshake and record layer: RFC 8446 <https://www.rfc-editor.org/rfc/rfc8446>  
- TLS 1.3 `Certificate`, `CertificateVerify`, `Finished`: RFC 8446 §4.4.x  
- HTTP/1.1 chunked encoding: RFC 9112 (obsletes 7230 chunked rules): <https://www.rfc-editor.org/rfc/rfc9112>

---

## 5. Stricter PKIX

### 5.1 What the guest does today

[`program/src/main.rs`](program/src/main.rs):

- Validates chain signatures to Mozilla anchors (`webpki-roots`) with custom anchor matching (`find_trust_anchor`).
- Verifies leaf **SAN** hostname ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) + TLS hostname practices).

### 5.2 What “stricter PKIX” typically adds

Implement **per-cert** checks along the chain (leaf + intermediates), using parsed fields from `x509-cert` (`x509_cert::certificate::Certificate`) or targeted DER:

| Check | Why | Notes for zkVM |
|-------|-----|----------------|
| **Validity** `notBefore` / `notAfter` | Reject expired / not-yet-valid certs | Requires committed **`now`** (align with §2); compare as UTCTime / GeneralizedTime |
| **Basic constraints** | CA vs EE; `pathLenConstraint` | Reject EE acting as CA; enforce path length on intermediates |
| **Key usage** | TLS leaf needs `digitalSignature`; legacy RSA key encipherment edge cases | Match CABForum expectations for TLS server certs |
| **Extended key usage** | **`serverAuth`** (OID 1.3.6.1.5.5.7.3.1) for HTTPS leaves | Allow absent EKU only if policy says so (some stacks treat absent as “any”; pick explicit policy) |
| **Critical unknown extensions** | RFC 5280 §4.2 | Reject if critical extension cannot be processed |

Optional / lower priority:

- **Name constraints** on CA certs (complex but important for enterprise chains).
- **Policy mappings / inhibit anyPolicy** — rarely needed for public web PKI demos.

### 5.3 Revocation (explicitly out of scope unless you add infrastructure)

- OCSP: RFC 6960 <https://www.rfc-editor.org/rfc/rfc6960>  
- CRLs: RFC 5280 §5  

Typical zkTLS demos skip in-guest fetching for cost; production options include **short-lived certs**, **out-of-band revocation lists committed as public inputs**, or **accepting no revocation** with documented risk.

### 5.4 Alignment with Web PKI norms

For **browser-aligned** server certificate expectations, read:

- **CA/B Forum Baseline Requirements** (TLS server certificates):  
  <https://cabforum.org/baseline-requirements-documents/>  
  Use as a **policy checklist**, not as code to embed verbatim.

### 5.5 References

- PKIX profile: RFC 5280 <https://www.rfc-editor.org/rfc/rfc5280>  
- TLS 1.3 certificate handling: RFC 8446 §4.4.2  
- hostname identification (historical RFC 6125; practice largely reflected in CABForum and implementers):  
  <https://www.rfc-editor.org/rfc/rfc6125>

---

## 6. Beyond the four pillars — production checklist

Use this when targeting real deployments.

### 6.1 Precise cryptographic statement

Document **exactly** what is proved:

- Hostname (SNI vs cert SAN policy).
- HTTP version and framing (today: HTTP/1.1 GET path from [`script/src/main.rs`](script/src/main.rs)).
- Whether **full response body** is proved or a hash/commitment.
- Which JSON fields appear in **public outputs** vs remain hidden.

Version the **guest ELF**; verifiers must pin **ELF hash** or SP1 **program vkey** per release.

### 6.2 Proving operations

- Local RAM constraints ([`README.md`](README.md)); `SP1_PROVER=network` ([SP1 / Succinct docs](https://docs.succinct.xyz/)) for machines without 32GB RAM.
- Artifact formats (`proof.bin`), retention, logging hygiene (**do not** print full HTTP bodies in production logs — [`script/src/main.rs`](script/src/main.rs) currently prints response body for debugging).

### 6.3 Verification surface

- Who runs `prover.verify`, on-chain vs off-chain, key rotation, replay of **proof submissions** at application layer.

### 6.4 Testing matrix

- Multiple hosts (RSA vs ECDSA leaf, chain with/without root in bundle, chunked vs `Content-Length`).
- Fuzz **witness parser** on host and negative tests on guest (malformed DER, wrong extension order).

### 6.5 Third-party / delegated proving

If the prover runs on **another party’s machine**:

- They observe API keys and plaintext responses.
- Mitigations: **MPC-TLS** (e.g. TLSNotary-style designs), **TEE attestation**, or user-only execution — see [`TODO.md`](TODO.md).

### 6.6 Cipher suite expansion

[`README.md`](README.md) limits guest to `TLS_AES_128_GCM_SHA256`. Supporting TLS 1.3 mandatory suites implies additional AEAD paths in guest (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) — RFC 8446 Appendix B.

---

## 7. Suggested implementation order

1. **Guest-facing correctness with smallest UX change:** integer asserts + `unchunk` fix + structured errors (§3, §4.2 item 4 partial).
2. **Freshness public inputs** wired host ↔ guest + docs for verifier (§2).
3. **Parse ECDH public key from ServerHello in guest**; shrink witness (§4).
4. **Stricter PKIX** starting with **validity window + serverAuth EKU + basic constraints** (§5).
5. **Host transcript FSM** instead of `.find()` on handshake records (§4).
6. **Ops hardening** — logging, proving network, README updates (§6).

---

## 8. Key file index

| Component | Path |
|-----------|------|
| Guest (verification + JSON assert) | [`program/src/main.rs`](program/src/main.rs) |
| Host CLI | [`script/src/main.rs`](script/src/main.rs) |
| Witness assembly / TLS parse | [`script/src/witness.rs`](script/src/witness.rs) |
| Key capture | [`script/src/capture.rs`](script/src/capture.rs) |
| KeyLog (host-only HS decrypt assist) | [`script/src/keylog.rs`](script/src/keylog.rs) |
| Shared witness + public claim | [`shared/src/lib.rs`](shared/src/lib.rs) |

---

## 9. External tooling references

- **SP1** (Succinct): installation and `cargo prove` — project README and <https://docs.succinct.xyz/>
- **rustls** provider hooks (custom KX group): <https://docs.rs/rustls/latest/rustls/crypto/index.html>
- **webpki-roots** (trust anchors format): crate docs on docs.rs for the pinned minor version

---

*Last aligned with repo review — extend this file as tasks close or scope changes.*
