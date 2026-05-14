# TODO

## Target Use Case

**"Prove my Binance balance is above $X to a 3rd party."**

The user holds a Binance API key. They run the prover locally, which makes an authenticated request to Binance, captures the full TLS session, and produces a ZK proof. The 3rd party receives only the proof — not the API key, not the full response.

The proof guarantees, unforgeably:

- The TLS session was with `binance.com`, cert chain verified against Mozilla roots
- The request was authenticated (Binance only returns real balances to valid API keys)
- The decrypted, authenticated response body had `balance > X`
- The prover cannot fake any of this — AES-GCM auth, ECDSA, and the full key schedule are all verified inside the guest against a fixed ELF whose hash the verifier checks

The prover is a courier for the witness, not a trusted party. The verifier trusts the TLS stack and Mozilla root store — the same things they'd trust making the request themselves.

**Remaining limitation:** a user could run the prover multiple times and pick the best session. Bounded by asserting on Binance's `/serverTime` in the same response — replay window collapses to minutes. Acceptable for a 3rd party doing a spot check.

**Note on selective disclosure:** the prover sees the full Binance response (all balances, positions, etc.) but the proof only reveals the single asserted field. The user must trust the prover not to log the full response. For self-proving (user runs prover on their own machine) this is not an issue. For delegated proving it requires MPC-TLS or a TEE — see Future Directions below.

**One addition needed to ship this (see Replay Prevention below):**
- Assert `json["/serverTime"] > now - 5min` alongside the balance check (Binance includes a server timestamp in all API responses)

---

## Next: Replay Prevention (blocks shipping the Binance use case)

- [ ] **Add `--freshness-field` and `--freshness-min` CLI args** — assert a second JSON field (the server's timestamp) is within an acceptable window of the current time. The verifier supplies `now` as a public input; the guest commits it alongside the balance claim. Example: `--freshness-field /serverTime --freshness-min 300` asserts `json["/serverTime"] > now - 300s`. Binance includes `/serverTime` (Unix ms) in all API responses. This collapses the cherry-pick window to minutes.

---

## Security / Correctness

- [ ] **Parse `server_ecdh_public` from ServerHello bytes in the guest** instead of accepting it as a separate `TlsWitness` field. Currently the guest trusts `witness.server_ecdh_public` directly; the implicit check (Server Finished HMAC fails if it's wrong) is sound but hidden. Parsing it from `handshake_messages[1]`'s `key_share` extension makes the integrity property explicit and removes a field from the witness struct.

- [ ] **Fix `unchunk` empty-response edge case** — if a chunked response starts with `0\r\n\r\n` (valid empty body), `unchunk` returns the raw string unchanged and passes it to `serde_json::from_str`, which panics. The guest has no graceful error handling — all unexpected inputs are panics with messages the verifier never sees. Add proper `Result` propagation through the guest's HTTP/JSON path.

## Code quality

- [ ] **Replace `Box::leak` in `make_capturing_provider`** with `Arc<dyn SupportedKxGroup + Send + Sync>`. The current leak-per-connection is harmless in a CLI but is a workaround for a lifetime constraint, not an intentional design choice.

## Precision

- [ ] **Replace `f64` with integer or decimal arithmetic** for the JSON field value and threshold. `f64` loses precision beyond ~15 significant digits — wrong for financial values. Use string comparison or scale to integer (e.g. cents / satoshis).

## Guest code cleanup

- [ ] **Remove `TlsWitness.server_finished_body` and `cert_verify_msg`** — both are derivable from `handshake_messages[5][4..]` and `handshake_messages[4][4..]` respectively. Keeping them is convenient but redundant; removing them shrinks the witness and makes the data model less ambiguous.

## Cipher suite coverage

- [ ] **ChaCha20-Poly1305 and AES-256-GCM decryption** in the guest. Currently only `TLS_AES_128_GCM_SHA256` is negotiated (forced at connection time). Add decryption paths for the other two TLS 1.3 mandatory cipher suites.

## Proving

- [ ] **Succinct prover network integration** — real STARK proof works on 32 GB RAM (verified on NUC). Wire up `SP1_PROVER=network` as an alternative for machines with less RAM, and document the flow in the README.

- [ ] **Investigate the cycle count gap** — actual execution is 21.2M cycles vs. the 263M estimate. SP1 likely has P-256 precompiles not accounted for in the original estimate. Understand what's precompiled to inform future optimization.

## Possible extensions

- [ ] On-chain verifier: generate a Solidity verifier with `sp1-sdk`'s `evm` feature and post proofs to a smart contract.
- [ ] Certificate revocation (OCSP) — expensive inside the zkVM; explore caching or off-circuit revocation checks committed as a separate public input.

## Future Directions (stronger trust model)

The current design requires the user to run the prover on their own machine. For delegated proving — where a 3rd party runs the prover on behalf of a user — the selective disclosure and agency problems require one of:

- **MPC-TLS** (e.g. TLSNotary): verifier co-participates in the TLS handshake via 2-of-2 MPC. Neither party alone can forge the session. Strongest guarantees, no hardware trust, but complex and slow.
- **TEE-assisted witness generation**: run the host inside an attested enclave (Intel TDX, AMD SEV). TEE makes the connection, produces the witness, returns only the proof. Verifier checks TEE attestation + proof. Pragmatic, trusts the hardware vendor.

Both are out of scope for a self-proving demo but are the natural next step for a production delegated-proving system.
